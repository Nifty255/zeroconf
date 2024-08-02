package zeroconf

import (
	"fmt"
	"net"
	"sync"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var (
	// Multicast groups used by mDNS
	mdnsGroupIPv4 = net.IPv4(224, 0, 0, 251)
	mdnsGroupIPv6 = net.ParseIP("ff02::fb")

	// mDNS wildcard addresses
	mdnsWildcardAddrIPv4 = &net.UDPAddr{
		IP:   net.ParseIP("224.0.0.0"),
		Port: 5353,
	}
	mdnsWildcardAddrIPv6 = &net.UDPAddr{
		IP: net.ParseIP("ff02::"),
		// IP:   net.ParseIP("fd00::12d3:26e7:48db:e7d"),
		Port: 5353,
	}

	// mDNS endpoint addresses
	ipv4Addr = &net.UDPAddr{
		IP:   mdnsGroupIPv4,
		Port: 5353,
	}
	ipv6Addr = &net.UDPAddr{
		IP:   mdnsGroupIPv6,
		Port: 5353,
	}

	udp4Conn *net.UDPConn
	pkt4Conn *ipv4.PacketConn
	udp6Conn *net.UDPConn
	pkt6Conn *ipv6.PacketConn

	ipv4JoinedGroups = map[string]bool{}
	ipv4Consumers    = map[interface{}]chan dnsMsgWrapper{}
	ipv4Mutex        sync.Mutex
	ipv6JoinedGroups = map[string]bool{}
	ipv6Consumers    = map[interface{}]chan dnsMsgWrapper{}
	ipv6Mutex        sync.Mutex
)

type dnsMsgWrapper struct {
	msg     *dns.Msg
	ifIndex int
	from    net.Addr
}

func joinUdp4Multicast(interfaces []net.Interface, consumer interface{}, msgCh chan dnsMsgWrapper) error {
	ipv4Mutex.Lock()
	defer ipv4Mutex.Unlock()

	// Make the UDP connection if not already made.
	err := error(nil)
	if udp4Conn == nil {
		udp4Conn, err = net.ListenUDP("udp4", mdnsWildcardAddrIPv4)
		if err != nil {
			// log.Printf("[ERR] bonjour: Failed to bind to udp4 mutlicast: %v", err)
			return err
		}
	}

	// Make the packet connection if not already made.
	if pkt4Conn == nil {
		pkt4Conn = ipv4.NewPacketConn(udp4Conn)
		pkt4Conn.SetControlMessage(ipv4.FlagInterface, true)
		pkt4Conn.SetMulticastTTL(255)
		go recv4()
	}

	// If no interfaces were provided, join on all.
	if len(interfaces) == 0 {
		interfaces = listMulticastInterfaces()
	}

	// Attempt to join as many given interfaces as are not already joined.
	attemptedJoins := 0
	failedJoins := 0
	for _, iface := range interfaces {
		if joined, ok := ipv4JoinedGroups[iface.Name]; ok && joined {
			continue
		}
		attemptedJoins++
		err := pkt4Conn.JoinGroup(&iface, &net.UDPAddr{IP: mdnsGroupIPv4})
		ipv4JoinedGroups[iface.Name] = err == nil
		if !ipv4JoinedGroups[iface.Name] {
			failedJoins++
		}
	}

	// Report number of interfaces not joined.
	err = nil
	if failedJoins > 0 {
		err = fmt.Errorf("udp4: failed to join with %d/%d interfaces", failedJoins, attemptedJoins)
	}

	if failedJoins < attemptedJoins {
		ipv4Consumers[consumer] = msgCh
	}

	return err
}

func recv4() {
	if pkt4Conn == nil {
		return
	}
	var msg dns.Msg
	buf := make([]byte, 65536)
	for {
		var ifIndex int
		n, cm, from, err := pkt4Conn.ReadFrom(buf)
		if err != nil {
			break
		}
		if cm != nil {
			ifIndex = cm.IfIndex
		}
		if err := msg.Unpack(buf[:n]); err != nil {
			// log.Printf("[ERR] zeroconf: Failed to unpack packet: %v", err)
			continue
		}

		msgW := dnsMsgWrapper{
			msg:     &msg,
			ifIndex: ifIndex,
			from:    from,
		}

		for _, ch := range ipv4Consumers {
			if ch != nil {
				ch <- msgW
			}
		}
	}
}

func leaveUdp4Multicast(interfaces []net.Interface) {
	ipv4Mutex.Lock()
	defer ipv4Mutex.Unlock()
	for _, iface := range interfaces {
		pkt4Conn.LeaveGroup(&iface, &net.UDPAddr{IP: mdnsGroupIPv4})
		ipv4JoinedGroups[iface.Name] = false
	}
}

func closeUdp4Connection(consumer interface{}) {
	// Count this consumer as closed and then ensure all consumers have closed first.
	ipv4Consumers[consumer] = nil
	for _, handler := range ipv4Consumers {
		if handler != nil {
			return
		}
	}

	// Ensure all multicast groups are left first.
	interfaces := listMulticastInterfaces()
	for _, iface := range interfaces {
		if ipv4JoinedGroups[iface.Name] {
			leaveUdp4Multicast([]net.Interface{iface})
		}
	}

	// Close the connections.
	ipv4Mutex.Lock()
	defer ipv4Mutex.Unlock()
	pkt4Conn.Close()
	udp4Conn.Close()

	// Reset the multicast map.
	ipv4JoinedGroups = map[string]bool{}
}

func joinUdp6Multicast(interfaces []net.Interface, consumer interface{}, msgCh chan dnsMsgWrapper) error {
	ipv6Mutex.Lock()
	defer ipv6Mutex.Unlock()

	// Make the UDP connection if not already made.
	err := error(nil)
	if udp6Conn == nil {
		udp6Conn, err = net.ListenUDP("udp6", mdnsWildcardAddrIPv6)
		if err != nil {
			// log.Printf("[ERR] bonjour: Failed to bind to udp6 mutlicast: %v", err)
			return err
		}
	}

	// Make the packet connection if not already made.
	if pkt6Conn == nil {
		pkt6Conn = ipv6.NewPacketConn(udp6Conn)
		pkt6Conn.SetControlMessage(ipv6.FlagInterface, true)
		pkt6Conn.SetMulticastHopLimit(255)
		go recv6()
	}

	// If no interfaces were provided, join on all.
	if len(interfaces) == 0 {
		interfaces = listMulticastInterfaces()
	}

	// Attempt to join as many given interfaces as are not already joined.
	attemptedJoins := 0
	failedJoins := 0
	for _, iface := range interfaces {
		if joined, ok := ipv6JoinedGroups[iface.Name]; ok && joined {
			continue
		}
		attemptedJoins++
		err := pkt6Conn.JoinGroup(&iface, &net.UDPAddr{IP: mdnsGroupIPv6})
		ipv6JoinedGroups[iface.Name] = err == nil
		if !ipv6JoinedGroups[iface.Name] {
			failedJoins++
		}
	}

	// Report number of interfaces not joined.
	err = nil
	if failedJoins > 0 {
		err = fmt.Errorf("udp6: failed to join with %d/%d interfaces", failedJoins, attemptedJoins)
	}

	if failedJoins < attemptedJoins {
		ipv6Consumers[consumer] = msgCh
	}

	return err
}

func recv6() {
	if pkt6Conn == nil {
		return
	}
	var msg dns.Msg
	buf := make([]byte, 65536)
	for {
		var ifIndex int
		n, cm, from, err := pkt6Conn.ReadFrom(buf)
		if err != nil {
			break
		}
		if cm != nil {
			ifIndex = cm.IfIndex
		}
		if err := msg.Unpack(buf[:n]); err != nil {
			// log.Printf("[ERR] zeroconf: Failed to unpack packet: %v", err)
			continue
		}

		msgW := dnsMsgWrapper{
			msg:     &msg,
			ifIndex: ifIndex,
			from:    from,
		}

		for _, ch := range ipv6Consumers {
			if ch != nil {
				ch <- msgW
			}
		}
	}
}

func leaveUdp6Multicast(interfaces []net.Interface) {
	ipv6Mutex.Lock()
	defer ipv6Mutex.Unlock()
	for _, iface := range interfaces {
		pkt6Conn.LeaveGroup(&iface, &net.UDPAddr{IP: mdnsGroupIPv6})
		ipv6JoinedGroups[iface.Name] = false
	}
}

func closeUdp6Connection(consumer interface{}) {
	// Count this consumer as closed and then ensure all consumers have closed first.
	ipv6Consumers[consumer] = nil
	for _, handler := range ipv4Consumers {
		if handler != nil {
			return
		}
	}

	// Ensure all multicast groups are left first.
	interfaces := listMulticastInterfaces()
	for _, iface := range interfaces {
		if ipv6JoinedGroups[iface.Name] {
			leaveUdp6Multicast([]net.Interface{iface})
		}
	}

	// Close the connections.
	ipv6Mutex.Lock()
	defer ipv6Mutex.Unlock()
	pkt6Conn.Close()
	udp6Conn.Close()

	// Reset the multicast map.
	ipv6JoinedGroups = map[string]bool{}
}

func listMulticastInterfaces() []net.Interface {
	var interfaces []net.Interface
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifi := range ifaces {
		if (ifi.Flags & net.FlagUp) == 0 {
			continue
		}
		if (ifi.Flags & net.FlagMulticast) > 0 {
			interfaces = append(interfaces, ifi)
		}
	}

	return interfaces
}
