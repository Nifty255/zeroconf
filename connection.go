package zeroconf

import (
	"fmt"
	"net"
	"sync"

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
	ipv4Consumers    = map[interface{}]bool{}
	ipv4Mutex        sync.Mutex
	ipv6JoinedGroups = map[string]bool{}
	ipv6Consumers    = map[interface{}]bool{}
	ipv6Mutex        sync.Mutex
)

func joinUdp4Multicast(interfaces []net.Interface, consumer interface{}) error {
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
		ipv4JoinedGroups[iface.Name] = err != nil
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
		ipv4Consumers[consumer] = true
	}

	return err
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
	ipv4Consumers[consumer] = false
	for _, consuming := range ipv4Consumers {
		if consuming {
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

func joinUdp6Multicast(interfaces []net.Interface, consumer interface{}) error {
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
		ipv6JoinedGroups[iface.Name] = err != nil
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
		ipv6Consumers[consumer] = true
	}

	return err
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
	ipv6Consumers[consumer] = false
	for _, consuming := range ipv4Consumers {
		if consuming {
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
