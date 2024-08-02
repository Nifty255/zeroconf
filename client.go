package zeroconf

import (
	"context"
	"fmt"
	"log"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// IPType specifies the IP traffic the client listens for.
// This does not guarantee that only mDNS entries of this sepcific
// type passes. E.g. typical mDNS packets distributed via IPv4, often contain
// both DNS A and AAAA entries.
type IPType uint8

// Options for IPType.
const (
	IPv4        = 0x01
	IPv6        = 0x02
	IPv4AndIPv6 = (IPv4 | IPv6) //< Default option.
)

type clientOpts struct {
	listenOn IPType
	ifaces   []net.Interface
}

// ClientOption fills the option struct to configure intefaces, etc.
type ClientOption func(*clientOpts)

// SelectIPTraffic selects the type of IP packets (IPv4, IPv6, or both) this
// instance listens for.
// This does not guarantee that only mDNS entries of this sepcific
// type passes. E.g. typical mDNS packets distributed via IPv4, may contain
// both DNS A and AAAA entries.
func SelectIPTraffic(t IPType) ClientOption {
	return func(o *clientOpts) {
		o.listenOn = t
	}
}

// SelectIfaces selects the interfaces to query for mDNS records
func SelectIfaces(ifaces []net.Interface) ClientOption {
	return func(o *clientOpts) {
		o.ifaces = ifaces
	}
}

// Resolver acts as entry point for service lookups and to browse the DNS-SD.
type Resolver struct {
	c *client
}

// NewResolver creates a new resolver and joins the UDP multicast groups to
// browse for the specified service.
func NewBrowser(ctx context.Context, service, domain string, entries chan<- *ServiceEntry, options ...ClientOption) (*Resolver, error) {
	// Apply default configuration and load supplied options.
	var conf = clientOpts{
		listenOn: IPv4AndIPv6,
	}
	for _, o := range options {
		if o != nil {
			o(&conf)
		}
	}

	c, err := newClient(conf)
	if err != nil {
		return nil, err
	}
	r := &Resolver{
		c: c,
	}

	params := defaultParams(service)
	if domain != "" {
		params.Domain = domain
	}
	params.Entries = entries
	params.isBrowsing = true
	ctx, cancel := context.WithCancel(ctx)
	go r.c.mainloop(ctx, params)

	err = r.c.query(params)
	if err != nil {
		cancel()
		return nil, err
	}
	// If previous probe was ok, it should be fine now. In case of an error later on,
	// the entries' queue is closed.
	go func() {
		if err := r.c.periodicQuery(ctx, params); err != nil {
			cancel()
		}
	}()

	return r, nil
}

// NewLookup creates a new resolver and joins the UDP multicast groups to
// browse for the specified service instance.
func NewLookup(ctx context.Context, instance, service, domain string, entries chan<- *ServiceEntry, options ...ClientOption) (*Resolver, error) {
	// Apply default configuration and load supplied options.
	var conf = clientOpts{
		listenOn: IPv4AndIPv6,
	}
	for _, o := range options {
		if o != nil {
			o(&conf)
		}
	}

	c, err := newClient(conf)
	if err != nil {
		return nil, err
	}
	r := &Resolver{
		c: c,
	}

	params := defaultParams(service)
	params.Instance = instance
	if domain != "" {
		params.Domain = domain
	}
	params.Entries = entries
	ctx, cancel := context.WithCancel(ctx)
	go r.c.mainloop(ctx, params)
	err = r.c.query(params)
	if err != nil {
		// cancel mainloop
		cancel()
		return nil, err
	}
	// If previous probe was ok, it should be fine now. In case of an error later on,
	// the entries' queue is closed.
	go func() {
		if err := r.c.periodicQuery(ctx, params); err != nil {
			cancel()
		}
	}()

	return r, nil
}

func (r *Resolver) Close() {
	r.c.shutdown()
}

// defaultParams returns a default set of QueryParams.
func defaultParams(service string) *lookupParams {
	return newLookupParams("", service, "local", false, make(chan *ServiceEntry))
}

// Client structure encapsulates both IPv4/IPv6 UDP connections.
type client struct {
	ifaces   []net.Interface
	receiver chan dnsMsgWrapper
}

// Client structure constructor
func newClient(opts clientOpts) (*client, error) {
	ifaces := opts.ifaces
	if len(ifaces) == 0 {
		ifaces = listMulticastInterfaces()
	}
	c := &client{
		ifaces:   ifaces,
		receiver: make(chan dnsMsgWrapper, 64),
	}

	// IPv4 interfaces
	if (opts.listenOn & IPv4) > 0 {
		err := joinUdp4Multicast(ifaces, c, c.receiver)
		if err != nil {
			return nil, err
		}
	}
	// IPv6 interfaces
	if (opts.listenOn & IPv6) > 0 {
		err := joinUdp6Multicast(ifaces, c, c.receiver)
		if err != nil {
			return nil, err
		}
	}

	return c, nil
}

// Start listeners and waits for the shutdown signal from exit channel
func (c *client) mainloop(ctx context.Context, params *lookupParams) {
	// Iterate through channels from listeners goroutines
	var entries, sentEntries map[string]*ServiceEntry
	sentEntries = make(map[string]*ServiceEntry)
	for {
		select {
		case <-ctx.Done():
			// Context expired. Notify subscriber that we are done here.
			params.done()
			c.shutdown()
			return
		case msgW := <-c.receiver:
			msg := msgW.msg

			// mDNS answers don't have questions, according to RFC6762 section 6,
			// but just in case the responder isn't following the RFC, also make
			// sure there's at least one answer.
			if msg.Question != nil || len(msg.Question) > 0 ||
				msg.Answer == nil || len(msg.Answer) == 0 {
				continue
			}
			entries = make(map[string]*ServiceEntry)
			sections := append(msg.Answer, msg.Ns...)
			sections = append(sections, msg.Extra...)

			for _, answer := range sections {
				switch rr := answer.(type) {
				case *dns.PTR:
					if params.ServiceName() != rr.Hdr.Name {
						continue
					}
					if params.ServiceInstanceName() != "" && params.ServiceInstanceName() != rr.Ptr {
						continue
					}
					if _, ok := entries[rr.Ptr]; !ok {
						entries[rr.Ptr] = NewServiceEntry(
							trimDot(strings.Replace(rr.Ptr, rr.Hdr.Name, "", -1)),
							params.Service,
							params.Domain)
					}
					entries[rr.Ptr].TTL = rr.Hdr.Ttl
				case *dns.SRV:
					if params.ServiceInstanceName() != "" && params.ServiceInstanceName() != rr.Hdr.Name {
						continue
					} else if !strings.HasSuffix(rr.Hdr.Name, params.ServiceName()) {
						continue
					}
					if _, ok := entries[rr.Hdr.Name]; !ok {
						entries[rr.Hdr.Name] = NewServiceEntry(
							trimDot(strings.Replace(rr.Hdr.Name, params.ServiceName(), "", 1)),
							params.Service,
							params.Domain)
					}
					entries[rr.Hdr.Name].HostName = rr.Target
					entries[rr.Hdr.Name].Port = int(rr.Port)
					entries[rr.Hdr.Name].TTL = rr.Hdr.Ttl
				case *dns.TXT:
					if params.ServiceInstanceName() != "" && params.ServiceInstanceName() != rr.Hdr.Name {
						continue
					} else if !strings.HasSuffix(rr.Hdr.Name, params.ServiceName()) {
						continue
					}
					if _, ok := entries[rr.Hdr.Name]; !ok {
						entries[rr.Hdr.Name] = NewServiceEntry(
							trimDot(strings.Replace(rr.Hdr.Name, params.ServiceName(), "", 1)),
							params.Service,
							params.Domain)
					}
					entries[rr.Hdr.Name].Text = rr.Txt
					entries[rr.Hdr.Name].TTL = rr.Hdr.Ttl
				}
			}
			// Associate IPs in a second round as other fields should be filled by now.
			for _, answer := range sections {
				switch rr := answer.(type) {
				case *dns.A:
					for k, e := range entries {
						if e.HostName == rr.Hdr.Name {
							entries[k].AddrIPv4 = append(entries[k].AddrIPv4, rr.A)
						}
					}
				case *dns.AAAA:
					for k, e := range entries {
						if e.HostName == rr.Hdr.Name {
							entries[k].AddrIPv6 = append(entries[k].AddrIPv6, rr.AAAA)
						}
					}
				}
			}
		}

		if len(entries) > 0 {
			for k, e := range entries {
				if e.TTL == 0 {
					delete(entries, k)
					delete(sentEntries, k)
					continue
				}
				if _, ok := sentEntries[k]; ok {
					continue
				}

				// If this is an DNS-SD query do not throw PTR away.
				// It is expected to have only PTR for enumeration
				if params.ServiceRecord.ServiceTypeName() != params.ServiceRecord.ServiceName() {
					// Require at least one resolved IP address for ServiceEntry
					// TODO: wait some more time as chances are high both will arrive.
					if len(e.AddrIPv4) == 0 && len(e.AddrIPv6) == 0 {
						continue
					}
				}
				// Submit entry to subscriber and cache it.
				// This is also a point to possibly stop probing actively for a
				// service entry.
				params.Entries <- e
				sentEntries[k] = e
				if !params.isBrowsing {
					params.disableProbing()
				}
			}
		}
	}
}

// Shutdown client will close currently open connections and channel implicitly.
func (c *client) shutdown() {
	closeUdp4Connection(c)
	closeUdp6Connection(c)
}

// periodicQuery sens multiple probes until a valid response is received by
// the main processing loop or some timeout/cancel fires.
// TODO: move error reporting to shutdown function as periodicQuery is called from
// go routine context.
func (c *client) periodicQuery(ctx context.Context, params *lookupParams) error {
	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = 4 * time.Second
	bo.MaxInterval = 60 * time.Second
	bo.MaxElapsedTime = 0
	bo.Reset()

	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		// Backoff and cancel logic.
		wait := bo.NextBackOff()
		if wait == backoff.Stop {
			return fmt.Errorf("periodicQuery: abort due to timeout")
		}
		if timer == nil {
			timer = time.NewTimer(wait)
		} else {
			timer.Reset(wait)
		}
		select {
		case <-timer.C:
			// Wait for next iteration.
		case <-params.stopProbing:
			// Chan is closed (or happened in the past).
			// Done here. Received a matching mDNS entry.
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
		// Do periodic query.
		if err := c.query(params); err != nil {
			return err
		}
	}
}

// Performs the actual query by service name (browse) or service instance name (lookup),
// start response listeners goroutines and loops over the entries channel.
func (c *client) query(params *lookupParams) error {
	var serviceName, serviceInstanceName string
	serviceName = fmt.Sprintf("%s.%s.", trimDot(params.Service), trimDot(params.Domain))

	// send the query
	m := new(dns.Msg)
	if params.Instance != "" { // service instance name lookup
		serviceInstanceName = fmt.Sprintf("%s.%s", params.Instance, serviceName)
		m.Question = []dns.Question{
			{Name: serviceInstanceName, Qtype: dns.TypeSRV, Qclass: dns.ClassINET},
			{Name: serviceInstanceName, Qtype: dns.TypeTXT, Qclass: dns.ClassINET},
		}
	} else if len(params.Subtypes) > 0 { // service subtype browse
		m.SetQuestion(params.Subtypes[0], dns.TypePTR)
	} else { // service name browse
		m.SetQuestion(serviceName, dns.TypePTR)
	}
	m.RecursionDesired = false
	if err := c.sendQuery(m); err != nil {
		return err
	}

	return nil
}

// Pack the dns.Msg and write to available connections (multicast)
func (c *client) sendQuery(msg *dns.Msg) error {
	buf, err := msg.Pack()
	if err != nil {
		return err
	}
	if pkt4Conn != nil {
		// See https://pkg.go.dev/golang.org/x/net/ipv4#pkg-note-BUG
		// As of Golang 1.18.4
		// On Windows, the ControlMessage for ReadFrom and WriteTo methods of PacketConn is not implemented.
		var wcm ipv4.ControlMessage
		for ifi := range c.ifaces {
			switch runtime.GOOS {
			case "darwin", "ios", "linux":
				wcm.IfIndex = c.ifaces[ifi].Index
			default:
				if err := pkt4Conn.SetMulticastInterface(&c.ifaces[ifi]); err != nil {
					log.Printf("[WARN] mdns: Failed to set multicast interface: %v", err)
				}
			}
			pkt4Conn.WriteTo(buf, &wcm, ipv4Addr)
		}
	}
	if pkt6Conn != nil {
		// See https://pkg.go.dev/golang.org/x/net/ipv6#pkg-note-BUG
		// As of Golang 1.18.4
		// On Windows, the ControlMessage for ReadFrom and WriteTo methods of PacketConn is not implemented.
		var wcm ipv6.ControlMessage
		for ifi := range c.ifaces {
			switch runtime.GOOS {
			case "darwin", "ios", "linux":
				wcm.IfIndex = c.ifaces[ifi].Index
			default:
				if err := pkt6Conn.SetMulticastInterface(&c.ifaces[ifi]); err != nil {
					log.Printf("[WARN] mdns: Failed to set multicast interface: %v", err)
				}
			}
			pkt6Conn.WriteTo(buf, &wcm, ipv6Addr)
		}
	}
	return nil
}
