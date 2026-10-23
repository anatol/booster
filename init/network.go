package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/client4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/dhcpv6/nclient6"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var initializedNetworkState struct {
	sync.Mutex
	ifnames []string
}

func rememberInitializedInterface(ifname string) {
	initializedNetworkState.Lock()
	defer initializedNetworkState.Unlock()

	if slices.Contains(initializedNetworkState.ifnames, ifname) {
		return
	}
	initializedNetworkState.ifnames = append(initializedNetworkState.ifnames, ifname)
}

func initializedInterfaces() []string {
	initializedNetworkState.Lock()
	defer initializedNetworkState.Unlock()

	return append([]string(nil), initializedNetworkState.ifnames...)
}

func parseDNSServers(raw string) ([]net.IP, error) {
	var ips []net.IP
	for server := range strings.SplitSeq(raw, ",") {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}
		ip := net.ParseIP(server)
		if ip == nil {
			return nil, fmt.Errorf("Unable to parse IP address for DNS server: %v", server)
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func runDhcp(ifname string) ([]net.IP, error) {
	dhcp := client4.NewClient()
	var conversation []*dhcpv4.DHCPv4
	for range 40 {
		var err error
		conversation, err = dhcp.Exchange(ifname)
		if err == nil {
			break
		}
		debug("%s got error from DHCP exchange: %v", ifname, err)
		time.Sleep(time.Second)
	}
	var ack *dhcpv4.DHCPv4
	for _, m := range conversation {
		switch m.MessageType() {
		case dhcpv4.MessageTypeAck:
			ack = m
		}
	}
	if ack == nil {
		return nil, fmt.Errorf("%s: no DHCP ACK received", ifname)
	}

	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return nil, err
	}

	addr := netlink.Addr{IPNet: &net.IPNet{
		IP:   ack.YourIPAddr,
		Mask: ack.SubnetMask(),
	}}
	if err := netlink.AddrAdd(link, &addr); err != nil {
		return nil, err
	}

	gateway := dhcpv4.GetIP(dhcpv4.OptionRouter, ack.Options)
	if gateway != nil {
		defaultRoute := netlink.Route{Gw: gateway}
		if err := netlink.RouteAdd(&defaultRoute); err != nil {
			return nil, err
		}
	}

	return dhcpv4.GetIPs(dhcpv4.OptionDomainNameServer, ack.Options), nil
}

const (
	// how long DHCPv6 keeps trying
	dhcp6Timeout = 30 * time.Second
	// how long each DHCPv6 exchange waits for a reply
	dhcp6ExchangeTimeout = 5 * time.Second
)

func runDhcp6(ifname string) ([]net.IP, error) {
	var reply *dhcpv6.Message
	deadline := time.Now().Add(dhcp6Timeout)
	for time.Now().Before(deadline) {
		client, err := nclient6.New(ifname)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), dhcp6ExchangeTimeout)
			var advertise *dhcpv6.Message
			if advertise, err = client.Solicit(ctx); err == nil {
				reply, err = client.Request(ctx, advertise)
			}
			cancel()
			client.Close()
		}
		if err == nil {
			break
		}
		debug("%s got error from DHCPv6 exchange: %v", ifname, err)
		time.Sleep(time.Second)
	}
	if reply == nil {
		return nil, fmt.Errorf("%s: no DHCPv6 reply received", ifname)
	}

	iana := reply.Options.OneIANA()
	if iana == nil || len(iana.Options.Addresses()) == 0 {
		return nil, fmt.Errorf("%s: DHCPv6 reply has no address", ifname)
	}

	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return nil, err
	}

	addr := netlink.Addr{IPNet: &net.IPNet{
		IP:   iana.Options.Addresses()[0].IPv6Addr,
		Mask: net.CIDRMask(128, 128),
	}}
	if err := netlink.AddrAdd(link, &addr); err != nil {
		return nil, err
	}

	return reply.Options.DNS(), nil
}

func shutdownNetwork() {
	for _, ifname := range initializedInterfaces() {
		debug("shutting down network interface %s", ifname)
		link, err := netlink.LinkByName(ifname)
		if err != nil {
			continue
		}

		addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
		for _, a := range addrs {
			_ = netlink.AddrDel(link, &a)
		}

		routes, _ := netlink.RouteList(link, netlink.FAMILY_ALL)
		for _, r := range routes {
			_ = netlink.RouteDel(&r)
		}

		_ = netlink.LinkSetDown(link)
	}
}

func initializeNetworkInterface(ifname string) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	hardwareAddr := link.Attrs().HardwareAddr
	debug("detected network interface %s (%s)", ifname, hardwareAddr)

	if len(config.Network.Interfaces) > 0 {
		if !macListContains(hardwareAddr, config.Network.Interfaces) {
			info("interface %s (%s) is not in 'active' list, skipping it", ifname, hardwareAddr)
			return nil
		}
	}

	ch := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	defer close(done)
	if err := netlink.LinkSubscribe(ch, done); err != nil {
		return err
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	rememberInitializedInterface(ifname)

	timeout := time.After(20 * time.Second)
	debug("%s waiting interface to be UP", ifname)
linkReadinessLoop:
	for {
		select {
		case ev := <-ch:
			if ifname == ev.Link.Attrs().Name && (ev.IfInfomsg.Flags&unix.IFF_UP != 0) {
				debug("%s: interface is UP", ifname)
				break linkReadinessLoop
			}
		case <-timeout:
			return fmt.Errorf("Unable to setup network link %s: timeout", ifname)
		}
	}

	c := config.Network
	if c.Dhcp {
		debug("%s: run DHCP", ifname)
		var dns6 []net.IP
		var err6 error
		var wg sync.WaitGroup
		wg.Go(func() { dns6, err6 = runDhcp6(ifname) })

		dns4, err4 := runDhcp(ifname)
		if dns4 != nil {
			if err := writeResolvConf(dns4); err != nil {
				return err
			}
		}
		wg.Wait()
		switch {
		case err4 != nil && err6 != nil:
			return errors.Join(err4, err6)
		case err4 != nil:
			info("%s: no DHCPv4 lease, using DHCPv6: %v", ifname, err4)
		case err6 != nil:
			debug("%s: no DHCPv6 lease: %v", ifname, err6)
		}
		if dns6 != nil {
			if err := writeResolvConf(slices.Concat(dns4, dns6)); err != nil {
				return err
			}
		}
	} else {
		// static address
		if c.IP != "" {
			addr, err := netlink.ParseAddr(c.IP)
			if err != nil {
				return err
			}
			if err := netlink.AddrAdd(link, addr); err != nil {
				return err
			}
		}

		if c.Gateway != "" {
			gw := net.ParseIP(c.Gateway)
			if gw == nil {
				return fmt.Errorf("network.gateway: unable to parse ip address %s", c.Gateway)
			}
			defaultRoute := netlink.Route{Gw: gw}
			if err := netlink.RouteAdd(&defaultRoute); err != nil {
				return err
			}
		}

		if c.DNSServers != "" {
			ips, err := parseDNSServers(c.DNSServers)
			if err != nil {
				return err
			}
			if err := writeResolvConf(ips); err != nil {
				return err
			}
		}
	}

	return nil
}

func writeResolvConf(servers []net.IP) error {
	var resolvConf bytes.Buffer
	for _, ip := range servers {
		resolvConf.WriteString("nameserver ")
		resolvConf.WriteString(ip.String())
		resolvConf.WriteByte('\n')
	}
	resolvConf.WriteString("search .\n")

	return os.WriteFile("/etc/resolv.conf", resolvConf.Bytes(), 0o644)
}
