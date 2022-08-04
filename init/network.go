package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/client4"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func runDhcp(ifname string) error {
	dhcp := client4.NewClient()
	var conversation []*dhcpv4.DHCPv4
	for i := 0; i < 40; i++ {
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
		return fmt.Errorf("%s: no DHCP ACK received", ifname)
	}

	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}

	addr := netlink.Addr{IPNet: &net.IPNet{
		IP:   ack.YourIPAddr,
		Mask: ack.SubnetMask(),
	}}
	if err := netlink.AddrAdd(link, &addr); err != nil {
		return err
	}

	gateway := dhcpv4.GetIP(dhcpv4.OptionRouter, ack.Options)
	if gateway != nil {
		defaultRoute := netlink.Route{Gw: gateway}
		if err := netlink.RouteAdd(&defaultRoute); err != nil {
			return err
		}
	}

	dnsServers := dhcpv4.GetIPs(dhcpv4.OptionDomainNameServer, ack.Options)
	if dnsServers != nil {
		if err := writeResolvConf(dnsServers); err != nil {
			return err
		}
	}

	return nil
}

func shutdownNetwork() {
	for _, ifname := range initializedIfnames {
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

var initializedIfnames []string

func initializeNetworkInterface(ifname string) error {
	debug("%s: start initializing network interface", ifname)
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
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
	initializedIfnames = append(initializedIfnames, ifname)

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
		if err := runDhcp(ifname); err != nil {
			return err
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
			servers := strings.Split(c.DNSServers, ",")
			ips := make([]net.IP, 0)
			for _, s := range servers {
				ip := net.ParseIP(s)
				if ip == nil {
					return fmt.Errorf("Unable to parse IP address for DNS server: %v", s)
				}
				ips = append(ips, ip)
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
