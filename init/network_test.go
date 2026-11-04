package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/require"
)

// useTempResolvConf points resolv.conf at a temporary directory and empties
// the leased DNS servers, restoring both when the test ends.  Tests using it
// share package state and must not run in parallel.
func useTempResolvConf(t *testing.T) string {
	t.Helper()

	oldPath := resolvConfPath
	resolvConfPath = filepath.Join(t.TempDir(), "resolv.conf")
	leasedDNSServers.ipv4, leasedDNSServers.ipv6 = nil, nil
	t.Cleanup(func() {
		resolvConfPath = oldPath
		leasedDNSServers.ipv4, leasedDNSServers.ipv6 = nil, nil
	})
	return resolvConfPath
}

func ips(t *testing.T, addrs ...string) []net.IP {
	t.Helper()

	var parsed []net.IP
	for _, a := range addrs {
		ip := net.ParseIP(a)
		require.NotNil(t, ip, a)
		parsed = append(parsed, ip)
	}
	return parsed
}

func TestAddDNSServersWritesEachLease(t *testing.T) {
	path := useTempResolvConf(t)

	// a DHCPv6 lease arriving first is written straight away, without
	// waiting for DHCPv4
	require.NoError(t, addDNSServers(ips(t, "fd00::53")))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "nameserver fd00::53\nsearch .\n", string(data))

	require.NoError(t, addDNSServers(ips(t, "10.0.2.3")))
	data, err = os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "nameserver 10.0.2.3\nnameserver fd00::53\nsearch .\n", string(data))
}

func TestAddDNSServersSkipsLeaseWithNothingNew(t *testing.T) {
	path := useTempResolvConf(t)

	// a lease without DNS servers writes no file
	require.NoError(t, addDNSServers(nil))
	_, err := os.Stat(path)
	require.ErrorIs(t, err, os.ErrNotExist)

	require.NoError(t, addDNSServers(ips(t, "10.0.2.3")))
	require.NoError(t, os.WriteFile(path, []byte("unchanged\n"), 0o644))

	// one repeating a server already listed leaves the file alone
	require.NoError(t, addDNSServers(ips(t, "10.0.2.3")))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "unchanged\n", string(data))
}

// TestAddDNSServersIgnoresFamilyInterleaving delivers two interfaces' DHCPv4
// and DHCPv6 leases in several interleavings.  Each family keeps the order
// its own leases arrived in, so the file is the same however the two
// families interleave, and servers both interfaces handed out appear once.
func TestAddDNSServersIgnoresFamilyInterleaving(t *testing.T) {
	v4 := [][]net.IP{
		ips(t, "10.0.2.3", "10.0.2.4"),
		ips(t, "10.0.2.4", "192.0.2.53"),
	}
	v6 := [][]net.IP{
		ips(t, "fd00::53"),
		ips(t, "fd00::53", "2001:db8::53"),
	}
	const want = "nameserver 10.0.2.3\nnameserver 10.0.2.4\nnameserver 192.0.2.53\n" +
		"nameserver fd00::53\nnameserver 2001:db8::53\nsearch .\n"

	// each step takes the next lease of the family it names
	for name, order := range map[string]string{
		"IPv4 first":  "4466",
		"IPv6 first":  "6644",
		"alternating": "6464",
		"mixed":       "4664",
	} {
		t.Run(name, func(t *testing.T) {
			path := useTempResolvConf(t)
			next4, next6 := v4, v6
			for _, family := range order {
				if family == '4' {
					require.NoError(t, addDNSServers(next4[0]))
					next4 = next4[1:]
				} else {
					require.NoError(t, addDNSServers(next6[0]))
					next6 = next6[1:]
				}
			}

			data, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, want, string(data))
		})
	}
}

// TestDhcp6ClientIDStable builds Solicits the way nclient6 does, a second
// apart, and checks they carry the same MAC-based DUID-LL instead of the
// time-based DUID-LLT NewSolicit puts in by default.
func TestDhcp6ClientIDStable(t *testing.T) {
	t.Parallel()

	hwaddr := net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}

	solicit := func() dhcpv6.DUID {
		msg, err := dhcpv6.NewSolicit(hwaddr, dhcpv6.WithClientID(dhcp6ClientID(hwaddr)))
		require.NoError(t, err)
		require.Len(t, msg.Options.Get(dhcpv6.OptionClientID), 1)
		return msg.Options.ClientID()
	}

	first := solicit()
	// DUID-LLT counts seconds, so a second apart it would differ
	time.Sleep(1100 * time.Millisecond)
	second := solicit()

	require.Equal(t, dhcpv6.DUID_LL, first.DUIDType())
	require.Equal(t, first.ToBytes(), second.ToBytes())
	require.Equal(t, []byte(hwaddr), []byte(first.(*dhcpv6.DUIDLL).LinkLayerAddr))
}

func TestWriteResolvConfReplacesFile(t *testing.T) {
	path := useTempResolvConf(t)
	require.NoError(t, os.WriteFile(path, []byte("nameserver 192.0.2.1\nnameserver 192.0.2.2\n"), 0o600))

	require.NoError(t, writeResolvConf(ips(t, "10.0.2.3")))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "nameserver 10.0.2.3\nsearch .\n", string(data))

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), info.Mode().Perm())

	// the temporary file was renamed into place, not left beside it
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	require.Len(t, entries, 1)
}
