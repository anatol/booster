package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// These tests compare booster's crypttab-versus-cmdline resolution against
// systemd's, by running systemd's own generator and diffing its output. They
// answer "does booster do what systemd does" from what systemd emits, not from
// crypttab(5), whose wording is ambiguous on field 3, and not from reading
// cryptsetup-generator.c either. Both were read while writing these cases and
// both produced a wrong answer at least once.
const systemdGenerator = "/usr/lib/systemd/system-generators/systemd-cryptsetup-generator"

// execStartRe pulls the four positional arguments systemd-cryptsetup is invoked
// with. They are the four crypttab fields in order: volume-name, encrypted
// device, key file, options.
var execStartRe = regexp.MustCompile(`ExecStart=\S+ attach '([^']*)' '([^']*)' '([^']*)' '([^']*)'`)

type sdUnit struct{ name, device, keyfile, options string }

// runSystemdGenerator runs the real generator over a synthetic crypttab and
// command line and returns one entry per unit it emitted. cmdline uses the bare
// luks.* spelling: outside an initrd the rd. prefix is stripped from arguments
// meant only for the initrd, so rd.luks.* would be discarded before the
// generator sees it.
func runSystemdGenerator(t *testing.T, cmdline, crypttab string) []sdUnit {
	t.Helper()
	if _, err := os.Stat(systemdGenerator); err != nil {
		t.Skipf("%s not present", systemdGenerator)
	}

	dir := t.TempDir()
	ctPath := filepath.Join(dir, "crypttab")
	require.NoError(t, os.WriteFile(ctPath, []byte(crypttab), 0o644))
	dest := filepath.Join(dir, "normal")
	for _, d := range []string{dest, filepath.Join(dir, "early"), filepath.Join(dir, "late")} {
		require.NoError(t, os.MkdirAll(d, 0o755))
	}

	cmd := exec.Command(systemdGenerator, dest, filepath.Join(dir, "early"), filepath.Join(dir, "late"))
	cmd.Env = append(os.Environ(), "SYSTEMD_CRYPTTAB="+ctPath, "SYSTEMD_PROC_CMDLINE="+cmdline)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "generator failed: %s", out)

	units, err := filepath.Glob(filepath.Join(dest, "systemd-cryptsetup@*.service"))
	require.NoError(t, err)
	sort.Strings(units)

	var got []sdUnit
	for _, u := range units {
		body, err := os.ReadFile(u)
		require.NoError(t, err)
		m := execStartRe.FindStringSubmatch(string(body))
		require.NotNil(t, m, "no ExecStart found in %s:\n%s", u, body)
		got = append(got, sdUnit{name: m[1], device: m[2], keyfile: m[3], options: m[4]})
	}
	return got
}

// canonDevice renders a device the same way on both sides. systemd resolves a
// UUID= reference to its /dev/disk/by-uuid path; booster keeps the reference.
func canonDevice(s string) string {
	if u, ok := strings.CutPrefix(s, "/dev/disk/by-uuid/"); ok {
		return "UUID=" + u
	}
	if l, ok := strings.CutPrefix(s, "/dev/disk/by-label/"); ok {
		return "LABEL=" + l
	}
	return s
}

// canonKeyfile maps systemd's "no key file" spellings onto booster's empty one.
// none and - are crypttab's way of asking for a passphrase prompt.
func canonKeyfile(s string) string {
	if s == "none" || s == "-" {
		return ""
	}
	return s
}

// canonOptions puts an option list in a form both sides can be compared in.
// luks is a type marker booster consumes at parse time because it detects LUKS
// from the superblock, x-initrd.attach is stripped by the generator, and
// allow-discards is the dm-crypt flag name booster stores discard as.
func canonOptions(s string) []string {
	out := []string{}
	for _, o := range strings.Split(s, ",") {
		switch o = strings.TrimSpace(o); o {
		case "", "luks", "x-initrd.attach":
			continue
		case "discard":
			o = "allow-discards"
		}
		out = append(out, o)
	}
	sort.Strings(out)
	return out
}

// boosterUnit renders a resolved mapping in systemd's four-field shape.
func boosterUnit(m *luksMapping) sdUnit {
	device := "?"
	if m.dataDeviceRef != nil {
		device = refString(m.dataDeviceRef)
	} else if m.ref != nil {
		device = refString(m.ref)
	}

	opts := append([]string{}, m.options...)
	if m.tries != luksOptionUnset {
		opts = append(opts, fmt.Sprintf("tries=%d", m.tries))
	}
	if m.keySlot != luksOptionUnset {
		opts = append(opts, fmt.Sprintf("key-slot=%d", m.keySlot))
	}
	if m.keyfileOffset != 0 {
		opts = append(opts, fmt.Sprintf("keyfile-offset=%d", m.keyfileOffset))
	}
	if m.keyfileSize != 0 {
		opts = append(opts, fmt.Sprintf("keyfile-size=%d", m.keyfileSize))
	}
	if m.header != "" {
		opts = append(opts, "header="+m.header)
	}
	sort.Strings(opts)
	return sdUnit{name: m.name, device: device, keyfile: m.keyfile, options: strings.Join(opts, ",")}
}

func refString(r *deviceRef) string {
	switch r.format {
	case refFsUUID:
		return "UUID=" + r.data.(UUID).toString()
	case refFsLabel:
		return "LABEL=" + r.data.(string)
	case refPath:
		return r.data.(string)
	}
	return fmt.Sprintf("%v", r.data)
}

const conformanceUUID = "639b8fdd-36ba-443e-be3e-e5b335935502"

// TestSystemdConformance pins booster's resolution of all four crypttab fields
// to what systemd's generator emits for the same inputs.
func TestSystemdConformance(t *testing.T) {
	u := conformanceUUID
	entry := "cryptroot UUID=" + u + " /entry.key luks,tries=2,discard\n"
	bare := "cryptroot UUID=" + u + " none luks\n"

	for _, tc := range []struct{ name, cmdline, crypttab string }{
		{"entry alone", "", entry},
		{"entry + uuid", "luks.uuid=" + u, entry},
		{"entry + name", "luks.name=" + u + "=fromcmdline", entry},
		{"entry + per-device key", "luks.uuid=" + u + " luks.key=" + u + "=/cmdline.key", entry},
		{"entry + default key", "luks.uuid=" + u + " luks.key=/default.key", entry},
		{"entry + per-device options", "luks.uuid=" + u + " luks.options=" + u + "=tries=9", entry},
		{"entry + default options", "luks.uuid=" + u + " luks.options=key-slot=3,tries=5", entry},
		{"entry + both option forms", "luks.uuid=" + u + " luks.options=key-slot=3 luks.options=" + u + "=tries=9", entry},
		{"entry wanting a prompt + per-device key", "luks.uuid=" + u + " luks.key=" + u + "=/own.key", bare},
		{"entry with keyfile bounds + per-device key", "luks.uuid=" + u + " luks.key=" + u + "=/b.key",
			"cryptroot UUID=" + u + " /a.key luks,keyfile-offset=4096,keyfile-size=64\n"},
		{"entry with header + per-device options", "luks.uuid=" + u + " luks.options=" + u + "=tries=9",
			"cryptroot UUID=" + u + " none luks,header=/h.hdr\n"},
		{"no entry + uuid", "luks.uuid=" + u, ""},
		{"no entry + name", "luks.name=" + u + "=fromcmdline", ""},
		{"no entry + default key", "luks.uuid=" + u + " luks.key=/default.key", ""},
		{"no entry + both key forms", "luks.uuid=" + u + " luks.key=/default.key luks.key=" + u + "=/own.key", ""},
		{"no entry + default options", "luks.uuid=" + u + " luks.options=key-slot=3,tries=5", ""},
		{"no entry + per-device options", "luks.uuid=" + u + " luks.options=" + u + "=tries=9", ""},
		{"no entry + both option forms", "luks.uuid=" + u + " luks.options=key-slot=3 luks.options=" + u + "=tries=9", ""},
		{"entry + data device", "luks.uuid=" + u + " luks.data=" + u + "=/dev/vdz", entry},
		{"no entry + data device", "luks.uuid=" + u + " luks.data=" + u + "=/dev/vdz", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sd := runSystemdGenerator(t, tc.cmdline, tc.crypttab)
			require.Len(t, sd, 1, "case expects exactly one systemd unit")
			want := sd[0]

			// booster only answers to the rd. spelling; inside an initrd systemd
			// strips that prefix, so the two are the same parameters.
			var rd []string
			for _, f := range strings.Fields(tc.cmdline) {
				rd = append(rd, "rd."+f)
			}
			resolveSources(t, strings.Join(rd, " "), tc.crypttab)
			require.Len(t, luksMappings, 1, "one device must leave one mapping")
			got := boosterUnit(luksMappings[0])

			require.Equal(t, want.name, got.name, "field 1, volume name")
			require.Equal(t, canonDevice(want.device), got.device, "field 2, encrypted device")
			require.Equal(t, canonKeyfile(want.keyfile), got.keyfile, "field 3, key file")
			require.Equal(t, canonOptions(want.options), canonOptions(got.options), "field 4, options")

			// Resolution is only half the path. The device then arrives and
			// matchLuksMapping runs, which can compose a mapping a second time.
			// What was resolved has to survive that.
			withLuksGlobals(t)
			uuid, err := parseUUID(conformanceUUID)
			require.NoError(t, err)
			m := matchLuksMapping(&blkInfo{path: "/dev/sda2", format: "luks", uuid: uuid})
			require.NotNil(t, m, "the device must match the mapping it resolved to")
			require.Equal(t, got, boosterUnit(m), "device arrival changed the resolved mapping")
		})
	}
}

// Booster pairs an entry and a parameter that reference one device in different
// forms; systemd does not, and cannot: its generator runs before the device
// exists, so all it has is the literal text of the second field. Where the two
// references differ systemd's whitelist drops the entry, and everything in it is
// lost. Booster resolves at device arrival, where uuid, label, path and wwid are
// known at once, and combines the two records.
//
// This is a deliberate divergence, not a gap, and it is the one place the
// conformance table above cannot be extended to. Both behaviours are pinned here
// so that neither changes by accident.
func TestDifferentlyReferencedEntryDivergesFromSystemd(t *testing.T) {
	u := conformanceUUID
	crypttab := "cryptroot LABEL=crypt none luks,tries=7\n"

	sd := runSystemdGenerator(t, "luks.uuid="+u, crypttab)
	require.Len(t, sd, 1, "systemd emits the command line's device only")
	require.Equal(t, "luks-"+u, sd[0].name, "the entry was not created")
	require.Empty(t, canonOptions(sd[0].options), "so its tries=7 is lost")

	withLuksGlobals(t)
	origGlobal := globalLuksOptions
	t.Cleanup(func() { globalLuksOptions = origGlobal })
	globalLuksOptions = newLuksOptions()

	resolveSources(t, "rd.luks.uuid="+u, crypttab)
	require.Len(t, luksMappings, 2, "two records until the device reconciles them")

	uuid, err := parseUUID(u)
	require.NoError(t, err)
	m := matchLuksMapping(&blkInfo{path: "/dev/sda2", format: "luks", uuid: uuid, label: "crypt"})
	require.NotNil(t, m)
	require.Equal(t, "cryptroot", m.name, "booster keeps the entry")
	require.Equal(t, 7, m.tries, "and its options take effect")
	require.Len(t, luksMappings, 2, "the list is not rewritten; the device unlocks once, as the combined mapping")
}
