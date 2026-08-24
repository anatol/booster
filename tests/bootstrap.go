package tests

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
)

// Every generator needs root, so building images on demand means a password
// prompt part way through a run, once per image. This builds them all up
// front, behind one prompt, and runs no tests.
var bootstrapAssets = flag.Bool("bootstrap", false,
	"build every missing test image, then exit without running tests")

// A few generators write files the others read, and name order puts all three
// behind the images that need them.
var buildFirst = []string{
	"tang/key.pub",                  // the tang images embed this advertisement
	"tpm2/tpm2-00.permall.pristine", // every TPM2 image is enrolled against it
	"luks2.detached_header.img",     // writes the header the hdrdev image copies
}

// clevis resolves a pin by running clevis-encrypt-<pin>, which builds the JWE
// with jose and then reaches for whatever the policy binds to. The pin comes
// from the image's environment rather than the script, so it cannot be part of
// the script's own declaration.
var pinTools = map[string][]string{
	"tpm2":    {"clevis", "jose", "swtpm", "swtpm_ioctl", "tpm2_createprimary"},
	"tang":    {"clevis", "jose", "tangctl"},
	"remote":  {"clevis", "jose", "tangctl"},
	"yubikey": {"clevis", "jose", "ykchalresp"},
}

var toolsDeclaration = regexp.MustCompile(`(?m)^#[ \t]*tools:[ \t]*(.*)$`)

// scriptTools returns what a generator declares in its "# tools:" lines. A
// script with none needs nothing beyond coreutils, util-linux and mkfs.ext4.
func scriptTools(script string) []string {
	body, err := os.ReadFile("generators/" + script)
	if err != nil {
		return nil
	}
	var tools []string
	for _, m := range toolsDeclaration.FindAllStringSubmatch(string(body), -1) {
		tools = append(tools, strings.Fields(m[1])...)
	}
	return tools
}

// tangctl and the clevis-encrypt-<pin> scripts are booster's own dependencies,
// not system packages. Go downloads the modules but puts neither on PATH, so
// build them here from the versions go.mod pins.
var generatorPath = sync.OnceValue(func() string {
	tangctl := filepath.Join(binariesDir, "tangctl")
	if err := exec.Command("go", "build", "-o", tangctl, "github.com/anatol/tang.go/cmd/tangctl").Run(); err != nil {
		fmt.Fprintf(os.Stderr, "cannot build tangctl, images that need it will be skipped: %v\n", err)
	}
	// The module cache is read-only, so the pin scripts have to be copied out
	// before anything can execute them.
	if out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/anatol/clevis.go").Output(); err == nil {
		pins, _ := filepath.Glob(filepath.Join(strings.TrimSpace(string(out)), "clevis-*"))
		for _, src := range pins {
			dst := filepath.Join(binariesDir, filepath.Base(src))
			if _, err := copyFile(src, dst); err == nil {
				_ = os.Chmod(dst, 0o755)
			}
		}
	}
	return binariesDir + ":" + os.Getenv("PATH")
})

// findTool resolves a tool the way a generator would, which is not the same
// as resolving it against this process's PATH.
func findTool(name string) string {
	for _, dir := range strings.Split(generatorPath(), ":") {
		path := filepath.Join(dir, name)
		if fi, err := os.Stat(path); err == nil && fi.Mode()&0o111 != 0 {
			return path
		}
	}
	return ""
}

func hasTool(name string) bool {
	return findTool(name) != ""
}

// clevisPin returns an image's clevis pin, or "" if it isn't clevis-bound.
func clevisPin(env []string) string {
	for _, e := range env {
		if pin, ok := strings.CutPrefix(e, "CLEVIS_PIN="); ok {
			return pin
		}
	}
	return ""
}

// requiredTools names what an image needs beyond coreutils, util-linux and
// mkfs.ext4: its script's own declaration, plus its clevis pin's if any.
func requiredTools(name string) []string {
	gen := assetGenerators[name]
	tools := scriptTools(gen.script)
	if pin := clevisPin(gen.env); pin != "" {
		tools = append(tools, pinTools[pin]...)
		if slices.Contains(gen.env, "LUKS_VERSION=1") {
			// LUKS1 has nowhere in the header to keep a binding, so clevis
			// puts it in a LUKSMeta slot instead of a LUKS2 token.
			tools = append(tools, "luksmeta")
		}
	}
	return tools
}

// unmet returns what this host is short of for one image. Being short of
// something is not a failure: no distro packages every one of these tools, and
// only the images that need it are affected.
func unmet(name string) []string {
	var absent []string
	for _, tool := range requiredTools(name) {
		if !hasTool(tool) && !slices.Contains(absent, tool) {
			absent = append(absent, tool)
		}
	}
	// Having ykchalresp is not having a key. ykinfo prints 1 for a programmed
	// slot, fails outright when none answers, and asks for no touch either way.
	// Slot 2 is what the image's CLEVIS_CONFIG binds to.
	if clevisPin(assetGenerators[name].env) == "yubikey" {
		out, err := exec.Command("ykinfo", "-q", "-2").Output()
		if err != nil || strings.TrimSpace(string(out)) != "1" {
			absent = append(absent, "a Yubikey with slot 2 programmed")
		}
	}
	return absent
}

// sudoCanFind reports whether root would resolve a tool. sudoers' secure_path
// can replace PATH outright for a privileged command, ignoring whatever PATH
// the calling shell had, so this is not the same question as hasTool.
func sudoCanFind(tool string) bool {
	return exec.Command("sudo", "sh", "-c", "command -v "+tool).Run() == nil
}

// reportTools lists every tool a not-yet-present image needs, ticked where
// this host has it, so what's missing is visible at a glance instead of
// buried in one skip line per image.
func reportTools(names []string) {
	var tools []string
	for _, name := range names {
		for _, tool := range requiredTools(name) {
			if !slices.Contains(tools, tool) {
				tools = append(tools, tool)
			}
		}
	}
	sort.Strings(tools)
	fmt.Println("tools needed for what's missing or skipped:")
	for _, tool := range tools {
		mark := "✓"
		if !hasTool(tool) {
			mark = "✗"
		}
		fmt.Printf("  %s %s\n", mark, tool)
	}
	fmt.Println()
}

// needsRoot reports whether a generator calls sudo. Reading the script beats
// keeping a list of which ones do, which would drift the first time one changed.
func needsRoot(script string) bool {
	body, err := os.ReadFile("generators/" + script)
	if err != nil {
		return true // prime sudo rather than fail late
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && line[0] != '#' && strings.Contains(line, "sudo ") {
			return true
		}
	}
	return false
}

// verifyAsset reads a generated image back. A generator that fails part way can
// still exit 0 and leave something plausible behind: a LUKS header with no
// keyslots, or an image bound to no one.
func verifyAsset(name string) error {
	gen := assetGenerators[name]
	var uuid string
	for _, e := range gen.env {
		if strings.HasPrefix(e, "HEADER_OUTPUT=") {
			return nil // the header is in its own file, not in the image
		}
		if v, ok := strings.CutPrefix(e, "LUKS_UUID="); ok {
			uuid = v
		}
	}
	if uuid == "" || !hasTool("cryptsetup") {
		return nil // nothing outside the image says what it should hold
	}

	dump, err := exec.Command("cryptsetup", "luksDump", "assets/"+name).Output()
	if err != nil {
		return fmt.Errorf("no readable LUKS header")
	}
	out := string(dump)
	if !strings.Contains(out, uuid) {
		return fmt.Errorf("LUKS UUID is not %s", uuid)
	}
	// Enrolling a TPM2 or FIDO2 token typically wipes the initial passphrase
	// slot, so the surviving key can land in any slot, not just 0.
	if !keyslotPresent.MatchString(out) {
		return fmt.Errorf("no key slot, so nothing can unlock it")
	}
	if pin := clevisPin(gen.env); pin == "tang" || pin == "remote" {
		if ok, err := clevisStillBound(name, pin, gen.env); err != nil {
			return err
		} else if !ok {
			return fmt.Errorf("bound to a %s key that no longer exists; rebuild assets/%s/key.pub first", pin, pin)
		}
	}
	return nil
}

var keyslotPresent = regexp.MustCompile(`(?m)^\s*\d+: luks2$|Key Slot \d+: ENABLED`)

// clevis's own fixed LUKSMeta slot identifier, used for every LUKS1 binding.
const clevisLUKSMetaUUID = "cb6e8904-81ff-40da-a84a-07ab9ab5715e"

// clevisStillBound reports whether a tang or remote binding still points at
// the advertisement this repo currently has. Rebuilding assets/<pin>/key.pub
// independently of the images bound against it leaves them silently unable to
// unlock, since the JWE embeds the advertising server's key, not a reference.
func clevisStillBound(name, pin string, env []string) (bool, error) {
	current, err := advertisedKeyX("assets/" + pin + "/key.pub")
	if err != nil {
		return true, nil // nothing to compare against; not this image's fault
	}
	luks1 := slices.Contains(env, "LUKS_VERSION=1")
	if luks1 && !hasTool("luksmeta") {
		return true, nil // can't read the binding without the tool
	}
	bound, err := boundAdvertisedKey(name, luks1)
	if err != nil {
		return false, fmt.Errorf("cannot read its clevis binding: %v", err)
	}
	return bound == current, nil
}

// advertisedKeyX reads the signing key's public coordinate out of a tang/jose
// advertisement file (a signed JWS whose payload is the key set).
func advertisedKeyX(file string) (string, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	var jws struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(data, &jws); err != nil {
		return "", err
	}
	payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		return "", err
	}
	var keys struct {
		Keys []struct {
			X string `json:"x"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(payload, &keys); err != nil || len(keys.Keys) == 0 {
		return "", fmt.Errorf("no keys in %s", file)
	}
	return keys.Keys[0].X, nil
}

// boundAdvertisedKey extracts the advertisement a clevis binding was made
// against, from a LUKS2 token or (LUKS1 has no token, only LUKSMeta slots) the
// compact JWE a LUKSMeta slot holds. Either way it's the JWE's protected
// header, which clevis stores the whole advertisement inside rather than a
// pointer to it.
func boundAdvertisedKey(name string, luks1 bool) (string, error) {
	var protected string
	if luks1 {
		show, err := exec.Command("luksmeta", "show", "-d", "assets/"+name).Output()
		if err != nil {
			return "", fmt.Errorf("cannot read LUKSMeta: %v", err)
		}
		var slot string
		for _, line := range strings.Split(string(show), "\n") {
			if strings.Contains(line, clevisLUKSMetaUUID) {
				slot = strings.Fields(line)[0]
			}
		}
		if slot == "" {
			return "", fmt.Errorf("no clevis LUKSMeta slot")
		}
		jwe, err := exec.Command("luksmeta", "load", "-d", "assets/"+name, "-s", slot, "-u", clevisLUKSMetaUUID).Output()
		if err != nil {
			return "", fmt.Errorf("cannot load LUKSMeta slot: %v", err)
		}
		protected = strings.Split(strings.TrimSpace(string(jwe)), ".")[0]
	} else {
		export, err := exec.Command("cryptsetup", "token", "export", "--token-id", "0", "assets/"+name).Output()
		if err != nil {
			return "", fmt.Errorf("cannot read LUKS2 token: %v", err)
		}
		var token struct {
			JWE struct {
				Protected string `json:"protected"`
			} `json:"jwe"`
		}
		if err := json.Unmarshal(export, &token); err != nil {
			return "", fmt.Errorf("cannot parse LUKS2 token: %v", err)
		}
		protected = token.JWE.Protected
	}

	header, err := base64.RawURLEncoding.DecodeString(protected)
	if err != nil {
		return "", fmt.Errorf("cannot decode JWE header: %v", err)
	}
	// "clevis" holds a "pin" string naming which of its other keys is the
	// pin's own section, e.g. {"pin":"remote","remote":{"adv":{"keys":[...]}}}.
	var top struct {
		Clevis map[string]json.RawMessage `json:"clevis"`
	}
	if err := json.Unmarshal(header, &top); err != nil {
		return "", fmt.Errorf("cannot parse JWE header: %v", err)
	}
	var pin string
	if err := json.Unmarshal(top.Clevis["pin"], &pin); err != nil {
		return "", fmt.Errorf("no clevis pin in JWE header: %v", err)
	}
	var section struct {
		Adv struct {
			Keys []struct {
				X string `json:"x"`
			} `json:"keys"`
		} `json:"adv"`
	}
	if err := json.Unmarshal(top.Clevis[pin], &section); err != nil || len(section.Adv.Keys) == 0 {
		return "", fmt.Errorf("no advertisement in JWE header")
	}
	return section.Adv.Keys[0].X, nil
}

func generateAllAssets() int {
	var missing, present, skipped []string
	reasons := map[string][]string{}
	for name := range assetGenerators {
		if fileExists("assets/" + name) {
			present = append(present, name)
			continue
		}
		if absent := unmet(name); len(absent) > 0 {
			skipped = append(skipped, name)
			reasons[name] = absent
			continue
		}
		missing = append(missing, name)
	}
	sort.Strings(missing)
	sort.Strings(present)
	sort.Strings(skipped)

	// An image built cleanly once can still rot: a script upgrade that starts
	// wiping a keyslot, or a generator killed mid-write on a prior run.
	var broken []string
	for _, name := range present {
		if err := verifyAsset(name); err != nil {
			broken = append(broken, name)
			fmt.Fprintf(os.Stderr, "%s is present but %v; delete it to rebuild\n", name, err)
		}
	}

	rank := func(name string) int {
		if i := slices.Index(buildFirst, name); i >= 0 {
			return i
		}
		return len(buildFirst)
	}
	slices.SortStableFunc(missing, func(a, b string) int { return rank(a) - rank(b) })

	for _, name := range skipped {
		fmt.Printf("skipping %s (needs %s)\n", name, strings.Join(reasons[name], ", "))
	}

	summarize := func(built, failed int) int {
		fmt.Printf("%d built, %d present, %d skipped, %d failed, %d broken\n",
			built, len(present), len(skipped), failed, len(broken))
		if failed > 0 || len(broken) > 0 {
			return 1
		}
		return 0
	}

	if len(missing) == 0 {
		return summarize(0, 0)
	}

	reportTools(slices.Concat(missing, skipped))
	fmt.Printf("building %d missing image(s):\n", len(missing))
	for _, name := range missing {
		fmt.Printf("  %s\n", name)
	}
	fmt.Println()

	if slices.ContainsFunc(missing, func(n string) bool { return needsRoot(assetGenerators[n].script) }) {
		sudo := exec.Command("sudo", "-v")
		sudo.Stdin, sudo.Stdout, sudo.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := sudo.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "cannot obtain root, so no image that needs it can be built: %v\n", err)
			return 1
		}
	}

	// clevis binds under sudo, and sudoers' secure_path can hide the custom
	// pins copied onto this process's own PATH, so a clevis image that looked
	// buildable a moment ago can still be unreachable once root is involved.
	missing = slices.DeleteFunc(missing, func(name string) bool {
		pin := clevisPin(assetGenerators[name].env)
		if pin == "" || sudoCanFind("clevis-encrypt-"+pin) {
			return false
		}
		fmt.Printf("skipping %s (needs clevis-encrypt-%s reachable under sudo; this host's sudoers secure_path excludes it)\n", name, pin)
		skipped = append(skipped, name)
		return true
	})

	var failed int
	for i, name := range missing {
		fmt.Printf("[%d/%d] %s\n", i+1, len(missing), name)
		err := checkAsset("assets/" + name)
		if err == nil {
			if err = verifyAsset(name); err != nil {
				_ = os.Remove("assets/" + name)
				err = fmt.Errorf("built but %v", err)
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAILED %s: %v\n", name, err)
			failed++
		}
	}

	fmt.Println()
	return summarize(len(missing)-failed, failed)
}
