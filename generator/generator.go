package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cavaliergopher/cpio"
	"gopkg.in/yaml.v3"
)

// An internal structure that represents configuration for the generator.
// It is essentially combination of UserConfig + flags
type generatorConfig struct {
	networkConfigType       netConfigType
	networkStaticConfig     *networkStaticConfig
	networkActiveInterfaces []net.HardwareAddr
	universal               bool
	modules                 []string // extra modules to add
	modulesForceLoad        []string // extra modules to load at the boot time
	appendAllModAliases     bool
	compression             string
	timeout                 time.Duration
	extraFiles              []string
	output                  string
	forceOverwrite          bool // overwrite output file
	initBinary              string
	kernelVersion           string
	modulesDir              string
	debug                   bool
	readDeviceAliases       func() (set, error)
	readHostModules         func(kernelVer string) (set, error)
	readModprobeOptions     func() (map[string]string, error)
	stripBinaries           bool
	enableLVM               bool
	enableMdraid            bool
	mdraidConfigPath        string
	enableZfs               bool
	zfsImportParams         string
	zfsCachePath            string

	enablePlymouth bool

	// virtual console configs
	enableVirtualConsole     bool
	vconsolePath, localePath string
}

type networkStaticConfig struct {
	ip         string
	gateway    string
	dnsServers string // comma-separated list
}

type netConfigType int

const (
	netOff netConfigType = iota
	netDhcp
	netStatic
)

var (
	imageModulesDir = "/usr/lib/modules/"
	firmwareDir     = "/usr/lib/firmware/"
)

// This is default modules list checked by booster. It either specifies a name of the module
// or whole directory that added recursively. Dependencies of these scanned modules are added as well.
//
// In case of 'universal' build all specified modules are added to the image.
// In case of 'host' build only modules for active devices are added.
var defaultModulesList = []string{
	"kernel/fs/",
	"kernel/arch/x86/crypto/",
	"kernel/crypto/",
	"kernel/drivers/input/serio/",
	"kernel/drivers/input/keyboard/",
	"kernel/drivers/md/",
	"kernel/drivers/char/tpm/",
	"kernel/drivers/usb/host/",
	"kernel/drivers/hid/",
	"kernel/drivers/ata/",
	"kernel/drivers/scsi/",
	"hid_generic", "usbhid", "sd_mod", "ahci",
	"sdhci", "sdhci_acpi", "sdhci_pci", "mmc_block", // mmc
	"nvme", "usb_storage", "uas",
	"efivarfs",
	"virtio_pci", "virtio_blk", "virtio_scsi", "virtio_crypto",
	"mptspi", "vmd",
}

func generateInitRamfs(conf *generatorConfig) error {
	if _, err := os.Stat(conf.output); (err == nil || !os.IsNotExist(err)) && !conf.forceOverwrite {
		return fmt.Errorf("File %v exists, please specify --force if you want to overwrite it", conf.output)
	}

	img, err := NewImage(conf.output, conf.compression, conf.stripBinaries)
	if err != nil {
		return err
	}
	defer img.Cleanup()

	if err := appendCompatibilitySymlinks(img); err != nil {
		return err
	}

	if err := img.appendInitBinary(conf.initBinary); err != nil {
		return err
	}

	if err := img.appendExtraFiles(conf.extraFiles...); err != nil {
		return err
	}

	kmod, err := NewKmod(conf)
	if err != nil {
		return err
	}

	// some kernels might be compiled without some of the modules (e.g. virtio) from the predefined list
	// generator should not fail if a module is not detected
	if err := kmod.activateModules(true, false, defaultModulesList...); err != nil {
		return err
	}
	if err := kmod.activateModules(false, true, conf.modules...); err != nil {
		return err
	}
	if err := kmod.activateModules(false, true, conf.modulesForceLoad...); err != nil {
		return err
	}

	// cbc module is a hard requirement for "encrypted_keys"
	// https://github.com/torvalds/linux/blob/master/security/keys/encrypted-keys/encrypted.c#L42
	kmod.addExtraDep("encrypted_keys", "cbc")

	if conf.networkConfigType != netOff {
		if err := kmod.activateModules(true, false, "kernel/drivers/net/ethernet/"); err != nil {
			return err
		}
	}

	if conf.enableLVM {
		if err := kmod.activateModules(false, false, "dm_mod", "dm_snapshot", "dm_mirror", "dm_cache", "dm_cache_smq", "dm_thin_pool"); err != nil {
			return err
		}

		conf.modulesForceLoad = append(conf.modulesForceLoad, "dm_mod")
		if err := img.appendExtraFiles("lvm"); err != nil {
			return err
		}
	}

	if conf.enableMdraid {
		if err := kmod.activateModules(true, true, "kernel/drivers/md/"); err != nil {
			return err
		}

		// preload md_mod for speed. Level-specific drivers (e.g. raid1, raid456) are going to be detected loaded at boot-time
		conf.modulesForceLoad = append(conf.modulesForceLoad, "md_mod")

		if err := img.appendExtraFiles("mdadm"); err != nil {
			return err
		}

		mdadmConf := conf.mdraidConfigPath
		if mdadmConf == "" {
			mdadmConf = "/etc/mdadm.conf"
		}
		content, err := os.ReadFile(mdadmConf)
		if err != nil {
			return err
		}
		if err := img.AppendContent("/etc/mdadm.conf", 0o644, content); err != nil {
			return err
		}
	}

	if conf.enablePlymouth {
		// Include base DRM modules for Plymouth's graphical splash.
		// These may be built-in (e.g. CONFIG_DRM_SIMPLEDRM=y on CachyOS)
		// so we only force-load the ones that exist as loadable modules.
		//
		// Booster does not run udevd, so Plymouth cannot detect new DRM
		// devices after startup via its libudev monitor. The GPU driver
		// must be force-loaded so it is available before Plymouth starts.
		drmModules := []string{"simpledrm", "drm", "drm_kms_helper"}
		if err := kmod.activateModules(true, false, drmModules...); err != nil {
			return err
		}
		for _, m := range drmModules {
			if kmod.requiredModules[m] {
				conf.modulesForceLoad = append(conf.modulesForceLoad, m)
			}
		}

		// In host mode, check whether a real GPU driver is present but not
		// force-loaded. Booster does not run udevd, so Plymouth cannot
		// transition from simpledrm to the real GPU after switch_root.
		// If Plymouth starts on simpledrm and the real GPU driver later tears
		// it down, plymouth-quit-wait.service (TimeoutSec=0) hangs forever.
		// Disable Plymouth now rather than produce an unbootable system.
		if !conf.universal {
			if gpuModules := detectHostGPUModules(); len(gpuModules) > 0 {
				forceLoad := make(map[string]bool, len(conf.modulesForceLoad))
				for _, m := range conf.modulesForceLoad {
					forceLoad[m] = true
				}
				var missing []string
				for _, m := range gpuModules {
					if !forceLoad[m] {
						missing = append(missing, m)
					}
				}
				if len(missing) > 0 {
					warning("plymouth: GPU driver(s) %v detected but not in modules_force_load — disabling Plymouth to prevent boot hang. Add to modules_force_load in booster.yaml to enable Plymouth.", missing)
					conf.enablePlymouth = false
				}
			}
		}
	}

	if conf.enableZfs {
		if err := kmod.activateModules(false, true, "zfs"); err != nil {
			return err
		}
		conf.modulesForceLoad = append(conf.modulesForceLoad, "zfs")

		if err := img.appendExtraFiles("zpool", "zfs"); err != nil {
			return err
		}

		zfsCachePath := conf.zfsCachePath
		if zfsCachePath == "" {
			zfsCachePath = "/etc/zfs/zpool.cache"
		}
		content, err := os.ReadFile(zfsCachePath)
		if err != nil {
			return err
		}
		if err := img.AppendContent("/etc/zfs/zpool.cache", 0o644, content); err != nil {
			return err
		}

		if err := img.AppendFile("/etc/default/zfs"); err != nil {
			if os.IsNotExist(err) {
				debug("Adding /etc/default/zfs to the image: %v", err)
			} else {
				return err
			}
		}
	}

	if err := kmod.resolveDependencies(); err != nil {
		return err
	}
	if err := kmod.addModulesToImage(img); err != nil {
		return err
	}

	var aliases []alias
	if conf.appendAllModAliases {
		aliases = kmod.aliases
	} else {
		// collect aliases for required modules only
		aliases, err = kmod.filterAliasesForRequiredModules(conf)
		if err != nil {
			return err
		}
	}
	if err := img.appendAliasesFile(aliases); err != nil {
		return err
	}

	kmod.filterModprobeForRequiredModules()

	var vconsole *VirtualConsole
	if conf.enableVirtualConsole {
		vconsole, err = img.enableVirtualConsole(conf.vconsolePath, conf.localePath)
		if err != nil {
			return err
		}
	}

	if err := img.appendInitConfig(conf, kmod, vconsole); err != nil {
		return err
	}

	if conf.enablePlymouth {
		if err := img.addPlymouthSupport(conf); err != nil {
			return err
		}
	}

	// appending initrd-release file per recommendation from https://systemd.io/INITRD_INTERFACE/
	if err := img.AppendContent("/etc/initrd-release", 0o644, []byte{}); err != nil {
		return err
	}

	return img.Close()
}

// appendCompatibilitySymlinks appends symlinks for compatibility with older firmware that loads extra files from non-standard locations
func appendCompatibilitySymlinks(img *Image) error {
	symlinks := []struct{ src, target string }{
		{"/lib", "usr/lib"},
		{"/usr/local/lib", "../lib"},
		{"/usr/sbin", "bin"},
		{"/bin", "usr/bin"},
		{"/sbin", "usr/bin"},
		{"/usr/local/bin", "../bin"},
		{"/usr/local/sbin", "../bin"},
		{"/var/run", "../run"},
		{"/usr/lib64", "lib"},
		{"/lib64", "usr/lib"},
	}

	for _, l := range symlinks {
		// Ensure that target always exist which may not be the
		// case if we only install files from /lib or /bin.
		targetDir := filepath.Join(filepath.Dir(l.src), l.target)
		if err := img.AppendDirEntry(targetDir); err != nil {
			return err
		}

		mode := cpio.FileMode(0o777) | cpio.TypeSymlink
		if err := img.AppendEntry(l.src, mode, []byte(l.target)); err != nil {
			return err
		}
	}
	return nil
}

func (img *Image) appendInitBinary(initBinary string) error {
	content, err := os.ReadFile(initBinary)
	if err != nil {
		return fmt.Errorf("%s: %v", initBinary, err)
	}
	return img.AppendContent("/init", 0o755, content)
}

func (img *Image) appendExtraFiles(binaries ...string) error {
	for _, f := range binaries {
		if !filepath.IsAbs(f) {
			// If the given name is not an absolute path, assume that it refers
			// to an executable and lookup the path to the executable using $PATH.
			var err error
			f, err = lookupPath(f)
			if err != nil {
				return err
			}
		}

		if err := img.AppendFile(f); err != nil {
			return err
		}
	}
	return nil
}

func (img *Image) addPlymouthSupport(conf *generatorConfig) error {
	debug("adding plymouth support to the image")

	// Detect Plymouth paths via pkg-config, falling back to common defaults
	pluginDir := plymouthPkgConfig("pluginsdir")
	if pluginDir == "" {
		// pkg-config unavailable; try common distro locations in order:
		// Arch/Alpine: /usr/lib/plymouth
		// Fedora/RHEL: /usr/lib64/plymouth
		// Debian/Ubuntu (multiarch): /usr/lib/<tuple>/plymouth
		for _, candidate := range []string{
			"/usr/lib/plymouth",
			"/usr/lib64/plymouth",
		} {
			if _, err := os.Stat(candidate); err == nil {
				pluginDir = candidate
				break
			}
		}
		if pluginDir == "" {
			// Try multiarch paths (Debian/Ubuntu)
			if entries, err := filepath.Glob("/usr/lib/*-linux-*/plymouth"); err == nil && len(entries) > 0 {
				pluginDir = entries[0]
			}
		}
	}
	themesDir := plymouthPkgConfig("themesdir")
	if themesDir == "" {
		themesDir = "/usr/share/plymouth/themes"
	}
	confDir := plymouthPkgConfig("confdir")
	if confDir == "" {
		confDir = "/etc/plymouth"
	}
	policyDir := plymouthPkgConfig("policydir")
	if policyDir == "" {
		policyDir = "/usr/share/plymouth"
	}
	debug("plymouth paths: plugins=%s themes=%s conf=%s policy=%s", pluginDir, themesDir, confDir, policyDir)

	// Add plymouth binaries (appendExtraFiles auto-resolves ELF deps)
	if err := img.appendExtraFiles("plymouth", "plymouthd"); err != nil {
		return fmt.Errorf("plymouth binaries: %v", err)
	}

	// Add plymouthd-fd-escrow helper
	fdEscrow := filepath.Join(pluginDir, "plymouthd-fd-escrow")
	if _, err := os.Stat(fdEscrow); err == nil {
		if err := img.AppendFile(fdEscrow); err != nil {
			return fmt.Errorf("plymouth fd-escrow: %v", err)
		}
	}

	// Add all .so plugins
	entries, err := os.ReadDir(pluginDir)
	if err != nil {
		return fmt.Errorf("reading plymouth plugin dir: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".so" {
			if err := img.AppendFile(filepath.Join(pluginDir, e.Name())); err != nil {
				return fmt.Errorf("plymouth plugin %s: %v", e.Name(), err)
			}
		}
	}

	// Add renderers
	rendererDir := filepath.Join(pluginDir, "renderers")
	if err := img.AppendFile(rendererDir); err != nil {
		return fmt.Errorf("plymouth renderers: %v", err)
	}

	// Add plymouth config files
	for _, f := range []string{
		filepath.Join(confDir, "plymouthd.conf"),
		filepath.Join(policyDir, "plymouthd.defaults"),
	} {
		if err := img.AppendFile(f); err != nil {
			if os.IsNotExist(err) {
				debug("plymouth config %s not found, skipping", f)
			} else {
				return fmt.Errorf("plymouth config %s: %v", f, err)
			}
		}
	}

	// Add /etc/os-release (needed by plymouth for branding)
	if err := img.AppendFile("/etc/os-release"); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("os-release: %v", err)
		}
	}

	// Detect and add default theme
	defaultTheme := detectPlymouthTheme()
	debug("plymouth default theme: %s", defaultTheme)

	// Add the default theme + fallback themes
	for _, theme := range []string{defaultTheme, "details", "text"} {
		themeDir := filepath.Join(themesDir, theme)
		if _, err := os.Stat(themeDir); err == nil {
			if err := img.AppendFile(themeDir); err != nil {
				return fmt.Errorf("plymouth theme %s: %v", theme, err)
			}
		} else {
			debug("plymouth theme %s not found, skipping", theme)
		}
	}

	// Bundle ImageDir target if the default theme references images from another directory
	themePlymouthFile := filepath.Join(themesDir, defaultTheme, defaultTheme+".plymouth")
	if imageDir := parseThemeImageDir(themePlymouthFile); imageDir != "" {
		themeOwnDir := filepath.Join(themesDir, defaultTheme)
		// Clean both paths so trailing slashes or double slashes don't cause false mismatches
		if filepath.Clean(imageDir) != filepath.Clean(themeOwnDir) {
			debug("plymouth theme %s references images from %s", defaultTheme, imageDir)
			if _, err := os.Stat(imageDir); err == nil {
				if err := img.AppendFile(imageDir); err != nil {
					return fmt.Errorf("plymouth theme image dir %s: %v", imageDir, err)
				}
			} else {
				debug("plymouth ImageDir %s not found, skipping", imageDir)
			}
		}
	}

	// Add default.plymouth symlink — copy from host or synthesize one
	defaultPlymouth := filepath.Join(themesDir, "default.plymouth")
	if _, err := os.Lstat(defaultPlymouth); err == nil {
		if err := img.AppendFile(defaultPlymouth); err != nil {
			return fmt.Errorf("default.plymouth: %v", err)
		}
	} else if os.IsNotExist(err) {
		// No default.plymouth symlink on host; create a synthetic one
		// pointing to the detected theme's .plymouth file.
		target := filepath.Join(defaultTheme, defaultTheme+".plymouth")
		debug("synthesizing default.plymouth -> %s", target)
		mode := cpio.FileMode(0o777) | cpio.TypeSymlink
		if err := img.AppendEntry(defaultPlymouth, mode, []byte(target)); err != nil {
			return fmt.Errorf("default.plymouth symlink: %v", err)
		}
	}

	// Resolve and install fonts to Plymouth's hardcoded lookup paths.
	// Plymouth's label-freetype plugin looks for fonts at fixed paths:
	//   /usr/share/fonts/Plymouth.ttf              (regular)
	//   /usr/share/fonts/Plymouth-bold.ttf         (bold)
	//   /usr/share/fonts/Plymouth-monospace.ttf    (monospace)
	//   /usr/share/fonts/Plymouth-monospace-bold.ttf (monospace bold)
	// Following mkinitcpio's approach, we use fc-match to resolve the
	// theme's font on the host and copy it to these fixed paths.
	fontFamily := "Sans" // Plymouth's own default
	themeFonts := parseThemeFonts(themePlymouthFile)
	if len(themeFonts) > 0 {
		fontFamily = themeFonts[0]
		debug("plymouth theme font family: %s", fontFamily)
	}

	plymouthFonts := []struct {
		pattern string
		dest    string
	}{
		{fontFamily, "/usr/share/fonts/Plymouth.ttf"},
		{fontFamily + ":style=Bold", "/usr/share/fonts/Plymouth-bold.ttf"},
		{"monospace", "/usr/share/fonts/Plymouth-monospace.ttf"},
		{"monospace:style=Bold", "/usr/share/fonts/Plymouth-monospace-bold.ttf"},
	}

	for _, pf := range plymouthFonts {
		fontPath := fcMatch(pf.pattern)
		if fontPath == "" {
			debug("plymouth: fc-match could not resolve %q, skipping %s", pf.pattern, pf.dest)
			continue
		}
		content, err := os.ReadFile(fontPath)
		if err != nil {
			debug("plymouth: failed to read font %s: %v", fontPath, err)
			continue
		}
		if err := img.AppendContent(pf.dest, 0o644, content); err != nil {
			debug("plymouth: failed to add font %s: %v", pf.dest, err)
		} else {
			debug("plymouth: %s -> %s (from %q)", fontPath, pf.dest, pf.pattern)
		}
	}

	// Add /etc/vconsole.conf for keyboard layout configuration.
	// Plymouth reads this file to get KEYMAP, XKBLAYOUT, XKBMODEL, etc.
	// Without it, Plymouth skips input device creation entirely.
	if err := img.AppendFile("/etc/vconsole.conf"); err != nil {
		if os.IsNotExist(err) {
			debug("plymouth: /etc/vconsole.conf not found, skipping")
		} else {
			return fmt.Errorf("vconsole.conf: %v", err)
		}
	}

	// Add XKB data files needed by libxkbcommon for keyboard input handling.
	// Without these, plymouthd cannot translate keycodes to characters and
	// the password prompt won't accept keyboard input.
	xkbDir := ""
	for _, candidate := range []string{"/usr/share/X11/xkb", "/usr/share/xkb"} {
		if _, err := os.Stat(candidate); err == nil {
			xkbDir = candidate
			break
		}
	}
	if xkbDir != "" {
		if err := img.AppendFile(xkbDir); err != nil {
			return fmt.Errorf("xkb data: %v", err)
		}
	} else {
		warning("plymouth: XKB data directory not found (/usr/share/X11/xkb or /usr/share/xkb) — keyboard input may not work")
	}

	return nil
}

func detectPlymouthTheme() string {
	out, err := exec.Command("plymouth-set-default-theme").Output()
	if err != nil {
		return "details" // safe fallback
	}
	theme := strings.TrimSpace(string(out))
	if theme == "" {
		return "details"
	}
	return theme
}

// plymouthPkgConfig queries pkg-config for a Plymouth variable.
// Returns empty string if pkg-config is unavailable or the variable is not set.
func plymouthPkgConfig(variable string) string {
	out, err := exec.Command("pkg-config", "--variable="+variable, "ply-splash-core").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// parseThemeImageDir reads a .plymouth theme file and extracts the ImageDir= value.
// Returns empty string if the file cannot be read or has no ImageDir directive.
func parseThemeImageDir(plymouthFile string) string {
	data, err := os.ReadFile(plymouthFile)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ImageDir=") {
			return strings.TrimPrefix(line, "ImageDir=")
		}
	}
	return ""
}

// fcMatch resolves a fontconfig pattern to a font file path using fc-match.
// Returns empty string if fc-match is unavailable or the pattern cannot be resolved.
func fcMatch(pattern string) string {
	out, err := exec.Command("fc-match", "-f", "%{file}", pattern).Output()
	if err != nil {
		return ""
	}
	path := strings.TrimSpace(string(out))
	if path == "" || !filepath.IsAbs(path) {
		return ""
	}
	return path
}

// parseThemeFonts reads a .plymouth theme file and extracts font family names
// from Font= and TitleFont= directives (Pango font descriptions).
func parseThemeFonts(plymouthFile string) []string {
	data, err := os.ReadFile(plymouthFile)
	if err != nil {
		debug("plymouth: failed to read theme file %s: %v", plymouthFile, err)
		return nil
	}
	seen := make(set)
	var families []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		var val string
		if strings.HasPrefix(line, "Font=") {
			val = strings.TrimPrefix(line, "Font=")
		} else if strings.HasPrefix(line, "TitleFont=") {
			val = strings.TrimPrefix(line, "TitleFont=")
		} else {
			continue
		}
		family := extractFontFamily(val)
		if family != "" && !seen[family] {
			seen[family] = true
			families = append(families, family)
		}
	}
	return families
}

// extractFontFamily extracts the font family name from a Pango font
// description like "Inter Bold 16" or "Sans 12". It strips trailing
// numeric size and style keywords.
func extractFontFamily(pangoDesc string) string {
	pangoDesc = strings.TrimSpace(pangoDesc)
	if pangoDesc == "" {
		return ""
	}

	styleWords := set{
		"Bold": true, "Italic": true, "Light": true, "Medium": true,
		"Thin": true, "Black": true, "ExtraBold": true, "SemiBold": true,
		"ExtraLight": true, "Regular": true, "Condensed": true, "Heavy": true,
		"Oblique": true, "Ultra-Bold": true, "Semi-Bold": true,
	}

	parts := strings.Fields(pangoDesc)
	// Strip trailing size (numeric)
	for len(parts) > 1 {
		if _, err := fmt.Sscanf(parts[len(parts)-1], "%f", new(float64)); err == nil {
			parts = parts[:len(parts)-1]
		} else {
			break
		}
	}
	// Strip trailing style keywords
	for len(parts) > 1 {
		if styleWords[parts[len(parts)-1]] {
			parts = parts[:len(parts)-1]
		} else {
			break
		}
	}
	return strings.Join(parts, " ")
}

func lookupPath(binary string) (string, error) {
	paths := []string{
		"/usr/bin",
		"/usr/sbin",
		"/bin",
		"/sbin",
		"/usr/local/bin",
		"/usr/local/sbin",
	}

	for _, p := range paths {
		f := filepath.Join(p, binary)
		_, err := os.Stat(f)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		return f, nil
	}

	return "", os.ErrNotExist
}

func findFwFile(fw string) (string, error) {
	supportedFwExt := []string{
		"",
		".xz",  // since linux v5.3
		".zst", // since linux v5.19
	}

	fwBasePath := firmwareDir + fw
	for _, ext := range supportedFwExt {
		fwPath := fwBasePath + ext
		if _, err := os.Stat(fwPath); err == nil {
			return fwPath, nil
		} else if os.IsNotExist(err) {
			continue // try the next extension
		} else {
			return "", err
		}
	}

	return "", os.ErrNotExist
}

func (img *Image) appendFirmwareFiles(modName string, fws []string) error {
	for _, fw := range fws {
		path, err := findFwFile(fw)

		if os.IsNotExist(err) {
			debug("module %s depends on firmware %s but the firmware file does not exist", modName, fw)
			continue
		} else if err != nil {
			return err
		}

		if err := img.AppendFile(path); err != nil {
			return err
		}
	}
	return nil
}

func (img *Image) appendInitConfig(conf *generatorConfig, kmod *Kmod, vconsole *VirtualConsole) error {
	var initConfig InitConfig // config for init stored to /etc/booster.init.yaml

	initConfig.MountTimeout = int(conf.timeout.Seconds())
	initConfig.Kernel = conf.kernelVersion
	initConfig.ModuleDependencies = kmod.dependencies
	initConfig.ModulePostDependencies = kmod.postDependencies
	initConfig.ModulesForceLoad = kmod.selectNonBuiltinModules(conf.modulesForceLoad)
	initConfig.ModprobeOptions = kmod.modprobeOptions
	initConfig.BuiltinModules = kmod.builtinModules
	initConfig.VirtualConsole = vconsole
	initConfig.EnableLVM = conf.enableLVM
	initConfig.EnableMdraid = conf.enableMdraid
	initConfig.EnableZfs = conf.enableZfs
	initConfig.ZfsImportParams = conf.zfsImportParams
	initConfig.EnablePlymouth = conf.enablePlymouth

	if conf.networkConfigType == netDhcp {
		initConfig.Network = &InitNetworkConfig{}
		initConfig.Network.Dhcp = true
	} else if conf.networkConfigType == netStatic {
		initConfig.Network = &InitNetworkConfig{}
		initConfig.Network.IP = conf.networkStaticConfig.ip
		initConfig.Network.Gateway = conf.networkStaticConfig.gateway
		initConfig.Network.DNSServers = conf.networkStaticConfig.dnsServers
	}
	if conf.networkActiveInterfaces != nil {
		initConfig.Network.Interfaces = conf.networkActiveInterfaces
	}

	content, err := yaml.Marshal(initConfig)
	if err != nil {
		return err
	}

	return img.AppendContent(initConfigPath, 0o644, content)
}

// detectHostGPUModules returns the names of loadable (non-built-in) GPU kernel
// modules backing real DRM devices on this host, excluding simpledrm.
// Returns nil on a simpledrm-only or GPU-less system.
func detectHostGPUModules() []string {
	var modules []string
	cards, _ := filepath.Glob("/sys/class/drm/card[0-9]*")
	for _, card := range cards {
		// Skip connector entries (e.g. card1-DP-1, card1-eDP-1)
		if strings.Contains(filepath.Base(card), "-") {
			continue
		}
		driverLink, err := os.Readlink(filepath.Join(card, "device", "driver"))
		if err != nil {
			continue
		}
		// simpledrm registers as platform driver "simple-framebuffer"
		if filepath.Base(driverLink) == "simple-framebuffer" {
			continue
		}
		// driver/module symlink is absent for built-in drivers; skip those
		moduleLink, err := os.Readlink(filepath.Join(card, "device", "driver", "module"))
		if err != nil {
			continue
		}
		modules = append(modules, filepath.Base(moduleLink))
	}
	return modules
}

func (img *Image) appendAliasesFile(aliases []alias) error {
	var buff bytes.Buffer
	for _, a := range aliases {
		buff.WriteString(a.pattern)
		buff.WriteString(" ")
		buff.WriteString(a.module)
		buff.WriteString("\n")
	}
	return img.AppendContent(imageModulesDir+"booster.alias", 0o644, buff.Bytes())
}
