package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

func parseCmdline() error {
	b, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return err
	}
	if err := parseParams(strings.TrimSpace(string(b))); err != nil {
		return err
	}

	if cmdRoot == nil {
		// try to auto-discover gpt partition https://www.freedesktop.org/wiki/Specifications/DiscoverablePartitionsSpec/
		rootUUIDType, ok := rootAutodiscoveryGptTypes[runtime.GOARCH]
		if !ok {
			return fmt.Errorf("root= boot option is not specified")
		}
		info("root= param is not specified. Use GPT partition autodiscovery with guid type %s", rootUUIDType)
		gptType, err := parseUUID(rootUUIDType)
		if err != nil {
			return err
		}

		activeEfiEspGUID, err = getActiveEfiEsp()
		if err != nil {
			return fmt.Errorf("unable to detect active ESP: %v", err)
		}

		rootAutodiscoveryMode = true
		cmdRoot = &deviceRef{refGptType, gptType}
	}

	if verbosityLevel >= levelDebug {
		// booster debug generates a lot of kmsg logs, to be able to preserve all these logs we disable kmsg throttling
		if err := disableKmsgThrottling(); err != nil {
			// user might set 'printk.devkmsg' param and it disables changing the throttling level
			// in this case ignore the error
			info("%v", err)
		}
	}

	return nil
}

func parseParams(params string) error {
	var luksOptions []string

	for _, part := range strings.Split(params, " ") {
		var key, value string
		// separate key/value based on the first = character;
		// there may be multiple (e.g. in rd.luks.name)
		if idx := strings.IndexByte(part, '='); idx > -1 {
			key, value = part[:idx], part[idx+1:]
		} else {
			key = part
		}

		switch key {
		case "booster.log":
			for _, p := range strings.Split(value, ",") {
				switch p {
				case "debug":
					verbosityLevel = levelDebug
				case "info":
					verbosityLevel = levelInfo
				case "warning":
					verbosityLevel = levelWarning
				case "error":
					verbosityLevel = levelError
				case "console":
					printToConsole = true
				default:
					warning("unknown booster.log key: %s", p)
				}
			}
		case "booster.debug":
			// booster.debug is an obsolete parameter
			verbosityLevel = levelDebug
			printToConsole = true
		case "quiet":
			verbosityLevel = levelError
		case "root":
			var err error
			cmdRoot, err = parseDeviceRef(value)
			if err != nil {
				return fmt.Errorf("root=%s: %v", value, err)
			}

		case "resume":
			var err error
			cmdResume, err = parseDeviceRef(value)
			if err != nil {
				return fmt.Errorf("resume=%s: %v", value, err)
			}
		case "init":
			initBinary = value
		case "rootfstype":
			rootFsType = value
		case "rootflags":
			rootFlags = value
		case "ro":
			rootRo = true
		case "rw":
			rootRw = true
		case "rd.luks.options":
			for _, o := range strings.Split(value, ",") {
				flag, ok := rdLuksOptions[o]
				if !ok {
					return fmt.Errorf("unknown value in rd.luks.options: %v", o)
				}
				luksOptions = append(luksOptions, flag)
			}
		case "rd.luks.name":
			parts := strings.Split(value, "=")
			if len(parts) != 2 {
				return fmt.Errorf("invalid rd.luks.name kernel parameter %s, expected format rd.luks.name=<UUID>=<name>", value)
			}
			uuid, err := parseUUID(stripQuotes(parts[0]))
			if err != nil {
				return fmt.Errorf("invalid UUID %s %v", parts[0], err)
			}

			dev := luksMapping{
				ref:  &deviceRef{refFsUUID, uuid},
				name: parts[1],
			}
			luksMappings = append(luksMappings, dev)
		case "rd.luks.uuid":
			stripped := stripQuotes(value)
			u, err := parseUUID(stripped)
			if err != nil {
				return fmt.Errorf("invalid UUID %s in rd.luks.uuid boot param: %v", value, err)
			}

			dev := luksMapping{
				ref:  &deviceRef{refFsUUID, u},
				name: "luks-" + stripped,
			}
			luksMappings = append(luksMappings, dev)
		default:
			if dot := strings.IndexByte(key, '.'); value != "" && dot != -1 {
				// this param looks like a module options
				mod, param := key[:dot], key[dot+1:]
				mod = normalizeModuleName(mod)
				moduleParams[mod] = append(moduleParams[mod], param+"="+value)
			}
		}
	}

	if luksOptions != nil {
		for i := range luksMappings {
			luksMappings[i].options = luksOptions
		}
	}

	return nil
}
