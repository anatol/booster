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
	parts := strings.Split(params, " ")
	cmdline := make(map[string]string)
	for _, part := range parts {
		// separate key/value based on the first = character;
		// there may be multiple (e.g. in rd.luks.name)
		if idx := strings.IndexByte(part, '='); idx > -1 {
			key, val := part[:idx], part[idx+1:]
			cmdline[key] = val

			if dot := strings.IndexByte(key, '.'); dot != -1 {
				// this param looks like a module options
				mod, param := key[:dot], key[dot+1:]
				mod = normalizeModuleName(mod)
				moduleParams[mod] = append(moduleParams[mod], param+"="+val)
			}
		} else {
			cmdline[part] = ""
		}
	}

	if param, ok := cmdline["booster.log"]; ok {
		for _, p := range strings.Split(param, ",") {
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
	} else if _, ok := cmdline["booster.debug"]; ok {
		// booster.debug is an obsolete parameter
		verbosityLevel = levelDebug
		printToConsole = true
	} else if _, ok := cmdline["quiet"]; ok {
		verbosityLevel = levelError
	}

	if param, ok := cmdline["root"]; ok {
		var err error
		cmdRoot, err = parseDeviceRef(param)
		if err != nil {
			return fmt.Errorf("root=%s: %v", param, err)
		}
	}

	if param, ok := cmdline["resume"]; ok {
		var err error
		cmdResume, err = parseDeviceRef(param)
		if err != nil {
			return fmt.Errorf("resume=%s: %v", param, err)
		}
	}

	if param, ok := cmdline["init"]; ok {
		initBinary = param
	}

	rootFsType = cmdline["rootfstype"]
	rootFlags = cmdline["rootflags"]
	_, rootRo = cmdline["ro"]
	_, rootRw = cmdline["rw"]

	// parse LUKS-specific kernel parameters
	var luksOptions []string
	if param, ok := cmdline["rd.luks.options"]; ok {
		for _, o := range strings.Split(param, ",") {
			flag, ok := rdLuksOptions[o]
			if !ok {
				return fmt.Errorf("unknown value in rd.luks.options: %v", o)
			}
			luksOptions = append(luksOptions, flag)
		}
	}

	if param, ok := cmdline["rd.luks.name"]; ok {
		parts := strings.Split(param, "=")
		if len(parts) != 2 {
			return fmt.Errorf("invalid rd.luks.name kernel parameter %s, expected format rd.luks.name=<UUID>=<name>", cmdline["rd.luks.name"])
		}
		uuid, err := parseUUID(stripQuotes(parts[0]))
		if err != nil {
			return fmt.Errorf("invalid UUID %s %v", parts[0], err)
		}

		dev := luksMapping{
			ref:     &deviceRef{refFsUUID, uuid},
			name:    parts[1],
			options: luksOptions,
		}
		luksMappings = append(luksMappings, dev)
	} else if uuid, ok := cmdline["rd.luks.uuid"]; ok {
		stripped := stripQuotes(uuid)
		u, err := parseUUID(stripped)
		if err != nil {
			return fmt.Errorf("invalid UUID %s in rd.luks.uuid boot param: %v", uuid, err)
		}

		dev := luksMapping{
			ref:     &deviceRef{refFsUUID, u},
			name:    "luks-" + stripped,
			options: luksOptions,
		}
		luksMappings = append(luksMappings, dev)
	}

	return nil
}
