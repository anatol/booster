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

	if cmdRoot == nil && !config.EnableZfs { // zfs specifies root dataset with 'zfs=' param.
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

// obtain the next key / value param from a params string starting at a given index
// will return the key and value and the next offset to send for the next call
// note that quotes will be removed after this step and new strings are returned
// can handle "param=true", param="true", param=true, param="tr ue", "param=tr ue"
// "param=tr\"ue", "param=tr\nue", param=test=true, param="test=true"
// param1=true\nparam2=false
func getNextParam(params string, index int) (string, string, int) {
	keyComplete := false // indicates if we are reading the key or value
	inQuote := false     // indicates if we are within quotes
	escaping := false    // indicates if we read an escape character "\"
	copyMode := false    // indicates if we are copying runes yet (leading whitespace trim)
	var key, value strings.Builder

	// copy a given rune into the key or value, update copy mode if not set
	copyRune := func(r rune) {
		copyMode = true
		if !keyComplete {
			key.WriteRune(r)
		} else {
			value.WriteRune(r)
		}
	}

	// walk through each rune
	for i, r := range params[index:] {
		// if we are in escape mode just copy the next rune and move on
		if copyMode && escaping {
			copyRune(r)
			escaping = false
			continue
		}

		switch r {
		case '\\':
			// now in copy mode if we were not already
			copyMode = true
			// escaping something, update flag and move on
			escaping = true
		case 0, '\n', '\r', '\t', ' ':
			// if we haven't seen any non-whitespace yet just continue
			if !copyMode {
				continue
			}

			// whitespace/null is end of a parse sequence if not in quotes
			if !inQuote {
				// return what we collected and give them the next rune to pass back
				return key.String(), value.String(), index + i + 1
			}

			// if we are in quotes we just copy it through
			copyRune(r)
		case '"':
			// now in copy mode if we were not already
			copyMode = true

			// if we are in quote mode this ends it
			if inQuote {
				inQuote = false

				// if we have parsed a key already this ends our parse too, otherwise continue as normal
				if keyComplete {
					return key.String(), value.String(), index + i + 1
				}

				continue
			}

			// if we are parsing a key, and it isn't empty, then something has gone wrong
			// same for value
			if (!keyComplete && key.Len() > 0) || (keyComplete && value.Len() > 0) {
				// error, this quote is inside real characters
				// we are going to recover as best we can, just copy the quote and hope for the best
				warning("while parsing cmdline parameter unexpected \" found at %d, input may be malformed, attempting to proceed", index+i)
				copyRune(r)
				continue
			}

			inQuote = true
		case '=':
			// this separates key=value, but only while in key mode
			if !keyComplete {
				// done reading key, do nothing with the rune
				keyComplete = true
			} else {
				// outside key mode just copy it through (value can have = in it)
				copyRune(r)
			}
		default:
			// anything else just copy and move on
			copyRune(r)
		}
	}

	// if we hit here return whatever we collected
	return key.String(), value.String(), len(params)
}

func parseParams(params string) error {
	var luksOptions []string

	var key, value string
	i := 0

	for i < len(params) {
		// read the next param to examine and update for next round
		key, value, i = getNextParam(params, i)

		switch key {
		case "":
			// probably trailing whitespace, just ignore it
			warning("attempting to parse a parameter returned a blank key, cmdline may be malformed somewhere around %d", i)
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
			uuid, err := parseUUID(parts[0])
			if err != nil {
				return fmt.Errorf("invalid UUID %s %v", parts[0], err)
			}

			dev := luksMapping{
				ref:  &deviceRef{refFsUUID, uuid},
				name: parts[1],
			}
			luksMappings = append(luksMappings, dev)
		case "rd.luks.uuid":
			u, err := parseUUID(value)
			if err != nil {
				return fmt.Errorf("invalid UUID %s in rd.luks.uuid boot param: %v", value, err)
			}

			dev := luksMapping{
				ref:  &deviceRef{refFsUUID, u},
				name: "luks-" + value,
			}
			luksMappings = append(luksMappings, dev)
		case "zfs":
			zfsDataset = value
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
