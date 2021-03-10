package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
)

var (
	outputFile         = flag.String("output", "booster.img", "Output initrd file")
	forceOverwriteFile = flag.Bool("force", false, "Overwrite existing initrd file")
	initBinary         = flag.String("initBinary", "/usr/lib/booster/init", "Booster 'init' binary location")
	compression        = flag.String("compression", "", `Output file compression ("zstd", "gzip", "none")`)
	kernelVersion      = flag.String("kernelVersion", "", "Linux kernel version to generate initramfs for")
	configFile         = flag.String("config", "/etc/booster.yaml", "Configuration file path")
	debugEnabled       = flag.Bool("debug", false, "Enable debug output")
	universal          = flag.Bool("universal", false, "Add wide range of modules/tools to allow this image boot at different machines")
	strip              = flag.Bool("strip", false, "Strip ELF binaries before adding it to the image")
	pprofcpu           = flag.String("pprof.cpu", "", "Write cpu profile to file")
	pprofmem           = flag.String("pprof.mem", "", "Write memory profile to file")
)

func debug(format string, v ...interface{}) {
	if *debugEnabled {
		fmt.Printf(format+"\n", v...)
	}
}

func warning(format string, v ...interface{}) {
	fmt.Printf(format+"\n", v...)
}

func saveProfile(profile, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	runtime.GC()
	if err := pprof.Lookup(profile).WriteTo(f, 0); err != nil {
		return err
	}
	_ = f.Close()

	return nil
}

func runGenerator() error {
	if *pprofcpu != "" {
		f, err := os.Create(*pprofcpu)
		if err != nil {
			return err
		}
		defer f.Close()

		if err := pprof.StartCPUProfile(f); err != nil {
			return err
		}
		defer pprof.StopCPUProfile()
	}

	conf, err := readGeneratorConfig(*configFile)
	if err != nil {
		return err
	}

	err = generateInitRamfs(conf)
	if *pprofmem != "" {
		if err := saveProfile("allocs", *pprofmem); err != nil {
			fmt.Println(err)
		}
	}
	return err
}

func main() {
	flag.Parse()

	if err := runGenerator(); err != nil {
		log.Fatal(err)
	}
}
