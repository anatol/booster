package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/jessevdk/go-flags"
)

var opts struct {
	Verbose  bool   `short:"v" long:"verbose" description:"Enable verbose output"`
	Pprofcpu string `long:"pprof.cpu" description:"Write cpu profile to file" hidden:"true"`
	Pprofmem string `long:"pprof.mem" description:"Write memory profile to file" hidden:"true"`

	BuildCommand struct {
		Force            bool   `short:"f" long:"force" description:"Overwrite existing initrd file"`
		InitBinary       string `long:"init-binary" default:"/usr/lib/booster/init" description:"Booster 'init' binary location"`
		Compression      string `long:"compression" choice:"zstd" choice:"gzip" choice:"xz" choice:"lz4" choice:"none" description:"Output file compression"`
		KernelVersion    string `long:"kernel-version" description:"Linux kernel version to generate initramfs for"`
		ModulesDirectory string `long:"modules-dir" description:"Directory with kernel modules, if not set then /lib/modules/$kernel-version is used"`
		ConfigFile       string `long:"config" default:"/etc/booster.yaml" description:"Configuration file path"`
		Universal        bool   `long:"universal" description:"Add wide range of modules/tools to allow this image boot at different machines"`
		Strip            bool   `long:"strip" description:"Strip ELF files (binaries, shared libraries and kernel modules) before adding it to the image"`
		Args             struct {
			Output string `positional-arg-name:"output" required:"true"`
		} `positional-args:"true"`
	} `command:"build" description:"Build initrd image"`

	LsCommand struct {
		Args struct {
			Image string `positional-arg-name:"image" required:"true"`
		} `positional-args:"true"`
	} `command:"ls" description:"List content of the image"`

	CatCommand struct {
		Args struct {
			Image string `positional-arg-name:"image" required:"true"`
			File  string `positional-arg-name:"file-in-image" required:"true"`
		} `positional-args:"true"`
	} `command:"cat" description:"Show content of the file inside the image"`

	UnpackCommand struct {
		Args struct {
			Image     string `positional-arg-name:"image" required:"true"`
			OutputDir string `positional-arg-name:"output-dir" required:"true"`
		} `positional-args:"true"`
	} `command:"unpack" description:"Unpack image"`
}

type set map[string]bool

func debug(format string, v ...interface{}) {
	if opts.Verbose {
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
	if opts.Pprofcpu != "" {
		f, err := os.Create(opts.Pprofcpu)
		if err != nil {
			return err
		}
		defer f.Close()

		if err := pprof.StartCPUProfile(f); err != nil {
			return err
		}
		defer pprof.StopCPUProfile()
	}

	increaseOpenFileLimit()

	conf, err := readGeneratorConfig(opts.BuildCommand.ConfigFile)
	if err != nil {
		return err
	}

	err = generateInitRamfs(conf)
	if opts.Pprofmem != "" {
		if err := saveProfile("allocs", opts.Pprofmem); err != nil {
			fmt.Println(err)
		}
	}
	return err
}

func main() {
	parser := flags.NewParser(&opts, flags.Default)
	_, err := parser.Parse()
	if err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}

	switch parser.Active.Name {
	case "build":
		err = runGenerator()
	case "cat":
		err = runCat()
	case "ls":
		err = runLs()
	case "unpack":
		err = runUnpack()
	}

	if err != nil {
		log.Fatal(err)
	}
}
