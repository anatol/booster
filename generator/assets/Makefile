obj-m += test_module.o

KVER   ?= $(shell uname -r)
KBUILD := /lib/modules/$(KVER)/build

# Match the compiler used to build the kernel — avoids flag incompatibilities
# on clang-built kernels (e.g. CachyOS, Arch linux-zen with LLVM).
ifneq (,$(wildcard $(KBUILD)/.config))
  ifeq ($(shell grep -c 'CONFIG_CC_IS_CLANG=y' $(KBUILD)/.config),1)
    KBUILD_CC := LLVM=1
  endif
endif

all:
	make $(KBUILD_CC) -C $(KBUILD) M=$(CURDIR) modules

clean:
	make $(KBUILD_CC) -C $(KBUILD) M=$(CURDIR) clean
