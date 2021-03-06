#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anatol Pomozov");
MODULE_DESCRIPTION("A test module for booster.");
MODULE_VERSION("0.01");

MODULE_FIRMWARE("whiteheat.fw");
MODULE_FIRMWARE("usbdux_firmware.bin");
MODULE_FIRMWARE("rtw88/rtw8723d_fw.bin");

static int __init booster_init(void) {
  printk(KERN_INFO "Hello, Booster!\n");
  return 0;
}

static void __exit booster_exit(void) {
  printk(KERN_INFO "Goodbye, Booster!\n");
}

module_init(booster_init);
module_exit(booster_exit);
