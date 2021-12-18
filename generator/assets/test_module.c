#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/string.h>
#include <linux/firmware.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anatol Pomozov");
MODULE_DESCRIPTION("A test module for booster.");
MODULE_VERSION("0.01");

MODULE_FIRMWARE("whiteheat.fw");
MODULE_FIRMWARE("usbdux_firmware.bin");
MODULE_FIRMWARE("rtw88/rtw8723d_fw.bin");

static void sample_firmware_load(const char *firmware, int size) {
  u8 *buf = kmalloc(size, GFP_KERNEL);
  memcpy(buf, firmware, size);
  buf[size] = '\0';
  printk(KERN_INFO "firmware_example: firmware address is %p\n", buf);
  kfree(buf);
}

static void sample_probe(struct device *dev) {
  /* uses the default method to get the firmware */
  const struct firmware *fw_entry;
  printk(KERN_INFO "firmware_example: ghost device inserted\n");

  if (request_firmware(&fw_entry, "usbdux_firmware.bin", dev) != 0) {
    printk(KERN_ERR "firmware_example: Firmware usbdux_firmware.bin not available\n");
    return;
  }

  sample_firmware_load(fw_entry->data, fw_entry->size);

  release_firmware(fw_entry);
  /* finish setting up the device */
}

static void ghost_release(struct device *dev) {
  printk(KERN_DEBUG "firmware_example : ghost device released\n");
}

static struct device ghost_device = {
  .init_name = "ghost0",
  .release = ghost_release
};

static int __init booster_init(void) {
  int rc;

  printk(KERN_INFO "Hello from test kernel module!\n");
  rc = device_register(&ghost_device);
  if (rc) {
    put_device(&ghost_device);
    return rc;
  }
  sample_probe(&ghost_device);
  return 0;
}

static void __exit booster_exit(void) {
  device_unregister(&ghost_device);
  printk(KERN_INFO "Goodbye test kernel module!\n");
}

module_init(booster_init);
module_exit(booster_exit);
