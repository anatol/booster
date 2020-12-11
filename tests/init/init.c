#include <stdio.h>
#include <unistd.h>
#include <sys/reboot.h>
#include <linux/reboot.h>

int main() {
   printf("Hello, booster!\n");
   reboot(LINUX_REBOOT_CMD_POWER_OFF);
   for (;;) pause();
   return 0;
}
