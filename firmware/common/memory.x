MEMORY
{
  /* App flash ends at 0xEC000. Two 4 KB pages above it are reserved and sit
     OUTSIDE this region, so the flasher never rewrites them and their contents
     survive a reflash:
       [0xEC000, 0xED000)  boot-mode store  (BOOT_MODE_PAGE in main.rs)
       [0xED000, 0xEE000)  crash records    (PANIC_PAGE in panic.rs)
     Keep BOOT_MODE_PAGE == this region's end. */
  FLASH (rx) : ORIGIN = 0x00027000, LENGTH = 0xEC000 - 0x27000
  RAM (rwx)  : ORIGIN = 0x20006000, LENGTH = 0x20040000 - 0x20006000
}

/* Boot mode is persisted in flash (BOOT_MODE_PAGE), not RAM: the XIAO's UF2
   bootloader runs on every reset with its stack at the top of RAM and clobbers
   any retained cell placed there, so RAM/GPREGRET schemes never survived. */
