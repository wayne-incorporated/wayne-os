## In Windows
You can run Command Prompt as administrator.

![initialize_usb-1](resources/initialize_usb1.png)

Notes: 
FAT32/exFAT file systems are recommended for USB flash drives.
<br>
The FAT32 supports max 32GiB volume size and max 4GiB file size.
<br>
The exFAT supports over 32GiB volume size but it doesn’t work on Windows XP (need additional driver).

![initialize_usb-2](resources/initialize_usb2.jpg)

## In Shell
First, remove partition table on your USB flash drive.
<br>
`sudo dd if=/dev/zero bs=4M count=1 of=/dev/${USB_FLASH_DRIVE}`
<br>
The `${USB_FLASH_DRIVE}` must be a device name like sdx, Not a partition name like sdx1.
<br>
**Warning: If you write local storage (ex: hdd/ssd) name on it by mistake, you will lose data on the local storage so please check the name carefully by `lsblk`.**
<br>
<br>
Then you can make a new partition table, partition, and file system by your preferred tools. (ex: Gparted, parted, fdisk, gdisk, mkfs.fat, etc)
