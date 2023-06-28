## Note
This document is looking foward to your contribution (documentation, translation, reporting, suggestion, coding).
<br>Only _wayne-os-dev_ and _wayne-os-test_ versions support PC installation as _wayne-os-base_ version doesn't support it.

## 1. Preparation
- [Install](https://gitlab.com/wayne-inc/wayneos/-/blob/master/docs/en/how-to/installing_wayne_os_on_a_usb_flash_drive.md) _wayne-os-dev_ or _wayne-os-test_ version on a USB flash drive.
- After booting Wayne OS by USB flash drive on a target PC, check whether it is up and running (check HW compatibilities, features, known issues)  
<p>If errors appear when you check, it means that the errors still exist even if you install OS on your PC. So if this case happens, you should reconsider about PC installation.
<br>FYI, Wayne OS STATE partition capacity will be increased as local disk capacity, after PC installation.

## 2. Installation
- [login to console mode](https://gitlab.com/wayne-inc/wayneos/-/blob/master/docs/en/how-to/using_shell.md)
- Check the target disk name by `lsblk`
<br>**Note: Check _SIZE_ and _TYPE_ column in `lsblk` result, then select the target disk carefully.**
<br>**Select the exact disk name (ex: sda 8:0 0 59.6G 0 disk) instead of the partition name (ex: sda1 8:1 0 55.3G 0 part).**
<br>**Don't confuse the target disk with other local/removable disk. Every data on the target disk will be disappear after installation.**
- Type command `sudo /usr/sbin/chromeos-install --dst /dev/${TARGET_DISK}` 
<br>(ex: `sudo /usr/sbin/chromeos-install --dst /dev/sda`)
- Retype PW when the console asks for it
- After dozens of minutes, the installation is successful if you can see `Installation to /dev/${TARGET_DISK} complete. Please shutdown, remove the USB device, cross your fingers, and reboot.` message
- Shutdown OS by `sudo poweroff`, remove USB flash drive, then [boot by target disk](https://gitlab.com/wayne-inc/wayneos/-/blob/master/docs/en/how-to/booting_wayne_os.md)

## 3. Troubleshoot
- If you want to install Wayne OS on a removable disk, add `--skip_dst_removable`
<br> (ex: `sudo /usr/sbin/chromeos-install --skip_dst_removable --dst /dev/sda`)
- `sudo /usr/sbin/chromeos-install --help` shows more installation options
- `sudo dd if=/dev/zero bs=512 count=4096 of=/dev/${TARGET_DISK}` will remove a partition scheme and initialize the target disk
