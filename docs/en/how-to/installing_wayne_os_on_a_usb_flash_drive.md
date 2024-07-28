## 1. Preparation
- An Wayne OS binary file
- A USB flash drive which size is greater than the OS binary file size
- A Windows/Linux/Chrome OS environment with free disk space greater than the OS binary file size.
  
## 2. Initialize USB flash drive (optional)
- If your USB flash drive has an error/corruption, the installation process could fail.
- [Initialize USB](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/how-to/initializing_usb_flash_drive.md).


## 3. Write the binary file on USB flash drive
### In Chrome/Chromium
- _Chromebook recovery utility_: [download](https://chrome.google.com/webstore/detail/chromebook-recovery-utili/jndclpdbaamdhonoechobihbbiimdgai/RK%3D2/RS%3DUI2uA8SxDAwF_T9oPb4YviZFT3Y-)
<br> click gear icon/setting on top right > use local image.

### In Windows
- _USBWriter-1.3_: [download](https://sourceforge.net/projects/usbwriter/)
- _win32diskimager-binary_: [download](https://win32diskimager.download/)
- _balenaEtcher-Portable-1.5.109_: This seems not working for Wayne OS installation perfectly
- _rufus-3.11_: This cannot install Wayne OS exactly

### In shell
`$ sudo dd if=${BIN_FILE} of=/dev/${USB_FLASH_DRIVE}`
<br>
`${BIN_FILE}` must be the binary file name.
<br>
`${USB_FLASH_DRIVE}` must be a device name like sdx, Not a partition name like sdx1.
<br>
**Warning: If you write local storage (ex: hdd/ssd) name on it by mistake, you will lose data on the local storage so please check the device name carefully by `lsblk`.**
