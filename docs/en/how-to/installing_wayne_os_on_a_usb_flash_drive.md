## Note
This document is looking foward to your contribution (documentation, translation, reporting, suggestion, coding).

## 1. Preparation
- Windows/Linux/Chromebook PC with the same free disk space available as the OS image file
- A USB flash drive

## 2. [Download Wayne OS binary](https://wayne-os.com/download-wayne-os-binary/)

## 3. Initialize USB flash drive (optional)
- If your USB flash drive has an error/corruption, the installation process could fail
- [Initialize USB](https://gitlab.com/wayne-inc/wayneos/-/blob/master/docs/en/how-to/initializing_usb_flash_drive.md)

## 4. Write .bin file on USB flash drive by image writer tool
### Windows user
- _USBWriter-1.3_: [download](https://sourceforge.net/projects/usbwriter/)
- _win32diskimager-binary_: [download](https://win32diskimager.download/)
- _Chromebook recovery utility_: [download](https://chrome.google.com/webstore/detail/chromebook-recovery-utili/jndclpdbaamdhonoechobihbbiimdgai/RK%3D2/RS%3DUI2uA8SxDAwF_T9oPb4YviZFT3Y-)
<br> click gear icon/setting on top right > use local image.
- _balenaEtcher-Portable-1.5.109_: This seems not working for Wayne OS installation perfectly
- _rufus-3.11_: This cannot install Wayne OS exactly

### Chromebook user
- _Chromebook recovery utility_: [download](https://chrome.google.com/webstore/detail/chromebook-recovery-utili/jndclpdbaamdhonoechobihbbiimdgai/RK%3D2/RS%3DUI2uA8SxDAwF_T9oPb4YviZFT3Y-)

### Linux user
`$ sudo dd if=${BIN_FILE} of=/dev/${USB_FLASH_DRIVE}`
<br>
`${BIN_FILE}` must be .bin file name like wayne-os-usb16g-1q21.bin.
<br>
`${USB_FLASH_DRIVE}` must be a device name like sdx, Not a partition name like sdx1.
<br>
**Warning: If you write local storage (ex: hdd/ssd) name on it by mistake, you will lose data on the local storage so please check the device name carefully by `lsblk`.**
<br>

## 5. Check
- If you install _wayne-os-portable_ version, you can see only a STORAGE partition in Windows/macOS if the installation is succeed
- Try to boot the USB flash drive on your computer via USB booting from BIOS/UEFI setting
