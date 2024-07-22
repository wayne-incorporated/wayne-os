# Wayne OS 23.11

## Version
- Chromium: 116
- Platform: 15509
- Kernel: 5.15
- Board: reven
- Image build type: dev, test


  
# Wayne OS 3q21-r1
- Same with _Wayne OS 3q21_

# Wayne OS 3q21

## Version
- Chromium: 94
- Platform: 14103
- Kernel: 4.14
- Board: amd64-generic
- Image build type: base, dev, test

## Requirement
- CPU: amd64(x86-64)
- RAM: minimum 2GB
- USB flash drive (or bootable removable storage devices)
    - wayne-os-base-portable8g-3q21: 8GB (7,600,000,000 bytes or over)
    - wayne-os-base-portable16g-3q21: 16GB (15,200,000,000 bytes or over)
    - wayne-os-base-portable32g-3q21: 32GB (30,400,000,000 bytes or over)
    - wayne-os-dev-installation-3q21: 8GB (6,807,435,776 bytes or over)
    - wayne-os-test-installation-3q21: 8GB (6,807,435,776 bytes or over)

## Storages
#### STATE partition
- EXT4
- Encryption
- Accessible in Wayne OS
- Size (in a USB flash drive)
    - wayne-os-base-portable8g-3q21: 2,147,534,848 bytes
    - wayne-os-base-portable16g-3q21: 2,147,534,848 bytes
    - wayne-os-base-portable32g-3q21: 2,147,534,848 bytes
    - wayne-os-dev-installation-3q21: 4,295,023,104 bytes (after install it on PC, the capacity will be increased as local disk capacity)
    - wayne-os-test-installation-3q21: 4,295,023,104 bytes (after install it on PC, the capacity will be increased as local disk capacity)
#### USB-STORAGE partition
- FAT32
- No encryption
- Accessible in Windows XP/7/8/10, macOS, Linux, Wayne OS
- Size
    - wayne-os-base-portable8g-3q21: 3,164,135,936 bytes
    - wayne-os-base-portable16g-3q21: 10,764,135,936 bytes
    - wayne-os-base-portable32g-3q21: 25,964,135,936 bytes
<br>
<br>
<br>

# Wayne OS 1q21

## Version
- Chromium: 91.0.4438.0
- Platform: 13828.0
- Board: amd64-generic
- Image build type: Developer

## Requirement
- CPU: amd64(x86-64)
- RAM: minimum 2GB
- USB flash drive: 8GB/16GB/32GB

## Binary file size
- wayne-os-usb8g-1q21: 7,200,000,000 bytes
- wayne-os-usb16g-1q21: 14,400,000,000 bytes
- wayne-os-usb32g-1q21: 28,800,000,000 bytes

## Storages
#### STATE partition
- 4,294,967,296 bytes
- EXT4
- Accessible in Wayne OS
- Encryption
#### USB-STORAGE partition
- wayne-os-usb8g-1q21: 392,571,904 bytes
- wayne-os-usb16g-1q21: 7,592,571,904 bytes
- wayne-os-usb32g-1q21: 21,992,571,904 bytes
- FAT32
- Accessible in Windows XP/7/8/10, macOS, Linux, Wayne OS
- No encryption
