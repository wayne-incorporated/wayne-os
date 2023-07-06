## Catatan
Dokumen asli: [specification.md](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/release/specification.md)
<br>Dokumen ini mengharapkan kontribusi anda (dokumentasi, terjemahan, pelaporan, saran, pengkodean).

## Wayne OS 3q21-r1
- Sama dengan Wayne OS 3q21

# Wayne OS 3Q21

## Versi
- Chromium: 94
- Platform: 14103
- Kernel: 4.14
- Board: amd64-generic
- Image build type: base, dev, test

## Persyaratan
- CPU: amd64(x86-64)
- RAM: minimum 2GB
- USB flash drive (atau perangkat removable storage yang dapat dibooting)
    - wayne-os-base-portable8g-3q21: 8GB (7,600,000,000 bytes or over)
    - wayne-os-base-portable16g-3q21: 16GB (15,200,000,000 bytes or over)
    - wayne-os-base-portable32g-3q21: 32GB (30,400,000,000 bytes or over)
    - wayne-os-dev-installation-3q21: 8GB (6,807,435,776 bytes or over)
    - wayne-os-test-installation-3q21: 8GB (6,807,435,776 bytes or over)

## Penyimpanan
#### Partisi STATE
- EXT4
- Terenkripsi
- Dapat diakses di Wayne OS
- Kapasitas (di USB flash drive)
    - wayne-os-base-portable8g-3q21: 2,147,534,848 bytes
    - wayne-os-base-portable16g-3q21: 2,147,534,848 bytes
    - wayne-os-base-portable32g-3q21: 2,147,534,848 bytes
    - wayne-os-dev-installation-3q21: 4,295,023,104 bytes (after install it on PC, the capacity will be increased as local disk capacity)
    - wayne-os-test-installation-3q21: 4,295,023,104 bytes (after install it on PC, the capacity will be increased as local disk capacity)
#### Partisi penyimpanan USB
- FAT32
- Tidak terenkripsi
- Dapat diakses di Windows XP/7/8/10, macOS, Linux, Wayne OS
- Kapasitas
    - wayne-os-base-portable8g-3q21: 3,164,135,936 bytes
    - wayne-os-base-portable16g-3q21: 10,764,135,936 bytes
    - wayne-os-base-portable32g-3q21: 25,964,135,936 bytes
<br>
<br>
<br>

# Wayne OS 1q21

## Versi
- Chromium: 91.0.4438.0
- Platform: 13828.0
- Board: amd64-generic
- Image build type: Developer

## Syarat keperluan
- CPU: amd64(x86-64)
- RAM: minimum 2GB
- USB flash drive: 8GB/16GB/32GB

## Ukuran fail binary
- wayne-os-usb8g-1q21: 7,200,000,000 bytes
- wayne-os-usb16g-1q21: 14,400,000,000 bytes
- wayne-os-usb32g-1q21: 28,800,000,000 bytes

## Penyimpanan 
#### Partisi STATE
- 4,294,967,296 bytes
- EXT4
- Dapat diakses di Wayne OS
- Terenkripsi
#### Partisi USB
- wayne-os-usb8g-1q21: 392,571,904 bytes
- wayne-os-usb16g-1q21: 7,592,571,904 bytes
- wayne-os-usb32g-1q21: 21,992,571,904 bytes
- FAT32
- Dapat diakses di Windows XP/7/8/10, macOS, Linux, Wayne OS
- Tidak terenkripisi
