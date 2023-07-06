## Catatan
Dokumen asli: [installing_wayne_os_on_a_usb_flash_drive.md](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/how-to/installing_wayne_os_on_a_usb_flash_drive.md)
<br>Dokumen ini mengharapkan kontribusi anda (dokumentasi, terjemahan, pelaporan, saran, pengkodean).

## 1. Persiapan
- PC Windows/Linux/Chromebook dengan ruang disk kosong yang tersedia sama seperti fail OS
- USB flash drive

## 2. [Unduh fail biner Wayne OS](https://wayne-os.com/download-wayne-os-binary/)

## 3. Initialisasi USB (pilihan)
- Jika USB anda eror/rusak, proses instalasi bisa gagal
- [Menginisialisasi USB](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/id/tata-cara/menginisialisasi_usb.md)

## 4. Membuat fail .bin di USB dengan alat image writer
### Pengguna Windows
- _USBWriter-1.3_: [unduh](https://sourceforge.net/projects/usbwriter/)
- _win32diskimager-binary_: [unduh](https://win32diskimager.download/)
- _Chromebook recovery utility_: [unduh](https://chrome.google.com/webstore/detail/chromebook-recovery-utili/jndclpdbaamdhonoechobihbbiimdgai/RK%3D2/RS%3DUI2uA8SxDAwF_T9oPb4YviZFT3Y-)
<br> Klik ikon roda/pengaturan di bagian kanan atas > gunakan image lokal.
- _balenaEtcher-Portable-1.5.109_: Metode ini sepertinya tidak berjalan begitu lancar untuk instalasi Wayne OS.
- _rufus-3.11_: Metode ini tidak bisa mengintsal Wayne OS.

### Pengguna Chromebook
- Chromebook recovery utility: [unduh](https://chrome.google.com/webstore/detail/chromebook-recovery-utili/jndclpdbaamdhonoechobihbbiimdgai/RK%3D2/RS%3DUI2uA8SxDAwF_T9oPb4YviZFT3Y-)

### Pengguna Linux
`$ sudo dd if=${BIN_FILE} of=/dev/${USB_FLASH_DRIVE}`
<br>
`${BIN_FILE}` haruslah berupa nama fail .bin seperti wayne-os-usb16g-1q21.bin.
<br>
`${USB_FLASH_DRIVE}` haruslah berupa nama perangkat seperti sdx, bukan berupa nama partisi seperti sdx1.
<br>
**Peringatan: Jika anda tidak sengaja menghapus nama penyimpanan lokal (cth: hdd/sdd), anda akan kehilangan data di penyimpanan lokal jadi mohon diperiksa nama perangkatnya secara teliti oleh lsblk.**
<br>

## 5. Periksa
- Jika anda menginstal versi wayne-os-portable, anda bisa melihat partisi penyimpanan USB jika proses instalasi berhasil.
- Coba untuk memboot USB di computer melalui boot USB booting di pengaturan BIOS/UEFI.
