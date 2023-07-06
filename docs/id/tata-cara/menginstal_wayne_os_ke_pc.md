## Catatan
Dokumen asli: [installing_wayne_os_on_a_pc.md](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/how-to/installing_wayne_os_on_a_pc.md)
<br>Dokumen ini mengharapkan kontribusi anda (dokumentasi, terjemahan, pelaporan, saran, pengkodean).
<br>Instalasi PC hanya tersedia di versi _wayne-os-dev_ dan _wayne-os-test_ dan tidak di tersedia di versi wayne-os-base.

## 1. Persiapan
- [Instal](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/id/tata-cara/menginstal_wayne_os_ke_usb.md) versi _wayne-os-dev or _wayne-os-test_ ke USB flash drive.
- Setelah boot Wayne OS dari USB flash drive di target PC, periksa apakah berfungsi dengan baik (periksa kompatibilitas HW, fitur, isu-isu)
<p>Apabila eror tetap muncul setelah diperiksa, ini berarti eror akan tetap muncul walaupun anda menginstal OS ke PC. Sehingga apabila hal ini terjadi, sebaiknya anda mempertimbangkan kembali mengenai PC instalasi.
<br>Sebagai informasi, kapasitas partisi STATE Wayne OS akan bertambah menjadi kapasitas disk lokal.

## 2. Proses Instalasi
- [login ke mode konsol](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/id/tata-cara/menggunakan_shell.md)
- Periksa nama disk target name dengan lsblk
<br>**Catatan: Periksa kolum SIZE dan TYPE dari lsblk, kemudian pilihlah disk target secara hati-hati.**
<br>**Pilih nama disk secara tepat (contoh: sda 8:0 0 59.6G 0 disk) dari pada nama partisi (contoh: sda1 8:1 0 55.3G 0 part).**
<br>**Jangan bingung di antara disk target dengan disk lokal lain atau removable disk. Setiap data dari disk target akan hilang setelah proses instalasi.**
- Ketik command `sudo /usr/sbin/chromeos-install --dst /dev/${TARGET_DISK}`
<br>(ex: `sudo /usr/sbin/chromeos-install --dst /dev/sda`)
- Ketik ulang PW ketika konsol memintanya.
- Setelah beberapa menit, proses instalasi sukses apabila anda melihat pesan `Installation to /dev/${TARGET_DISK} complete. Please shutdown, remove the USB device, cross your fingers, and reboot.`
- Tutup OS dengan `sudo poweroff`, melepas USB flash drive, kemudian [boot dengan target disk](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/id/tata-cara/membooting_wayne_os.md)

## 3. Pemecahan masalah
- Jika anda ingin menginstal Wayne OS ke removable disk, tambahkan `--skip_dst_removable` 
<br> (ex: `sudo /usr/sbin/chromeos-install --skip_dst_removable --dst /dev/sda`)
- `sudo /usr/sbin/chromeos-install --help` akan menunjukkan lebih banyak opsi instalasi
- `sudo dd if=/dev/zero bs=512 count=4096 of=/dev/${TARGET_DISK}` akan menghapus skema partisi dan akan menginiliasi
