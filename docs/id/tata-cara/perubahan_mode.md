## Catatan
Dokumen asli: [mode_change.md](https://gitlab.com/wayne-inc/wayneos/-/blob/master/docs/en/how-to/mode_change.md)
<br>Dokumen ini mengharapkan kontribusi anda (dokumentasi, terjemahan, pelaporan, saran, pengkodean).
<br>Fitur di dokumen ini belum dirilis. (2022-03-17)
 
 
## Mengakses ke chrome_dev.conf
- [login ke mode konsol](https://gitlab.com/wayne-inc/wayneos/-/blob/master/docs/id/tata-cara/menggunakan_shell.md).
- Ketik command `/usr/sbin/mode_change-wayneos` (memerlukan sudo pw).
- Booting ulang OS setelah memodifikasi _chrome_dev.conf_.

#### Mengaktifkan flag:
1. Pilih flags di _chrome_dev.conf_. 
2. Hapus tanda sharp (#) yang berada di depan flag (Jangan menghapus tanda sharp yang berada di depan penjelasan).
3. Tambahkan argumen jika flag membutuhkannya.
#### Mengnonaktifkan flag:
1. Tulis tanda sharp (#) di depan flag.

## Kumpulan kegunaan flag 
#### Untuk kios
- --kiosk: UI akan dikunci kecuali browser.
- --start-fullscreen: Browser web akan dibuka dengan layar penuh.
- --enable-virtual-keyboard: Untuk layar sentuh.
#### Untuk PC umum
- --incognito: Browser web akan dimulai dengan mode incognito.
