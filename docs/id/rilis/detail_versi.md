## Catatan
Dokumen asli: [version_details.md](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/release/version_details.md)
<br>Dokumen ini mengharapkan kontribusi anda (dokumentasi, terjemahan, pelaporan, saran, pengkodean).

## Notasi
wayne-os-${IMAGE_TYPE}-${USE}-${RELEASED_QUARTER_YEAR}
​
## Deskripsi
#### Tipe image
- _base_: Image Pristine Chromium OS yang hampir serupa dengan Chrome OS
- _dev_: Image Developer image yang serupa dengan base dengan tambahan paket dev
- _test_: Serupa dengan dev dengan tambahan paket spesifik dari test dan bisa digunakan secara gampang untuk test otomatis dengan menggunakan skrip seperti test_that, dsb.
#### Penggunaan
- _portabel_: termasuk partisi USB-STORAGE yang bisa digunakan sebagai removable storage di Windows, macOS, Linux, Wayne OS
- _instalasi_: bisa menginstal Wayne OS dari USB flash drive ke lokal/removable disk yang lain di PC
#### Perilisan kuartal dan tahunan
- Sebagai contohnya, 3q21 yang berarti dirilis kuarter ketiga di 2021

## Perbandingan fitur
|                           |_base-portable_ |_dev-installation_  |_test-installation_ |
|---                        |---    |---    |---    |
|USB-STORAGE                |O      |X      |X      |
|[menggunakan shell](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/id/tata-cara/menggunakan_shell.md)                |X      |O      |O      |
|[menginstal ke PC](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/id/tata-cara/menginstal_wayne_os_ke_pc.md)           |X      |O      |O      |
|[koneksi ssh dari remote](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/id/tata-cara/koneksi_ssh_dari_remote.md) |X      |O      |O      |
|[cros flash](https://chromium.googlesource.com/chromiumos/docs/+/master/cros_flash.md) |X      |X      |O      |
