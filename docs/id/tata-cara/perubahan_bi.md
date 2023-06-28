## Catatan
Dokumen asli: [bi_change.md](https://gitlab.com/wayne-inc/wayneos/-/blob/master/docs/en/how-to/bi_change.md)
<br>Dokumen ini mengharapkan kontribusi anda (dokumentasi, terjemahan, pelaporan, saran, pengkodean).
<br>Wayne OS mengizinkan para pengguna/pelanggan untuk mengubah BI (identitas merk: logo, nama) dari Wayne OS dibawah [persyaratan layanan Wayne OS](https://gitlab.com/wayne-inc/wayneos/-/blob/doc-eve-220730/docs/id/bisnis/persyaratan_layanan.md).

## Persiapan
- Susun fail _png_ image anda dengan merujuk ke paket [chromiumos-assets](https://gitlab.com/wayne-inc/wayneos/-/tree/master/src/platform/chromiumos-assets).
- Periksa apakah ukuran dan nama fail pixel gambar anda sesuai dengan referensi.

## Memasukkan BI anda di Wayne OS
- [login ke mode konsol](https://gitlab.com/wayne-inc/wayneos/-/blob/master/docs/id/tata-cara/menggunakan_shell.md).
- Hapus fail gambar yang ada di 
<br>/usr/share/chromeos-assets/images
<br>/usr/share/chromeos-assets/images_100_percent
<br>/usr/share/chromeos-assets/images_200_percent
- Masukkan fail gambar di jalur yang disebutkan di atas (melalui USB flash drive atau ssh).
- Nyalakan ulang dan periksa BI baru.
