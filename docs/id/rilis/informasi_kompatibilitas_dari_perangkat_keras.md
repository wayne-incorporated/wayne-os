## Catatan
Dokumen asli: [hw_compatibility_information.md](https://gitlab.com/wayne-inc/wayneos/-/blob/master/docs/en/release/hw_compatibility_information.md)

## Cara pemakaian
Carilah (`ctrl+f`) nama PC/perangkat/chipset anda, dan periksa informasi kompatibilitasnya.

## Cara pelaporan/berkontribusi
#### Cara yang sederhana
Lihat tabel kompatibilitas, dan laporkan masalah kompatibilitas perangkat keras di
[komunitas](https://www.facebook.com/groups/wayneosgroup).
<br>Kami akan sangat menghargai jika anda menuliskan isu secara rinci dengan mengacu pada Tabel Kompatibilitas.
<br>Kemudian kontributor/pengelola lain akan menuliskan isu pada dokumen ini dengan nama/ID Anda.

#### Cara yang lebih baik
Jika anda memiliki semangat open source, anda bisa menjadi kontributor.
1) [Gabung di projek Wayne OS](https://gitlab.com/wayne-inc/wayneos/-/blob/master/CONTRIBUTING.md) dan mendapatkan posisi Developer
2) Buat branch sementara (contoh: report-hw_compatibility-[date])
3) Tambahkan informasi di *docs/release/hw_compatibility_information.md*
4) Commit
5) Kirim merge request dari branch sementara (contoh: report-hw_compatibility-[date]) ke branch master
6) Hapus branch sementara (opsional) 

## Tabel kompatibilitas
- PC: detail nama PC dengan perangkat. Pembatas harus berupa spasi (kosong) untuk memudahkan pencarian.
- Kateggori
    - processor: CPU
    - graphic: integrated/external GPU, brightness control
    - wlan: WiFi, IEEE 802.11
    - ethernet: LAN with cable
    - I/O port: input/output ports/interface
    - input device: keyboard, mouse, touchpad
    - audio: audio input/output, volume control
    - buttons: power/sleep/etc buttons on computer
    - bluetooth
    - camera
    - etc: category could be added more
- device: detail nama perangkat yang diperiksa. Pembatas harus berupa spasi (kosong) untuk memudahkan pencarian.
- chipset/driver: detail nama chipset/driver dari perangkat. Pembatas harus berupa spasi (kosong) untuk memudahkan pencarian.
- works
    - O: berfungsi dengan sempurna
    - !: berfungsi dengan masalah
    - X: tidak dapat berfungsi sama sekali
- symptom: deskripsi untuk works column
- OS version: versi Wayne OS (ex: test-installation-3q21)
-reporter: anonymous/name/ID/nickname/email
- report date: YYYY-MM-DD
- remark: informasi tambahan

| PC | category | device | chipset<br>/driver | works | symptom | OS version | reporter | report date | remark |
| --- | --- | ---  | --- | :---: | --- | --- | --- | --- | --- |
| Asus Transformer Book T100TA | wlan | Broadcom 802.11 abgn Wireless SDIO Adapter || X || 3q21-r1 | Stepan Rumyantsev | 2021-10-30 | CloudReady (kernel 5.4) and Fedora (version 34) work well about this device |
||wlan|Intel Centrino Wireless N 100|iwlwifi|X||3q21|Donna R Marpaung|2021-08-14|v: kernel port: d000 bus ID: 03:00.0 chip ID: 8086:08ae IF: wlp3s0 state: up mac: \<filter\>|
|ASUSTeK K43SD|wlan|Qualcomm Atheros AR8151 v2.0 Gigabit Ethernet|atl1c|X||3q21|Donna R Marpaung|2021-08-14|v: 1.0.1.1-NAPI port: 9000 bus ID: 05:00.0 chip ID: 1969:1083 IF: enp5s0 state: down mac: \<filter\> v: 1.0 serial: <filter> Mobo: ASUSTeK model: K43SD v: 1.0 serial: <filter> UEFI: American Megatrends  v: K43SD.208 date: 08/10/2012|
|Dell Inspiron 15 3501||||X|cannot boot|3q21|Ifty ER|2021-08-05|CPU/GPU compatibility is suspected|
|Dell Inspiron 14 3467|wlan|||X||1q21|Jesus Daniel CJ|2021-05-14||
|Samsung NT 670Z5E X58S|wlan|||X||1q21|Choi Jaehyuk|2021-05-04||
|E4300|graphic|Graphics Card Intel GMA 4500MHD||X|shows a white screen, then black|1q21|Peter Nimmo|2021-05||
|E4300|input device|Alps PS/2 ALPS DualPoint Stick||O||1q20|Peter Nimmo|2021-05|as /devices/platform/i8042/serio1/input/input7|
|E4300|input device|Alps PS/2 ALPS DualPoint TouchPad||!||1q20|Peter Nimmo|2021-05|as /devices/platform/i8042/serio1/input/input6<br><br>it needed to pass "psmouse.proto=imps" to the kernel during boot for the touchpad to work|
|M1210|graphic|Intel Graphics Media Accelerator 950 (integrated)||X|shows a white screen, then black|1q21|Peter Nimmo|2021-05||
|M1210|input device|Synaptics TouchPad||O||2q20|Peter Nimmo|2021-05||
||graphic|AMD E1 6010 APU with AMD Radeon R2 Graphics||X|screen was black after installation|usb16g-1q21|Nickatnyte Chauhan|2021-04-01||

## Aturan pengisian tabel
- Mengelola dalam bahasa inggris
- Tambahkan informasi terbaru di tabel teratas
- Satu baris berisi satu informasi untuk perangkat/versi OS
- Jika anda tidak setuju dengan informasi yang ada, alih-alih menghapus/memodifikasi informasi yang ada, tambahkan baris lain dalam tabel
