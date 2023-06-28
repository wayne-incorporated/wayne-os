## Catatan
Dokumen asli: [commands_for_os_management.md](https://gitlab.com/wayne-inc/wayneos/-/blob/master/docs/en/how-to/commands_for_os_management.md)
<br>Dokumen ini mengharapkan kontribusi anda (dokumentasi, terjemahan, pelaporan, saran, pengkodean).
<br>Dokumen ini bertujuan untuk membantu para pengembang yang ingin mengelola Wayne OS.
<br>Kegiatan: Sepertinya dokumen ini berfungsi untuk cros versi turunan lainnya, sehingga hasil tes harus ditambahkan.

## Persyaratan
Versu _wayne-os-dev_ atau _wayne-os-test_ 

## Dalam shell lokal
[Membuka shell](https://gitlab.com/wayne-inc/wayneos/-/blob/master/docs/en/how-to/using_shell.md) di Wayne OS device kemudian cobalah langkah-langkah berikut.
#### Penghapusan
```
$ { sudo bash -c 'echo "fast safe" > /mnt/stateful_partition/factory_install_reset' ;} && sudo reboot
```
or
```
$ { echo "fast safe" | sudo tee -a /mnt/stateful_partition/factory_install_reset ;} && sudo reboot
```
#### Pengendalian tugas
Wayne OS dan versi turunan Chromium OS menggunakan [Upstart](https://upstart.ubuntu.com/).
<br>Untuk memerika lis tugas.
```
$ sudo initctl list
```
Untuk mengendalikan pekerjaan.
```
sudo initctl start/stop/restart/status ${JOB}
```

#### Perintah-perintah yang tersedia untuk memeriksa informasi, kinerja
- cat [/proc/*](https://man7.org/linux/man-pages/man5/proc.5.html)
- cat /etc/*release
- [lscpu](https://man7.org/linux/man-pages/man1/lscpu.1.html)
- [lsusb](https://man7.org/linux/man-pages/man8/lsusb.8.html)
- sudo [lspci](https://man7.org/linux/man-pages/man8/lspci.8.html)
- [mount](https://man7.org/linux/man-pages/man8/mount.8.html)
- [uname](https://man7.org/linux/man-pages/man1/uname.1.html)
- [ifconfig](https://man7.org/linux/man-pages/man8/ifconfig.8.html)
- [top](https://man7.org/linux/man-pages/man1/top.1.html)
- [free](https://man7.org/linux/man-pages/man1/free.1.html)
- [vmstat](https://man7.org/linux/man-pages/man8/vmstat.8.html)
- [netstat](https://man7.org/linux/man-pages/man8/netstat.8.html)
- [df](https://man7.org/linux/man-pages/man1/df.1.html)
- [du](https://man7.org/linux/man-pages/man1/du.1.html)
- [lsof](https://man7.org/linux/man-pages/man8/lsof.8.html)
- [uptime](https://man7.org/linux/man-pages/man1/uptime.1.html)
- [ps](https://man7.org/linux/man-pages/man1/ps.1.html)
- [pmap](https://man7.org/linux/man-pages/man1/pmap.1.html)
- sudo [ss](https://man7.org/linux/man-pages/man8/ss.8.html)
- [ipcs](https://man7.org/linux/man-pages/man1/ipcs.1.html)
- sudo [dmidecode](https://linux.die.net/man/8/dmidecode)
- sudo [hdparm](https://man7.org/linux/man-pages/man8/hdparm.8.html)
- [lsblk](https://man7.org/linux/man-pages/man8/lsblk.8.html)
- sudo [dmesg](https://man7.org/linux/man-pages/man1/dmesg.1.html)

## Dari jarak jauh
Anda dapat mengirimkan perintah shell dari perangkat jarak jauh pada perangkat Wayne OS [melalui ssh](https://gitlab.com/wayne-inc/wayneos/-/blob/master/docs/en/how-to/ssh_connection_from_remote.md).
```
ssh chronos@${IP} -t "COMMAND"  # Bagian ini akan meminta kata sandi lagi jika perintah meliputi sudo.
ssh root@${IP} "COMMAND"  # Bagian ini hanya tersedia di versi Wayne OS test.
```

#### Contoh-contoh
- Memaksa penghapusan pada perangkat Wayne OS.
```
$ ssh chronos@192.168.100.200 -t "{ echo "fast safe" | sudo tee -a /mnt/stateful_partition/factory_install_reset ;} && sudo reboot"
```
- Memaksa untuk menstart ulang UI (Keluar dari sesi grafik pengguna) pada perangkat Wayne OS.
```
$ ssh root@192.168.100.200 "initctl restart ui"
```
- Mendapatkan proses informasi dari perangkat Wayne OS.
```
$ ssh chronos@192.168.100.200 -t "top -n 1 -b" > proc_list.txt
```
