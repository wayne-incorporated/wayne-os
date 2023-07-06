## Catatan
Dokumen asli: [ssh_connection_from_remote.md](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/how-to/ssh_connection_from_remote.md)
<br>Dokumen ini mengharapkan kontribusi anda (dokumentasi, terjemahan, pelaporan, saran, pengkodean).

## Persyaratan
- Server: PC Wayne OS yang menjalankan versi _dev_ atau _test_.
- Klien: PC dengan fitur klien ssh (Segala OS dapat dipakai, tetapi dokumen ini akan menjelaskan dengan shell Linux).
- Periksa alamat dari server IP dan pastikan IP dapat dijangkau dari klien (mis: `ping ${SERVER_IP}`).

## Wayne OS versi dev
#### Hubungkan ke server dari klien
ID: chronos
<br>PW: kata sandi dari versi _wayne-os-dev_ 
- Sebagai contoh:
~~~
$ ssh chronos@192.168.140.172
Password:
~~~
#### Menghapus kata sandi 
TODO: menulis

## Wayne OS versi test
#### 1. Pengaturan pada klien
Pertama, unduhlah kunci pengujian RSA dan file konfigurasi ke ~/.ssh/
~~~
$ cd ~/.ssh && wget \
https://gitlab.com/wayne-inc/wayne_os/-/raw/master/cros-src/cros_sdk/src/scripts/mod_for_test_scripts/ssh_keys/testing_rsa \
https://gitlab.com/wayne-inc/wayne_os/-/raw/master/cros-src/cros_sdk/src/scripts/mod_for_test_scripts/ssh_keys/testing_rsa.pub \
https://gitlab.com/wayne-inc/wayne_os/-/raw/master/cros-src/cros_sdk/src/scripts/mod_for_test_scripts/ssh_keys/config
~~~
Kemudian batasi izin pada ~/.ssh/testing_rsa
~~~
$ chmod 0600 ~/.ssh/testing_rsa
~~~
Dan ganti 000.000.000.000 to alamat klien IP di file config oleh editor.
~~~
$ vim ~/.ssh/config
~~~
~~~
# Example
Host wayne-os
  CheckHostIP no
  StrictHostKeyChecking no
  IdentityFile %d/.ssh/testing_rsa
  Protocol 2
  User root
  HostName 000.000.000.000  # Replace here to server IP
~~~
#### 2. Hubungkan ke server dari klien
~~~
$ ssh wayne-os
~~~
Kemudian anda akan mendapatkan root-Shell tanpa kata sandi.
<br>Jika terhubung ke beberapa server, anda dapat membagikan opsi konfigurasi umum di ~/.ssh/config.php anda.
~~~
# Example
Host 172.22.168.*   # The subnet containing your Servers
  CheckHostIP no
  StrictHostKeyChecking no
  IdentityFile %d/.ssh/testing_rsa
  Protocol 2
  User root

Host wayne-os1
  HostName 172.22.168.233   # Write server IP on here

Host wayne-os2
  HostName 172.22.168.234   # Write server IP on here
~~~

## Referensi 
https://www.chromium.org/chromium-os/testing/autotest-developer-faq/ssh-test-keys-setup 
