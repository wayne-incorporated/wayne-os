## Catatan
Dokumen asli: [auto_login.md](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/how-to/auto_login.md)
<br>Dokumen ini mengharapkan kontribusi anda (dokumentasi, terjemahan, pelaporan, saran, pengkodean).
<br>Dokumen ini sedang dalam proses penulisan.
<br>Fitur-fitur di dokumen ini belum dirilis. (2022-03-17)

## Persyaratan
- Server: PC Wayne OS yang menjalankan versi _test_
- Klien: PC dengan fitur klien ssh (OS apa pun bisa digunakan, tetapi dokumen ini akan menjelaskan dengan shell Linux) 
- Periksa alamat IP server dan pastikan IP dapat dijangkau dari klien (mis: `ping ${SERVER_IP}`)

## 1. Persiapan
#### SSH
Siapkan dan periksa [koneksi ssh](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/id/tata-cara/koneksi_ssh_dari_remote.md).
#### ID Google 
Disarankan menggunakan ID Google sementara dikarenakan fitur login otomatis ini tidaklah aman, dan lebih mudah untuk menggunakan login otomatis, jika Anda menonaktifkan Verifikasi 2 Langkah untuk ID Google.
#### GCP
#### Server
Aktifkan _Wayne OS test version_ dan konfigurasikan konfigurasi awal (bahasa/jaringan/dll).

## 2. Login jarak jauh
#### Hubungkan ssh dari klien ke server.
~~~
$ sudo ssh ${SERVER_IP} "/usr/local/autotest/bin/autologin.py -u '${USER_ID}'"
Password:

...

Warning: Password input may be echoed.
Password:
~~~
- ${SERVER_IP}: Alamat IP dari perangkat Wayne OS (mis.: 192.168.0.100) 
- ${USER_ID}: ID Google untuk login
- 1st Password prompt: Kata sandi shell dari versi _Wayne OS test_ 
- 2st Password prompt: Kata sandi dari ID Google
#### Contoh pilihan 
~~~
$ sudo ssh 192.168.0.100 "/usr/local/autotest/bin/autologin.py --help"
Password:

...

usage: autologin.py [-h] [-a] [--arc_timeout ARC_TIMEOUT] [-d] [-u USERNAME]
                    [--enable_default_apps] [-p PASSWORD] [-w]
                    [--no-arc-syncs] [--toggle_ndk] [--nativebridge64]
                    [-f FEATURE] [--url URL]

Make Chrome automatically log in.

optional arguments:
  -h, --help            show this help message and exit
  -a, --arc             Enable ARC and wait for it to start.
  --arc_timeout ARC_TIMEOUT
                        Enable ARC and wait for it to start.
  -d, --dont_override_profile
                        Keep files from previous sessions.
  -u USERNAME, --username USERNAME
                        Log in as provided username.
  --enable_default_apps
                        Enable default applications.
  -p PASSWORD, --password PASSWORD
                        Log in with provided password.
  -w, --no-startup-window
                        Prevent startup window from opening (no doodle).
  --no-arc-syncs        Prevent ARC sync behavior as much as possible.
  --toggle_ndk          Toggle the translation from houdini to ndk
  --nativebridge64      Enables the experiment for 64-bit native bridges
  -f FEATURE, --feature FEATURE
                        Enables the specified Chrome feature flag
  --url URL             Navigate to URL.

$ sudo ssh 192.168.140.172 "/usr/local/autotest/bin/autologin.py --url 'https://wayne-os.com' -u 'seongbin@wayne-inc.com' -p 'my_private_pw'"
~~~


## Referensi
https://chromium.googlesource.com/chromiumos/docs/+/main/tips-and-tricks.md#how-to-enable-a-local-user-account 
