## GUI setup (hanya setup yang penting)
#### Nyalakan layar sewaktu tidak digunakan
1. Pengaturan
2. Perangkat
3. Power
4. Ketika tidak digunakan: display tetap nyala
#### Hangul input
1. Pengaturan
2. Perangkat
3. Keyboard
4. Mengubar pengaturan input
5. Menunjukkan input di shelf: buka
6. Metode Hangul input: Hangul 2 Set
7. Mengubah keyboard input dengan ctrl+space
8. Mengubah ke Hangul dengan metode input di sisi bawah, ketika input bersama keyboard on screen
#### Menutup notifikasi
1. Pengaturan
2. Aplikasi
3. Pengaturan: Mode jangan menganggu
4. Aplikasi
5. Mengembakikan aplikasi ketika dimatikan: tidak menyala

## Setup CUI

#### Memodifikasi wayne-autologin.conf
- [enter console mode](https://github.com/Wayne-Incorporated/wim-os/blob/main/docs/using_shell.md), `sudo mount -o remount,rw / && sudo vi /etc/init/wayne-autologin.conf`
- Modify --url parameter of autologin.py

#### Memodifikasi chrome_dev.conf
- [enter console mode](https://github.com/Wayne-Incorporated/wim-os/blob/main/docs/using_shell.md), `sudo mount -o remount,rw / && sudo vi /etc/chrome_dev.conf`
- Refer Chromium mode flag list(https://peter.sh/experiments/chromium-command-line-switches/), then input the features.
- Save `chrome_dev.conf` file then reboot.
- Fitur yg tersedia:
- --kiosk: full screen of the web browser, and the other features will be locked excpet web browser & power button.
- --start-fullscreen: full screen of the web browser. panel, [shell](https://github.com/wayne-incorporated/wim-os/blob/main/docs/%EC%85%B8%20%EC%82%AC%EC%9A%A9%ED%95%98%EA%B8%B0.md)
- --enable-virtual-keyboard: on screen keyboard.
- --incognito: incognito mode of web browser
