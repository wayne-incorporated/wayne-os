## GUI setup (only important setups)
#### Turn on screen while the device is idel
1. Settings
2. Device
3. Power
4. When idle: Keep display on
#### Input Hangul
1. Settings
2. Device
3. Keyboard
4. Change input settings
5. Show input options in the shelf: on
6. Input methods: Hangul 2 Set
7. Change the keyboard input by ctrl+space
8. Turn it to Hangul by Input methods icon in right bottom side, when input with the on screen keyboard
#### Turn off notification
1. Settings
2. Apps
3. Notifications: Do not disturb on
4. Apps
5. Restore apps on startup: off

## CUI setup

#### Modify wayne-autologin.conf
- [enter console mode](https://github.com/Wayne-Incorporated/wim-os/blob/main/docs/using_shell.md), `sudo mount -o remount,rw / && sudo vi /etc/init/wayne-autologin.conf`
- Modify --url parameter of autologin.py

#### Modify chrome_dev.conf
- [enter console mode](https://github.com/Wayne-Incorporated/wim-os/blob/main/docs/using_shell.md), `sudo mount -o remount,rw / && sudo vi /etc/chrome_dev.conf`
- Refer Chromium mode flag list(https://peter.sh/experiments/chromium-command-line-switches/), then input the features.
- Save `chrome_dev.conf` file then reboot.
- Available features:
- --kiosk: full screen of the web browser, and the other features will be locked excpet web browser & power button.
- --start-fullscreen: full screen of the web browser. panel, [shell](https://github.com/wayne-incorporated/wim-os/blob/main/docs/%EC%85%B8%20%EC%82%AC%EC%9A%A9%ED%95%98%EA%B8%B0.md)
- --enable-virtual-keyboard: on screen keyboard.
- --incognito: incognito mode of web browser
