# Commands for OS management
## Requirement
_wayne-os-dev_ or _wayne-os-test_ versions

## In local shell
[Open shell](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/how-to/using_shell.md) in Wayne OS device then try the following steps.
#### Powerwash
```
$ { sudo bash -c 'echo "fast safe" > /mnt/stateful_partition/factory_install_reset' ;} && sudo reboot
```
or
```
$ { echo "fast safe" | sudo tee -a /mnt/stateful_partition/factory_install_reset ;} && sudo reboot
```
#### Job control
Wayne OS and Chromium OS derivates use [Upstart](https://upstart.ubuntu.com/).
<br>To check job list.
```
$ sudo initctl list
```
To control the job.
```
sudo initctl start/stop/restart/status ${JOB}
```

#### Available commands for checking information, performance
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

## From remote
You can send the shell commands from remote device to Wayne OS device [via ssh](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/how-to/ssh_connection_from_remote.md).
```
ssh chronos@${IP} -t "COMMAND"  # This will ask pw again if the COMMAND includes sudo.
ssh root@${IP} "COMMAND"  # This is available only in Wayne OS test version.
```

#### Examples
- Force powerwash to Wayne OS device.
```
$ ssh chronos@192.168.100.200 -t "{ echo "fast safe" | sudo tee -a /mnt/stateful_partition/factory_install_reset ;} && sudo reboot"
```
- Force to restart UI (logout user graphic session) on Wayne OS device.
```
$ ssh root@192.168.100.200 "initctl restart ui"
```
- Getting process information from Wayne OS device.
```
$ ssh chronos@192.168.100.200 -t "top -n 1 -b" > proc_list.txt
```

--------------
# auto_login.md
## Note
This document is in progress.
<br>This document is looking foward to your contribution (documentation, translation, reporting, suggestion, coding).
<br>The features in this document have not been released yet. (2022-03-17)

## Requirement
- Server: A Wayne OS PC that runs _test_ version
- Client: A PC with ssh client feature (any OS is fine, but this document will explain with Linux shell)
- Check an IP address of the server and make sure the IP is reachable from the client (ex: `ping ${SERVER_IP}`)

## 1. Preparation
#### SSH
Setup and check [ssh connection](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/how-to/ssh_connection_from_remote.md).
#### Google ID
Temporary Google ID is recommended since this auto login feature is not secure, and it's convenient to use auto login, if you turn off 2-Step Verification for the Google ID.
#### GCP
#### Server
Turn on _Wayne OS test version_ and setup initial configuration (language/network/etc).

## 2. Remote login
#### Connect ssh from client to server.
~~~
$ sudo ssh ${SERVER_IP} "/usr/local/autotest/bin/autologin.py -u '${USER_ID}'"
Password:

...

Warning: Password input may be echoed.
Password:
~~~
- ${SERVER_IP}: The IP address of Wayne OS device (ex:192.168.0.100)
- ${USER_ID}: Google ID for login
- 1st Password prompt: _Wayne OS test_ version's shell password
- 2st Password prompt: Password for the Google ID 
#### Options with example
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


## Reference
https://chromium.googlesource.com/chromiumos/docs/+/main/tips-and-tricks.md#how-to-enable-a-local-user-account 


--------------
# bi_change.md
## Note
This document is looking foward to your contribution (documentation, translation, reporting, suggestion, coding).
<br>Wayne OS allows users/customers to change BI (brand idendity: logo, name) of Wayne OS, under [Terms of service](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/business/terms_of_service.md).

## Preparation
- Arrange your _png_ image files by referring to [chromiumos-assets](https://github.com/wayne-incorporated/wayne-os/tree/main/src/platform/chromiumos-assets) package.
- Check whether your image files' pixel size and name are same with the reference.

## Putting your BI in Wayne OS
- [login to console mode](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/how-to/using_shell.md).
- Remove the existing image files in 
<br>/usr/share/chromeos-assets/images
<br>/usr/share/chromeos-assets/images_100_percent
<br>/usr/share/chromeos-assets/images_200_percent
- Put your image files in the above path (via USB flash drive or ssh).
- Reboot and check the new BI.

--------------
# booting_wayne_os.md
## Note
This document is looking foward to your contribution (documentation, translation, reporting, suggestion, coding).

## 1. To enter BIOS/UEFI
- Check the connection of local disk or USB flash drive with Wayne OS installed when the PC is turned off
- Once the PC is turned on, press the BIOS/UEFI entrance key repeatedly, which varies depending on the PC model and manufacturer as per below example

| manufacturer     | Key    |
| ------ | ------ |
| HP     |  F1 / F2 / F6 / F10 / F11 / F12 / ESC |
| Dell   |  F1 / F2 / F3 / F12 / DEL / CTRL+ALT+ENTER / DEL+ESC / Fn+ESC / Fn+F1 |
| Lenovo |  F1 / F2 / F12 / Fn+F2 / Enter-F1 / CTRL+ALT+F3 / CTRL+ALT+INC / Fn+F1|
| Acer   |  F1 / F2 / F10 / DEL / CTRL+ALT+ESC |
| Asus   |  F2 / F10 / DEL / INSERT |
| Toshiba|  F1 / F2 / F12 / ESC |
| Samsung|  F2 |
| Sony   |  F1 / F2 / F3 / ASSIST |
| MSI    |  F2 / DEL |
| ASRock |  F2 / DEL |
| ECS    |  DEL |
| Gigatbyte/Aorus| F2 / DEL |
| MS Surface Tablets| Press and hold volume up button |
| Origin |  F2 |
| Zorac  |  DEL|
#### Alternative way to enter BIOS/UEFI with Windows10
- Navigate to **Settings** in Windows 10 start menu
<img src="resources/start_os1.png"  width="700" height="400">

- Click **Update & Security** in Windows Settings
<img src="resources/start_os2.png"  width="700" height="400">

- Select **Recovery** in the left pane
<img src="resources/start_os3.png"  width="700" height="400">

- Click **Restart now** under the Advanced startup header (computer will reboot)
<img src="resources/start_os4.png"  width="700" height="400">

- Click **Troubleshoot** in Choose an option with blue screen
<img src="resources/start_os5.jpg"  width="700" height="400">

- Click **Advanced options**
<img src="resources/start_os6.jpg"  width="700" height="400">

- Click **UEFI Firmware Settings**
<img src="resources/start_os7.jpg"  width="700" height="400">

- Click **Restart** to confirm
<img src="resources/start_os8.jpg"  width="700" height="400">

## 2. Setup BIOS/UEFI
- Once entering the BIOS/UEFI menu, set your USB flash drive into boot order number 1
<img src="resources/start_os9.png"  width="700" height="400">

- Turn off Secure Boot and Fast Boot
- Save your setting and reboot

## 3. Start OS
- Wayne OS splash screen will be displayed
- Once booting, configure language, accessibility, network
- Login with Google account or guest mode

## 4. Troubleshoot
- Update your BIOS/UEFI.
- If you still cannot boot the OS, please report on [known_issues.md](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/release/known_issues.md)


--------------
# initializing_usb_flash_drive.md
## Note
This document is looking foward to your contribution (documentation, translation, reporting, suggestion, coding).

## Windows
You can run Command Prompt as administrator.

![initialize_usb-1](resources/initialize_usb1.png)

Notes: 
FAT32/exFAT file systems are recommended for USB flash drives.
<br>
The FAT32 supports max 32GiB volume size and max 4GiB file size.
<br>
The exFAT supports over 32GiB volume size but it doesn’t work on Windows XP (need additional driver).

![initialize_usb-2](resources/initialize_usb2.jpg)

## Linux Shell, [Wayne OS Shell](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/how-to/using_shell.md)
First, remove partition table on your USB flash drive.
<br>
`sudo dd if=/dev/zero bs=512 count=4096 of=/dev/${USB_FLASH_DRIVE}`
<br>
The `${USB_FLASH_DRIVE}` must be a device name like sdx, Not a partition name like sdx1.
<br>
**Warning: If you write local storage (ex: hdd/ssd) name on it by mistake, you will lose data on the local storage so please check the name carefully by `lsblk`.**
<br>
<br>
Then you can make a new partition table, partition, and file system by your preferred tools. (ex: Gparted, parted, fdisk, gdisk, mkfs.fat, etc)


--------------
# installing_wayne_os_on_a_pc.md
## Note
This document is looking foward to your contribution (documentation, translation, reporting, suggestion, coding).
<br>Only _wayne-os-dev_ and _wayne-os-test_ versions support PC installation as _wayne-os-base_ version doesn't support it.

## 1. Preparation
- [Install](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/how-to/installing_wayne_os_on_a_usb_flash_drive.md) _wayne-os-dev_ or _wayne-os-test_ version on a USB flash drive.
- After booting Wayne OS by USB flash drive on a target PC, check whether it is up and running (check HW compatibilities, features, known issues)  
<p>If errors appear when you check, it means that the errors still exist even if you install OS on your PC. So if this happens, you should reconsider PC installation.
<br>FYI, Wayne OS STATE partition capacity will be increased as local disk capacity, after PC installation.

## 2. Installation
- [login to console mode](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/how-to/using_shell.md)
- Check the target disk name by `lsblk`
<br>**Note: Check _SIZE_ and _TYPE_ column in `lsblk` result, then select the target disk carefully.**
<br>**Select the exact disk name (ex: sda 8:0 0 59.6G 0 disk) instead of the partition name (ex: sda1 8:1 0 55.3G 0 part).**
<br>**Don't confuse the target disk with other local/removable disk. Every data on the target disk will be disappear after installation.**
- Type command `sudo /usr/sbin/chromeos-install --dst /dev/${TARGET_DISK}` 
<br>(ex: `sudo /usr/sbin/chromeos-install --dst /dev/sda`)
- Retype PW when the console asks for it
- After dozens of minutes, the installation is successful if you can see the `Installation to /dev/${TARGET_DISK} complete. Please shutdown, remove the USB device, cross your fingers, and reboot.` message
- Shutdown OS by `sudo poweroff`, remove USB flash drive, then [boot by target disk](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/how-to/booting_wayne_os.md)

## 3. Troubleshoot
- If you want to install Wayne OS on a removable disk, add `--skip_dst_removable`
<br> (ex: `sudo /usr/sbin/chromeos-install --skip_dst_removable --dst /dev/sda`)
- `sudo /usr/sbin/chromeos-install --help` shows more installation options
- `sudo dd if=/dev/zero bs=512 count=4096 of=/dev/${TARGET_DISK}` will remove a partition scheme and initialize the target disk


--------------
# installing_wayne_os_on_a_usb_flash_drive.md
## Note
This document is looking foward to your contribution (documentation, translation, reporting, suggestion, coding).

## 1. Preparation
- Windows/Linux/Chromebook PC with the same free disk space available as the OS image file
- A USB flash drive

## 2. [Download Wayne OS binary](http://wayne-os.com/download-wayne-os-binary/)

## 3. Initialize USB flash drive (optional)
- If your USB flash drive has an error/corruption, the installation process could fail
- [Initialize USB](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/how-to/initializing_usb_flash_drive.md)

## 4. Write .bin file on USB flash drive by image writer tool
### Windows user
- _USBWriter-1.3_: [download](https://sourceforge.net/projects/usbwriter/)
- _win32diskimager-binary_: [download](https://win32diskimager.download/)
- _Chromebook recovery utility_: [download](https://chrome.google.com/webstore/detail/chromebook-recovery-utili/jndclpdbaamdhonoechobihbbiimdgai/RK%3D2/RS%3DUI2uA8SxDAwF_T9oPb4YviZFT3Y-)
<br> click gear icon/setting on top right > use local image.
- _balenaEtcher-Portable-1.5.109_: This seems not working for Wayne OS installation perfectly
- _rufus-3.11_: This cannot install Wayne OS exactly

### Chromebook user
- _Chromebook recovery utility_: [download](https://chrome.google.com/webstore/detail/chromebook-recovery-utili/jndclpdbaamdhonoechobihbbiimdgai/RK%3D2/RS%3DUI2uA8SxDAwF_T9oPb4YviZFT3Y-)

### Linux user
`$ sudo dd if=${BIN_FILE} of=/dev/${USB_FLASH_DRIVE}`
<br>
`${BIN_FILE}` must be .bin file name like wayne-os-usb16g-1q21.bin.
<br>
`${USB_FLASH_DRIVE}` must be a device name like sdx, Not a partition name like sdx1.
<br>
**Warning: If you write local storage (ex: hdd/ssd) name on it by mistake, you will lose data on the local storage so please check the device name carefully by `lsblk`.**
<br>

## 5. Check
- If you install _wayne-os-portable_ version, you can see only a STORAGE partition in Windows/macOS if the installation is succeed
- Try to boot the USB flash drive on your computer via USB booting from BIOS/UEFI setting


--------------
# mode_change.md
## Note
This document is looking foward to your contribution (documentation, translation, reporting, suggestion, coding).
<br>TO-DO: This document requires contributions about useful Chromium flags.
<br>The features in this document have not been released yet. (2022-03-17)
 
## Accessing to chrome_dev.conf
- [login to console mode](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/how-to/using_shell.md).
- Type command `/usr/sbin/mode_change-wayneos` (requires sudo pw).
- Reboot OS after modify the _chrome_dev.conf_.

#### Switching on flag:
1. Select flags in the _chrome_dev.conf_. 
2. Delete the sharp (#) which is ahead of the flag (Don't remove the sharp which is ahead of the explanation).
3. Add an argument, if the flag requires it.
#### Switching off flag:
1. Write a sharp mark (#) ahead of the flag.

## Useful flag set
#### For kiosk
- --kiosk: UI will be locked except web browser.
- --start-fullscreen: Web browser will be opened with full screen.
- --enable-virtual-keyboard: For touch screen.
#### For public PC
- --incognito: Web browser will be started with incognito mode.


--------------
# setup_os.md
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


--------------
# signing_in_google_account_in_wayne_os.md
## Note
This document is looking foward to your contribution (documentation, translation, reporting, suggestion, coding).

## Joining Google Groups
In order to login to Wayne OS by Google account, you have to add the account to Google's whitelist.
1. Login to your Google account.
2. Visit https://groups.google.com/u/0/a/chromium.org/g/google-browser-signin-testaccounts
3. Press _Join group_ button
4. Login with your Google account in Wayne OS.

## Note
Above method is for test purposes and managed by Google officially. 
<br>
However, It doesn't mean that you can use all of Google services since Google restricts/controls third-parties of open source.
<br>

## Reference 
https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/business/googles_restriction_for_chromium_and_chromium_os.md
<br>
https://www.chromium.org/developers/how-tos/api-keys


--------------
# ssh_connection_from_remote.md
## Note
This document is looking foward to your contribution (documentation, translation, reporting, suggestion, coding).

## Requirement
- Server: A Wayne OS PC that runs _dev_ or _test_ version
- Client: A PC with ssh client feature (any OS is fine, but this document will explain with Linux shell)
- Check an IP address of the server and make sure the IP is reachable from the client (ex: `ping ${SERVER_IP}`)

## Wayne OS dev version
#### Connect to server from client
ID: chronos
<br>PW: _wayne-os-dev_ version's password
- For example:
~~~
$ ssh chronos@192.168.140.172
Password:
~~~
#### Ommiting PW 
TODO: write

## Wayne OS test version
#### 1. Setup on client
First, download the testing RSA keys and configuration files into ~/.ssh/
~~~
$ cd ~/.ssh && wget \
https://gitlab.com/wayne-inc/wayne_os/-/raw/master/cros-src/cros_sdk/src/scripts/mod_for_test_scripts/ssh_keys/testing_rsa \
https://gitlab.com/wayne-inc/wayne_os/-/raw/master/cros-src/cros_sdk/src/scripts/mod_for_test_scripts/ssh_keys/testing_rsa.pub \
https://gitlab.com/wayne-inc/wayne_os/-/raw/master/cros-src/cros_sdk/src/scripts/mod_for_test_scripts/ssh_keys/config
~~~
Then restrict the permissions on ~/.ssh/testing_rsa
~~~
$ chmod 0600 ~/.ssh/testing_rsa
~~~
And replace _000.000.000.000_ to IP address of the client, in _config_ file by editor.
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
#### 2. Connect to server from client
~~~
$ ssh wayne-os
~~~
Then you will get a root-shell without password.
<br>If connect to multiple servers, you can share common config options in your ~/.ssh/config.
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

## Reference
https://www.chromium.org/chromium-os/testing/autotest-developer-faq/ssh-test-keys-setup



--------------
# using_shell.md
## Note
This document is looking foward to your contribution (documentation, translation, reporting, suggestion, coding).

## Requirement
Shell is only available in _wayne-os-dev_ and _wayne-os-test_ versions as _wayne-os-base_ version doesn't support it.

## Console
Switching to console mode: `ctrl+alt+f2`
<br>
Switching to GUI mode: `ctrl+alt+f1`

## Terminal
First, you need to login in GUI or enter Guest Mode.
<br>
Opening terminal: `ctrl+alt+t`
<br>
Opening shell: `crosh> shell`

## ID & PW
- dev version
    - ID: `chronos`
    - PW of chronos/sudo: `same with hostname` (ex: _wayne-os-1q21_)
- test version
    - ID: `chronos`
    - PW of chronos/sudo: `test0000`

## Changing PW
TODO: write
