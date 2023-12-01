# Getting started

The scope of this document is to provide a guide on how to setup your DUT with
hiberman (hibernate service).

## Prerequisites

1. Have a **brya** board DUT.
1. Desktop with cros_sdk setup.
1. (necessary for old DUTs) 8GiB+ USB drive.

## Setup
1. Place Brya in *developer mode* by following [these instructions](https://chromium.googlesource.com/chromiumos/docs/+/main/debug_buttons.md#firmware-keyboard-interface):
    * Hold ESC+Refresh, press power button.
    * When asked, select Ctrl+D for developer mode.
    * Select *confirm* then *Boot from internal disk*.
    * Wait for the machine to transition to developer mode and reboot.

1. Option 1: Install brya-hibernate/latest
    * Bring up a console window pressing *Ctrl+Alt+Refresh*.
    * Login as a user *root*, password *test0000*.
    * Run the command:
      ```
      (dut)# /sbin/pvs
      ```
      If output result is empty, go to Setup step no.3. Otherwise, continue.
    * Plug the Taeko to the lab network and obtain it's DUT_IP address
      (using ifconfig).
    * Run the command:
      ```
      (desktop/outside)# cros flash ssh://{DUT_IP} brya-hibernate-latest
      ```
    * Once installation is complete, DUT reboots.
    * Go to Setup step no.4.

1. Option 2: Install brya-hibernate/latest with USB.
    * Insert the USB drive to the desktop.
    * Run the command:
      ```
      (desktop/outside)# cros flash usb:// brya-hibernate-latest[/test]
      ```
    * Select the correct USB device and flash the drive.
    * Remove the USB drive from the desktop.
    * Insert the USB drive to the DUT.
    * Restart the DUT and select *Boot from external disk*.
    * Login as a user *root*, password *test0000*.
    * Run the command:
      ```
      (dut)# /usr/sbin/chromeos-install
      ```
    * Once installation is complete, shutdown the DUT
    * Remove the USB drive from the DUT.

1. Start the DUT and select *Boot from internal disk*.

1. (not required for test images) Remount filesystem as a read-write:
    * Bring up a console window pressing *Ctrl+Alt+Refresh*.
    * Login as a user *root*, password *test0000*.
    * Run the commands:
      ```
      (dut)# /usr/share/vboot/bin/make_dev_ssd.sh --remove_rootfs_verification --partitions 2
      (dut)# reboot
      (dut)# /usr/libexec/debugd/helpers/dev_feature_ssh
      ```

## Verification

After a successful setup, the DUT should be running with the latest
brya-hibernate image.

To verify, you can enter the console and run the command:
```
(dut)# hiberman --help
(dut)# status hiberman
hiberman start/running, process XXXX
```

### FAQ

1. Cros flash fails to SSH.
    * Can you ping the DUT?
    * Can you ssh to the DUT?
        * Do you have fresh gcert?
        * Is SSH enabled on the dut?
1. Cros flash fails on fetching the image.
    * Run the command:
      ```
      (desktop/outside)# gsutil config
      ```
1. Can't I just build the image myself?
Yes you can, using:
```
  setup_board \
    --force \
    --board=brya-hibernate \
  && \
  USE="pcserial kgdb vtconsole" build_packages \
    --board=brya-hibernate \
    --autosetgov \
  && \
  build_image \
    --enable_serial=ttyS0 \
    --board=brya-hibernate \
    --noenable_rootfs_verification test \
    --replace
```
