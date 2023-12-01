# Running detachable base fw tests

FAFT is currently not supported for detachable base tests because it does not
support two ECs on the same device.
[Tracking bug](https://issuetracker.google.com/36075961). Because of this,
the firmware tests for detachable bases were written as scripts that need to be
manually run on the DUT. Setting up and running the tests takes approximately
1-2 hours and keyboard EC firmware updates are fairly infrequent
(once a year on average pre-FSI, and ~once post-FSI).

[TOC]

# Prepare Host and DUT

Tests already come installed in the DUT ChromeOS test image at
`/usr/local/bin/hammertests`. Before you start, ensure that the test folder
exists in the test image.

A list of current devices with detachable base mappings is as follows:

|       Device         |Detachable keyboard            |
|----------------------|-------------------------------|
|Poppy                 |Hammer
|Soraka                |Staff
|Nocturne              |Whiskers
|Krane                 |Masterball
|Kodama                |Magnemite
|Kakadu                |Moonball
|Katsu                 |Don
|CoachZ                |Zed
|Homestar              |Star
|Wormdingler           |Eel
|Quackingstick         |Duck

## On Host

1.  Create a [chroot](https://chromium.googlesource.com/chromiumos/docs/+/HEAD/developer_guide.md#Create-a-chroot)
from [ToT checkout](https://chromium.googlesource.com/chromiumos/docs/+/HEAD/developer_guide.md#Get-the-source-code).

2.  Obtain the images that will be used in the tests. Obtain the base ec image
from GoldenEye/ BCS/ APFE.
[Usually the dev will have supplied the image in the testing request bug or
indicated where to download it from, because these tests are typically run
before RO is locked in the firmware branch].

3.  Select build # you want to test.

4.  Select board name.

5.  Download the `firmware_from_source.tar` file and unzip.

6.  Change directory into the unzipped folder then cd into the base ec firmware
folder (e.g. staff).

7.  Inside the base ec firmware folder, copy `ec.bin` into the
chroot created in step 1. You can rename this file if you wish
to indicate that it’s base firmware e.g. `staff_ec.bin`.

8.  Flash the keyboard EC with the image obtained in step 2, following the steps
in this [document](https://chromium.googlesource.com/chromiumos/platform/ec/+/HEAD/docs/hammer.md#Flash-EC)

9.  Generate the images needed for tests, from the base ec image obtained in
step 5 following the steps below:

    a.   **Inside chroot**: Run the shell script
    [gen_test_images.sh](https://chromium.googlesource.com/chromiumos/third_party/autotest/+/HEAD/server/cros/faft/gen_test_images.sh) that generates the necessary
    images, supplying ec.bin as the first argument for the BOARD name
    (where board is the name of the detachable base) and the IMAGE name as
    the second argument e.g. for staff:

        ~/chromiumos/src/third_party/autotest/files/server/cros/faft/gen_test_images.sh staff staff_ec.bin

    **The above script needs to run inside chroot of the DUT host**

    *For devices without fingerprint sensor, if you see error message like `Unable to open
    /mnt/host/source/src/third_party/autotest/files/server/cros/faft/fingerprint_dev_keys/magnemite/dev_key.pem`,
    please create a symlink from any existing key to the missing path manually.*

    Ensure that the ec.bin image used above is the same image running on the
    base ec of the DUT. If they are different, RW verification will fail
    during testing.

    You should then see the following 17 images created:

    1.  EC_RW.bin
    2.  staff_corrupt_first_byte.bin
    3.  staff.dev.hex
    4.  staff.dev.rb9
    5.  key.vbprik2
    6.  staff_corrupt_first_byte.bin.hex
    7.  staff.dev.rb0
    8.  staff.dev.rb9.hex
    9.  key.vbpubk2
    10. staff_corrupt_last_byte.bin
    11. staff.dev.rb0.hex
    12. staff.bin
    13. staff_corrupt_last_byte.bin.hex
    14. staff.dev.rb1
    15. staff.bin.hex
    16. staff.dev
    17. staff.dev.rb1.hex

    There is one image file that must be **manually** included in the images
    folder. For first-time firmware qualification e.g. of a new keyboard,
    include a copy of the firmware and name it `BASE_NAME_older.bin` where
    BASE_NAME is the keyboard name e.g. `staff_older.bin`.
    For revised firmware qualifications i.e. qualifying new version of
    RO/RW but not the first RO/RW, include an image of the older firmware
    and also name it `BASE_NAME_older.bin`. The image
    `BASE_NAME_older.bin` is used to test that RW updates can happen with
    the new firmware. In the case of first time firmware, the tests still
    check that RW region is updatable even though the older image is the
    same as the newer image.

    b. Copy the new images folder in your chroot into the DUT from the host
    via ssh (ensure ssh test keys are added to the shell window first):

        scp -r images root@dut.ip.address:/usr/local/bin/hammertests

## On DUT

Flash the DUT with a test ChromeOS image. The test image already has the base
tests in the folder `/usr/local/bin/hammertests`, You should see the
following tests.

1.  flash_wrong_address.py
2.  rb_protection.py
3.  rb_rw_protected.py
4.  ro_boot_valid_rw.py
5.  ro_stay_ro.py
6.  ro_update_rw.py
7.  rw_no_update_ro.py
8.  transfer_touchpad_works.py
9.  verify_pairing.py

You should also see the following control files

1.  hammertests_control.py
2.  hammertests_control_rb.py
3.  hammertests_control_tp.py

# Test Execution

To run the tests, simply run each of the **control files** in the DUT from the
`/usr/local/bin/hammertestsi` directory. You can do this directly on the DUT or
ssh via the host. E.g.

    ./hammertests_control.py

Each control file runs a number of tests, and creates log folders corresponding
to each of the tests outlined above. Some tests have several iterations.

|       Control file   |Tests executed                 |
|----------------------|-------------------------------|
|hammertests_control.py|flash_wrong_address.py
|                      |rb_rw_protected.py
|                      |ro_boot_valid_rw.py
|                      |ro_stay_ro.py
|                      |ro_update_rw.py
|                      |rw_no_update_ro.py
|                      |verify_pairing.py


Image that should be flashed on DUT for hammertests_control.py:
`$BASE_NAME_ec.bin` *(locked)*.
This **locked** image should be supplied by the dev who requests the testing and
attached in the testing request bug.

|       Control file     |Tests executed      |
|------------------------|--------------------|
|hammertests_control_rb.py|rb_protection.py

Image that should be flashed on DUT for hammertests_control_rb.py:
`$BASE_NAME.dev.rb1` *(rollback version = 1)*.
This image is in the ‘images’ folder which is generated by the script
[gen_test_images.sh](https://chromium.googlesource.com/chromiumos/third_party/autotest/+/HEAD/server/cros/faft/gen_test_images.sh)

|       Control file      |Tests executed             |
|-------------------------|---------------------------|
|hammertests_control_tp.py|transfer_touchpad_works.py

Image that should be flashed on DUT for hammertests_control_tp.py:
`$BASE_NAME_ec.bin` *(unlocked)*.
This **unlocked** image should be supplied by the dev who requests the testing
and attached in the testing request bug.

After running all the tests, **attach the log files** to the request bug.

# Manual Tests

## RO cannot update RW with dev signed image:

-   Flash the image `staff.dev` generated by ./genimages_staff.sh and verify on
the ec console that RW update fails due to failed signature verification.

## Keyboard

-   Run command `evtest` on DUT and check that each key works.

-   (Vivaldi keyboard only) Check that function key works in Chrome.
Use a web page like
[keyboard event viewer](https://w3c.github.io/uievents/tools/key-event-viewer.html)
to verify that Chrome can detect F1~F10 by pressing search + top row keys.

### Keyboard backlight works

-   Can control backlight using:

        echo $VALUE > /sys/class/leds/hammer::kbd_backlight/brightness

-   Or via powerd:

        backlight_dbus_tool --increase_keyboard

Keyboard backlight not advertised on SKUs where backlight not available

Implemented here: https://issuetracker.google.com/67722756.

TODO(drinkcat): give system path to keyboard backlight to distinguish devices
that have backlight support from those that don't

## Touchpad

### Touchpad works

Needed:

-   Base running RW version b under test with touchpad FW v2

Steps:

-   Manual testing

-   Check that touchpad works

-   1 to 5 finger swipes

-   Click using touchpad works

### I2C passthrough interface does not work

(to be active only when WP is off, for Elan usage)

-   WP on, cannot update the touchpad FW over I2C

        ec_touchpad_updater -f FW_IMAGE

-   WP off (through servo or physically remove the screw), can update the
touchpad FW over I2C:

        ec_touchpad_updater -f FW_IMAGE

## Touchpad dimensions are correct

No errors of this kind in EC console:

    [1.430530 reset rv 0 buf=0000]
    [1.432640 max=3206/1832 width=124/124 adj=0 dpi=800/800]
    *[1.432948 *** TP mismatch!]*
    [1.433585 elan_tp_init:0]

See https://issuetracker.google.com/67982128 for example.

We only really need to test for version update when we release new TP firmware
