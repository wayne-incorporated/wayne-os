# Fingerprint Study Tool

The fingerprint study tool allows you to capture raw fingerprint samples from
study participants in order to analyze the performance of a fingerprint system.

<!-- mdformat off(b/139308852) -->
*** note
See [Typography conventions] to understand what `(outside)`, `(inside)`,
`(in/out)`, and `(device)` mean.
***
<!-- mdformat on -->

## Install/Run Fingerprint Study

1.  You can either install the fingerprint_study package on a chromebook in dev
    mode (**Option 1**) or build+flash a custom chrome os image with the
    fingerprint_study package preinstalled (**Options 2**).

    On the host, run the following commands:

    -   **Option 1**

        ```bash
        (inside) $ BOARD=hatch
        (inside) $ DUT=dut1
        (inside) $ emerge-$BOARD fingerprint_study
        (inside) $ cros deploy $DUT fingerprint_study
        ```

    -   **Option 2**

        ```bash
        (inside) $ BOARD=hatch
        (inside) $ USE=fpstudy ./build_packages --board=$BOARD
        (inside) $ ./build_image --board=$BOARD --noenable_rootfs_verification \
                   base
        (inside) $ cros flash usb:// $BOARD/latest
        ```

        Insert the USB flash drive into the chromebook
        [boot from USB][boot-from-usb] and then
        [install the image][install-from-usb].

2.  Configure `FINGER_COUNT`, `ENROLLMENT_COUNT`, and `VERIFICATION_COUNT` in
    [/etc/init/fingerprint_study.conf](init/fingerprint_study.conf) with the
    proper fingerprint study parameters.

3.  Reboot the device.

4.  Navigate to http://127.0.0.1:9000 in a web browser.

5.  Output fingerprint captures are stored by default in `/var/lib/fingers`. See
    [/etc/init/fingerprint_study.conf](init/fingerprint_study.conf).

[boot-from-usb]:
https://chromium.googlesource.com/chromiumos/docs/+/HEAD/developer_guide.md#boot-from-your-usb-disk
[install-from-usb]:
https://chromium.googlesource.com/chromiumos/docs/+/HEAD/developer_guide.md#installing-your-chromium-os-image-to-your-hard-disk

## Test on Host Using Mock ectool

We will use a python virtual environment to ensure proper dependency versions
and a mock `ectool` in [mock-bin](mock-bin). Note, the mock ectool will
effectively emulate an immediate finger press when the study tool requests a
finger press. This does not make use of the FPC python library.

1.  Run the following command:

    ```bash
    (in/out) $ ./host-run.sh
    ```

2.  Finally, navigate to http://127.0.0.1:9000 in a web browser.

## Setup GPG Encryption

The keys generated here are strictly for transmission and retrieval of data for
a single Fingerprint Study run.

### Generating Keys

Setting `GNUPGHOME` will force gpg to use a completely different keyring/config.
In this case, we set it to an empty directory `/tmp/fpstudygpg`, where we will
build a new keyring with only one key pair.

```bash
# Setup a new empty GNUPG directory.
(in/out) $ export GNUPGHOME=/tmp/fpstudygpg
(in/out) $ gio trash -f "${GNUPGHOME}" \
           && mkdir -p "${GNUPGHOME}/private-keys-v1.d" \
           && chmod -R 700 "${GNUPGHOME}"
# Setup key generation parameters.
# https://www.gnupg.org/documentation/manuals/gnupg/Unattended-GPG-key-generation.html
(in/out) $ cat >keyparams <<EOF
    %echo Generating key.
    Key-Type: RSA
    Key-Length: 4096
    # Disable subkey generation, since this is a one time use key pair anyways.
    # Subkey-Type: RSA
    # Subkey-Length: 4096
    Name-Real: ChromeOSFPStudy
    Name-Comment: Chrome OS Fingerprint Study Key
    Name-Email: <FILL_IN_RECIPIENT_EMAIL>
    Expire-Date: 0
    # Passphrase: <IF_UNCOMMENTED_THIS_IS_THE_PASSWORD>
    %ask-passphrase
    # %no-ask-passphrase
    # %no-protection
    %commit
    %echo Done.
EOF
# Generate a new key pair. Make note of the password used. This password is used
# to protect the private key and will be required when decrypting the captures.
(in/out) $ gpg --verbose --batch --gen-key ./keyparams
# Record the fingerprint/keyid from by the following command.
# The fingerprint is the 40 hex character string grouped into 10 groups of
# 4 characters. Remove the spaces from this fingerprint to form the keyid.
(in/out) $ gpg --fingerprint ChromeOSFPStudy
# Export only the public key for the test device. This key must be copied to the
# test device and will be used as the keyring.
(in/out) $ gpg --verbose --export ChromeOSFPStudy > "${GNUPGHOME}/chromeos-fpstudy-public-device.gpg"
# Export the private key for backup. This key is for the recipient to be able
# to decrypt the fingerprint capture.
# This key must NOT be copied to the test device.
(in/out) $ gpg --verbose --export-secret-keys ChromeOSFPStudy > "${GNUPGHOME}/chromeos-fpstudy-private.gpg"
```

### Install Keys on Device

*   Copy the `chromeos-fpstudy-public-device.gpg` file to the test device.

    ```bash
    scp "${GNUPGHOME}/chromeos-fpstudy-public-device.gpg" \
      dut1:/var/lib/fpstudygnupg
    ssh dut1 chmod u=r,g=,o= \
      /var/lib/fpstudygnupg/chromeos-fpstudy-public-device.gpg
    ```

*   Edit the `/etc/init/fingerprint_study.conf` file to have the following
    additional arguments to `exec study_serve`.

    -   `--gpg-keyring /var/lib/fpstudygnupg/chromeos-fpstudy-public-device.gpg`
    -   `--gpg-recipients KEYID` where KEYID is the keyid recorded in the
        `Generating Keys` section.

### Test Encryption Manually

Follow the `Generating Keys` section and then run the following commands:

```bash
(in/out) $ GNUPGHOME_KEYGEN=/tmp/fpstudygpg
# Unfortunately, you still need a proper homedir for gpg to work.
(in/out) $ export GNUPGHOME=/tmp/fpstudygpg-host
(in/out) $ gio trash -f "${GNUPGHOME}" \
             && mkdir -p "${GNUPGHOME}/private-keys-v1.d" \
             && chmod -R 700 "${GNUPGHOME}"

# Test encrypting a sequence of numbers using only the public key.
(in/out) $ gpg --verbose --no-default-keyring \
             --keyring \
             "${GNUPGHOME_KEYGEN}/chromeos-fpstudy-public-device.gpg" \
             --trust-model always \
             -ear ChromeOSFPStudy > test-output.gpg < <(seq 10)
(in/out) $ file test-output.gpg
(in/out) $ gpg --list-packets test-output.gpg

# We will now import the private key to our clean GNUPHHOME.
# In order to test the above encryption step again, you would need to
# clear the GNUPGHOME directory (run these test instructions from the top).
(in/out) $ gpg --import "${GNUPGHOME_KEYGEN}/chromeos-fpstudy-private.gpg"
# The following should yield a sequence of number from 1 to 10.
(in/out) $ gpg -d test-output.gpg
```

### Test Encryption Using Host

Follow the `Generating Keys` section and then run the following commands:

```bash
(in/out) $ ./host-run.sh \
             --gpg-keyring "${GNUPGHOME}/chromeos-fpstudy-public-device.gpg" \
             --gpg-recipients ChromeOSFPStudy
```

### Decrypting Fingerprint Captures

To decrypt the fingerprint captures on the receiving/host side, you must import
the private key `chromeos-fpstudy-private.gpg` generated above in the
`Generating Keys` section.

<!-- mdformat off(b/139308852) -->
*** note
If you do not want to import the private key into your normal gpg homedir, you
can run the following to create a temporary gpg homedir:

```bash
(in/out) $ export GNUPGHOME=/tmp/fpstudygpg-host
(in/out) $ gio trash -f "${GNUPGHOME}" \
           && mkdir -m 700 -p "${GNUPGHOME}/private-keys-v1.d"
```
***
<!-- mdformat on -->

```bash
# Import the private key into the current gpg homedir.
(in/out) $ gpg --import chromeos-fpstudy-private.gpg
# Decrypt all fingerprint captures, while place the decrypted file version
# alongside the encrypted version.
(in/out) $ find ./fpstudy-fingers -type f -name '*.gpg' | \
             xargs -P $(nproc) gpg --decrypt-files
```

--------------------------------------------------------------------------------

## Running Fingerprint Study Using Python Virtualenv

This is an **alternative method** to install the fingerprint study tool on a
test device. It bypasses the Chrome OS/Gentoo dependencies and allows using
providing a clean virtualenv for the execution on the test device.

### 1) Build python3 virtual environment bundle

```bash
# Optionally, you can build the virtual environment in a Docker container.
# docker run -v$HOME/Downloads:/Downloads -it debian
# On Debian, ensure that git, python3, python3-pip, and virtualenv are installed.
(outside) $ sudo apt update && apt install git python3 python3-pip virtualenv
# Grab the fingerprint study tool source
(outside) $ git clone https://chromium.googlesource.com/chromiumos/platform2
# Create an isolated python3 environment
(outside) $ virtualenv -p python3 /tmp/fpstudy-virtualenv
(outside) $ . /tmp/fpstudy-virtualenv/bin/activate
# Install fingerprint study dependencies
(outside) $ pip3 install -r platform2/biod/study/requirements.txt
# Copy the fingerprint study source
(outside) $ cp -r platform2/biod/study /tmp/fpstudy-virtualenv
# Bundle the virtual environment with study source
(outside) $ tar -C /tmp -czvf /tmp/fpstudy-virtualenv.tar.gz fpstudy-virtualenv
# For Docker with Downloads volume shared, run the following command:
# cp /tmp/fpstudy-virtualenv.tar.gz /Downloads/
```

The output of these steps is the `fpstudy-virtualenv.tar.gz` archive.

### 2) Enable developer mode on the chromebook

See [Enable Developer Mode].

### 3) Install python3 virtual environment bundle

Transfer the `fpstudy-virtualenv.tar.gz` bundle to the test device.

One such method is to use scp, like in the following command:

```bash
(in/out) $ scp fpstudy-virtualenv.tar.gz root@$DUTIP:/root/
```

On the test device, extract the bundle into `/opt/google`, as shown in the
following command set:

```bash
(device) $ mkdir -p /opt/google
(device) $ tar -xzvf /root/fpstudy-virtualenv.tar.gz -C /opt/google
```

Enable the fingerprint study Upstart job.

```bash
(device) $ ln -s /opt/google/fpstudy-virtualenv/study/fingerprint_study_virtualenv.conf /etc/init
(device) $ start fingerprint_study_virtualenv
(device) $ sleep 2
(device) $ status fingerprint_study_virtualenv
```

### 4) Configure

To configure the number of fingers, enrollment taps, and verification taps
expected by the fingerprint study tool, please modify
`/opt/google/fpstudy-virtualenv/study/fingerprint_study_virtualenv.conf`.

### 5) Test

Navigate to http://127.0.0.1:9000 in a web browser.

[Enable Developer Mode]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/developer_mode.md#dev-mode
[Typography conventions]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/developer_guide.md#typography-conventions
