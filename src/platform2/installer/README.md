# Chromium OS Installer

Files in this folder will be compiled by `chromeos-base/chromeos-installer`
package into few programs, including:

- `chromeos-install`: A shell script for manual installation from USB.
- `chromeos-install-kernel`: A script which installs kernel and kernel modules
  from USB.  This script is used by ChromeOS kernel developers to recover
  from bad kernel updates.
- `chromeos-recovery`: The main command for recovery shim to install image.
- `chromeos-postinst`: The script executed by auto update or recovery shim after
    image installation is completed, being the symbolic link of `/postinst`.
- `cros_installer`: A program meant to be the backend of above commands (but it
    currently only supports post-install).

## Full Installation
When installing manually from USB or from recovery shim, the procedure is:
1. `chromeos-install` is invoked by either manually or `chromeos-recovery`.
2. The script will re-create partition table on target storage device.
3. The script will clone all partitions (stateful, rootfs, kernel, OEM, etc...).
4. Start post-install (see below) from `/postinst` of new rootfs.

## Auto Update Installation
Auto update (via `update_engine`) is slightly different. After the payload is
downloaded, `update_engine` will try to apply the payload (may be full or
partial), then invoke the post-install from new rootfs.

## Post Install
After the new image is written to disk storage, there may be several steps to
activate the new partition. This is done by `cros_installer` as:

1. Rebuild 'verity' information. To reduce download size, the payload from auto
   update won't include verity hash data because that can be re-constructed.
   In this step the post-install program will read, verify, and regenerate hash
   data for the rootfs partition.
2. Update GPT entries to set proper boot priorities on the new kernel partition.
3. For legacy systems, update EFI or `syslinux` entries.
4. Run a per-board post install script `/usr/sbin/board-postinst` if it exists.
   The script is usually installed by `chromeos-base/chromeos-bsp-$BOARD`
   or `chromeos-base/chromeos-firmware-$BOARD` in board overlays.
5. Apply firmware update by running `/usr/sbin/chromeos-firmwareupdate
   --mode=autoupdate` if the signing signature (`/root/.force_update_firmware`)
   is available. The special signature is needed to prevent unexpected firmware
   updates from self-built USB images.
6. Apply Cr50 firmware updates if available (error will be ignored).
7. Any other misc housekeeping work. Consult `ChromeosChrootPostinst` for
   further details.

To make sure the new kernel and rootfs is bootable, the GPT boot priority may be
set with few "try" attempts so the system will revert to the old partition when
running out of "tries".

If the new kernel and rootfs boots, the `update_engine` will wait for 60 seconds
and then:

1. Invoke `chromeos-setgoodkernel`, to update partition records and mark current
   kernel as "good" for future reboots.
2. Invoke `chromeos-setgoodfirmware` to mark active firmware as "good" as well.
   At the end of `chromeos-setgoodfirmware`, it will also invoke
   `/usr/sbin/board-setgoodfirmware` for board specific configuration if
   available. The `board-setgoodfirmware` is usually provided by
   `chromeos-base/chromeos-firmware-$BOARD` package.

In summary, if you want to add some board specific task:
- To run on every boot, do it in `/usr/sbin/board-setgoodfirmware`.
- To run only after each AU or recovery, do it in `/usr/sbin/board-postinst`.
