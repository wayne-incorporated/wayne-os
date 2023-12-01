# Termina

## Overview
The `project-termina` encompasses the majority of functionality for Termina.
Architecture-dependent leaf overlays should inherit from this overlay.
Currently, these are `tatl` (`x86_64`) and `tael` (`arm64`).

## Packages

### `chromeos-base/chromeos-bsp-termina`
Installs files required for basic VM functionality.

### `chromeos-base/termina-auth-config`
Sets up PAM to allow root/chronos passwordless login. By default this is only
installed by `target-termina-os-dev`, meaning that only dev or test images will
get this functionality.

### `chromeos-base/termina-lxd-scripts`
Installs convenience wrapper scripts for setting up the stateful disk image,
lxd's initial configuration, and for starting a container with lxd.

### `virtual/target-os*`
These override the normal Chromium OS targets to either no-op (e.g. the factory
shim) or depend on the corresponding `termina` equivalent.

### `virtual/target-termina-os*`
The `termina` target ebuilds should depend on packages for the appropriate
target. Release images will work with just `target-termina-os`, but
developers will likely want to include `target-termina-os-dev` as well to
enable serial console support and allow login.

## Building
Termina images are currently repacked from a normal Chromium OS disk image. An
example invocation of the repacking script is below.

```sh
export BOARD=tatl
./build_packages --board=${BOARD} --nowithautotest
./build_image --board=${BOARD} --noenable_rootfs_verification test
sudo ../platform/container-guest-tools/termina/termina_build_image.py \
  ../build/images/${BOARD}/latest/chromiumos_test_image.bin ${BOARD}
```

At this point, the output directory will have (among others), the
following files:
* `vm_kernel` - A kernel suitable booting with crosvm.
* `vm_rootfs.img` - The rootfs for the VM.

## Running
Please refer to crosvm documentation on how to run the kernel and rootfs.

To use a custom image with concierge:

```sh
# Copy the rootfs and kernel to a working directory on the device, such as
# /usr/local/tatl.
# Then, make this visible to concierge.
mkdir /run/imageloader/cros-termina/99999.0.0
mount --bind /usr/local/tatl /run/imageloader/cros-termina/99999.0.0
restart vm_concierge
```
