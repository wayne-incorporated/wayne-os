# Readme

This package builds the audio topology binary required to hear sound on your
Chromebook from the public bxt_i2s.conf source file.

The default implementation created here is *not* fully equivalent to the binary
that gets used in production devices, but can be easily modified to use the
production binary.

## Known issues
  - Speaker is very loud (i.e. use at your own risk)
  - Headset is not working

## Recommended workaround

It is possible and recommended to install the original audio topology binary
that is being used in mass production of your device and that the audio system
has been tuned with.

In order to do so follow these steps:
  1. Enable [developer
mode](http://www.chromium.org/chromium-os/chromiumos-design-docs/developer-mode)
on your chromebook
  1. Copy the original topology file from /lib/firmware/dfw_sst.bin to a USB
     drive
  1. Copy the dfw_sst.bin from the USB drive into the overlay's
     media-libs/lpe-support-topology/files folder on your system containing the
     Chromium OS source code
  1. Set the USE="original_device_topology_bin" flag either on the command line
     or by adding it to the overlay's profile/base/make.defaults.
