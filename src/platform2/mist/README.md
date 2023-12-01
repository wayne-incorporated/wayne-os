# mist: Modem Interface Switching Tool

## Overview

`mist` is a Chromium OS utility for switching USB cellular dongles into the
modem mode. A cellular dongle may implement multiple functions and the function
exposed by its initial USB configuration may not be a modem. We need to switch
the device into a modem before it can be detected and managed by
[ModemManager](https://www.freedesktop.org/wiki/Software/ModemManager) to
provide cellular connectivity.

`mist` is activated by udev events. When udev detects a supported dongle, it
invokes `mist` to switch the dongle into the modem mode. The mode switching
operation invokes the following:
- Open the USB device associated with the dongle. If the device has a USB
  configuration that exposes a MBIM interface, select that configuration and
  complete the switch operation. Otherwise, find and claim the mass storage
  interface of the device.
- Initiate a bulk output transfer of a (or multiple) special USB message(s) to
  the mass storage endpoint of the device.
- On some devices, a bulk input transfer from the mass storage endpoint of the
  device is expected after completing each bulk output transfer.
- Once the transfer of the last message completes, the device is expected to
  disconnect from the USB bus and then reconnect to the bus after it has been
  switched to the modem mode. The device may change its USB vendor ID and
  product ID (mostly the latter) after the switch operation.


## Device Detection

`mist` relies on udev to detect when a dongle is plugged into the system. A
udev rules file, [`/lib/udev/rules.d/51-mist.rules`](51-mist.rules), is used to
identify a supported dongle based on its USB vendor ID and product ID before
and after mode switching. Upon detecting a supported dongle in the non-modem
mode, udev launches a mist process to switch the dongle into modem, and also
tags the dongle as `MIST_SUPPORTED_DEVICE=1`, which allows cros-disks to
filter out the mass storage exposed by the dongle.

After udev launches the `mist` process, `mist` daemonizes itself so that it can
use libudev to monitor the status of the mode switching via udev events. After
the special USB messages are sent to the mass storage interface of the dongle,
the dongle detaches itself from USB, which results in a udev remove event.
After the dongle switches into the modem mode, it reattaches to USB, which
results in a udev add event.


## Configuration File

`mist` uses a protobuf-based configuration file,
[`/usr/share/mist/default.conf`](default.conf), to specify information about
the supported dongles. The configuration file specifies a list of supported
dongles and the following information associated with each dongle:
- Initial USB vendor and product ID of the modem when it is in the mass storage
  mode.
- A list of possible final USB vendor and product IDs of the modem after it has
  switched to the modem mode.
- A list of USB messages, in form of hexadecimal strings, to send to the mass
  storage interface of the modem in order to switch the modem to the modem
  mode.
- An optional flag to indicate whether a response is expected from the mass
  storage interface after sending each USB message to the interface.
- An optional initial delay, in milliseconds, that mist should wait before
  starting the modem switch operation.


## USB Communications

`mist` uses libusb 1.x API to retrieve the USB descriptors of the dongle and
initiate bulk transfers to the mass storage interface of the dongle. It thus
needs to have read and write access to the USB device associated with the
dongle.
