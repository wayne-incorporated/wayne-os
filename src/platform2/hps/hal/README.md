# HPS Hardware Abstraction Layer

The HPS code uses a HAL (Hardware Abstraction Layer)
interface to access the HPS hardware device.
The ```dev.h``` interface defines the HAL API.
This HAL library implements the various access
methods that are used.

## I2C

The i2c implementation uses a i2c device to connect to
the hardware module.

## FakeDev

The FakeDev class implements an internal s/w simulator
of the HPS hardware for testing and development.

## MCP

The mcp class implements a driver that uses the libusb
library to communicate to a MCP2221A device (used as an I2C bridge).

The MCP2221A USB device may need to have appropriate udev rules to allow
write access to the device, and also to disable the kernel from attempting to
claim the device as a USB HID device.
The following lines can be placed in ```/etc/udev/rules.d/99-mcp.rules```, and the
udev rules reloaded via ```/etc/init.d/udev reload```. The device may need to be unplugged
and replugged for the rules to be run again:

```bash
# MCP2221A rules
SUBSYSTEM=="usb", ATTRS{idVendor}=="04d8", ATTRS{idProduct}=="00dd", GROUP="dialout", MODE="0664", RUN="/bin/sh -c 'echo -n $kernel > /sys/bus/usb/drivers/usbhid/unbind'"
```

## Retry

The retry class is a shim proxy layer that allows
calls to be retried upon error.
