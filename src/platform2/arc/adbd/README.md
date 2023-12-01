# ARC adbd ConfigFS / FunctionFS proxy for Developer Mode

This sets up the ADB gadget to allow Chromebooks that have the necessary
hardware / kernel support to be able to use ADB over USB. This avoids exposing
ConfigFS into the container.

See
https://android.googlesource.com/platform/system/core/+/HEAD/adb/daemon/usb.cpp
for more information.

## Configuration

This service expects a file in `/etc/arc/adbd.json` to configure the service.
The file should be a JSON with the following format:

```json
{
  # Required, the USB product identifier for the SoC.
  "usbProductId": "0x520B",
  # Optional, a list of kernel modules that need to be loaded prior to starting
  # to setup the USB gadget.
  "kernelModules": [
    # Each one of these objects will become an invocation to modprobe(8).
    {
      # Required, the name of the kernel module.
      "name": "g_ffs",
      # Optional, the list of additional parameters to modprobe(8). These can be
      # used to further configure the module.
      "parameters": [
        "functions=adb"
      ]
    }
  ]
}
```
