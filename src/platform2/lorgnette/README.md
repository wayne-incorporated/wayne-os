# Lorgnette

`lorgnette` provides support for document scanners on Chrome OS.

[TOC]

## Overview

`lorgnette` acts as a [Scanner Access Now Easy (SANE)](http://sane-project.org/)
frontend.  It exposes a D-Bus API for Chrome or other clients to enumerate
scanners, request scanner capabilities, and request scanned pages.  Other
related components include:

*  [sane-backends](https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/third_party/chromiumos-overlay/media-gfx/sane-backends):
   SANE libraries and backends.
*  [sane-airscan](https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/third_party/chromiumos-overlay/media-gfx/sane-airscan/):
   A SANE backend implementing the Mopria eSCL Scan protocol (see below for more
   info).
*  [ippusb\_bridge](https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/platform2/ippusb_bridge/):
   Allows eSCL to be used over USB on IPP-USB-capable devices.
*  Scanning support in [Chrome](https://source.chromium.org/chromium/chromium/src/+/HEAD:chrome/browser/ash/scanning/)
   handles mDNS resolution and provides the Scan app UI.
*  [virtual-usb-printer](https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/third_party/virtual-usb-printer):
   A virtual USB printer and scanner that allows testing without a physical
   device.

## Protocols

`lorgnette` is a SANE frontend, so in theory any USB or network scanner
supported by an existing [backend](http://sane-project.org/sane-mfgs.html) may
work.

However, the primary supported and tested protocol is Mopria eSCL.  The
code referenced in this documentation implements the Mopria Alliance eSCL Scan
Technical Specification. You may obtain a copy of the Mopria Alliance eSCL Scan
Technical Specification directly from the Mopria Alliance by visiting
[https://mopria.org/mopria-escl-specification](https://mopria.org/mopria-escl-specification).

## Device Discovery

For devices discovered through SANE, they are described with a string like

```
backend:Backend_Specific_String
```

These will mostly be USB-connected scanners, but some Epson and Canon network
devices can be detected.  `lorgnette` does minimal parsing on the returned
string to de-duplicate entries for devices that also support eSCL.

Network eSCL devices are discovered through mDNS.  `lorgnette` does not do mDNS
probing or resolution; it relies on Chrome's zeroconf support for this.  The
resulting device description string looks like

```
airscan:escl:Device Name:https://NNN.NNN.NNN.NNN:PPP/eSCL/
```

Local USB devices that expose an IPP-USB descriptor are probed for eSCL support
on the IPP-USB tunnel.  If the device responds, `lorgnette` generates a device
string similar to

```
ippusb:escl:Device Name:<vid>_<pid>/eSCL/
```

In this case _vid_ and _pid_ refer to the USB vendor ID and product ID of the
device.  They are used to look up an `ippusb_bridge` socket in `/run/ippusb`
for further communication with the device.

## Command line

Test images include a `lorgnette_cli` command-line client that can be used to
exercise all of `lorgnette`'s functionality.  Note that mDNS resolution is
normally done in Chrome, so the scanner lists returned by `lorgnette` do not
normally contain networked eSCL devices in the list.  `lorgnette_cli` simulates
this by running `airscan-discover`.  It is possible that the scanner lists will
be slightly different from what the UI exposes as a result.
