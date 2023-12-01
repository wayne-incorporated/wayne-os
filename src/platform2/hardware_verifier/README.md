# Overview

Hardware Verifier is a command line tool that checks if the device is
compliant.  The program obtains the hardware
[probe result](https://chromium.googlesource.com/chromiumos/platform/factory/+/HEAD/py/probe/README.md#output-format)
from the
[Runtime Probe](/runtime_probe/README.md)
and compares it with the hardware verification spec.  The hardware
verification spec is generated from the DLM (Device Lifecycle Management) and
the AVL (Approved Vendor List) services and contains both the qualification
status of each hardware components and the expected hardware probe result like
the total DRAM size and the display panel resolution.

# Motivation

Various of benefits can be taken from the Hardware Verifier.
The following list contains some potential scenarios:

- If a hardware component were replaced by an unqualified one during the
  repairing process, we might want to warn the user about that.
- We can include the verification result in the feedback report to describe
  the latest device's status, which should be more up-to-date then current
  HWID encoding.
- In the factory, we would like to help the partner building devices with the
  right spec for each SKU and to prevent the partner from using the peripheral
  components that are not qualified.

Currently, the
[HWID](https://chromium.googlesource.com/chromiumos/platform/factory/+/HEAD/py/hwid/README.md)
generating flow provides similar checks.  However, that check is a one-time
check and only available in the manufacturing environment.

# Usage

## Command Line Interface

Users can call the tool directly by invoking the binary with arguments:

```
/usr/bin/hardware_verifier \
  [--verbosity=<log_level>] \
  [--probe_result_file=<path_to_the_probe_result>] \
  [--hw_verification_spec=<path_to_the_hardware_verification_spec>] \
  [--output_format=proto|text]
```

The tool loads the correct probe result data and the hardware verification spec
based on the given arguments.  Then it outputs the verification results to the
standard output.

## D-Bus Interface

Users can call the tool using D-Bus.  It owns the service name
`org.chromium.HardwareVerifier` at the service path
`/org.chromium/HardwareVerifier` and exports an interface named
[`org.chromium.HardwareVerifier`](dbus_bindings/org.chromium.HardwareVerifier.xml).

Example command:

```
dbus-send --system --print-reply --dest=org.chromium.HardwareVerifier \
  /org/chromium/HardwareVerifier <method>
```

# Testing

Unit tests are provided and can be run in chroot by the following command:

```
FEATURES=test emerge-<board> chromeos-base/hardware_verifier
```

# Development

- [High Level Design](http://go/cros-hw-verification-design)
- [Design Doc](http://go/cros-hw-verifier)
- [Root Issue Tracker (chromium:926825)](http://crbug.com/926825)
- [Consolidated summary for all supported component types and fields](http://go/cros-runtime-probe-fields)
