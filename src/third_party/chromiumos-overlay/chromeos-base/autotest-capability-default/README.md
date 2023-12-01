# Manage CrOS Video Capabilities
We define static capabilities, because dynamic detection of capabilities may
fail in case of issues (e.g. a driver issue). If we used dynamic detection,
no capability would be detected, we would have not run a corresponding test,
and no failure would be reported. Instead, we prefer to run tests based on
static capabilities and to be alerted in case they fail, and make a decision
either to remove the static capability from configuration if the capability
should not supported, or that we need to fix an actual issue.

## Overview of components in the system
Autotest capability works with autotest. While autotest runs, the component
on DUT should be like the following.

- `/usr/local/etc/autotest-capabilities/`
  Installed by this package `autotest-capability`. The configuration files which
  defines the capabilities on the device.

- `/usr/local/autotest/cros/video/detectors/`
  - `device_capability.py`
    Utility to parse the configuration and get the capabilities on the DUT.
  - `detectors/`
    scripts to detect the hardware configuration on DUT.

This document describes how the components work.

## Gentoo Package: autotest-capability

This package will install the configuration files into
`/usr/local/etc/autotest-capability/`. Take board `jecht` as an example, there could be
the following files in the directory:

*   [`managed-capabilities.yaml`](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/chromeos-base/autotest-capability-default/files/managed-capabilities.yaml)
*   [`15-chipset-bdw-capabilities.yaml`](https://chromium.googlesource.com/chromiumos/overlays/board-overlays/+/HEAD/chipset-bdw/chromeos-base/autotest-capability-chipset-bdw/files/15-chipset-bdw-capabilities.yaml)
*   [`18-baseboard-jecht-capabilities.yaml`](https://chromium.googlesource.com/chromiumos/overlays/board-overlays/+/HEAD/baseboard-jecht/chromeos-base/autotest-capability-baseboard-jecht/files/18-baseboard-jecht-capabilities.yaml)
*   [`20-guado-capabilities.yaml`](https://chromium.googlesource.com/chromiumos/overlays/board-overlays/+/HEAD/overlay-guado/chromeos-base/autotest-capability-guado/files/20-guado-capabilities.yaml)

`managed-capabilities.yaml` lists all possible capabilities managed
by the package. If an unexpected capability is found while discovering
board-specific capability definition files,
[`device_capability.DeviceCapability()`](#devicecapability) will fail.

The remaining files contain capability configurations for the particular
board hierarchy and will be loaded in the order of their priorities (The first
number of the filename). Each of the file is installed by different overlays:

*   `15-chipset-bdw-capabilities.yaml`: installed by `chipset-bdw` overlay
*   `18-baseboard-jecht-capabilities.yaml`: installed by `baseboard-jecht` overlay
*   `20-guado-capabilities.yaml`: installed by `overlay-guado` overlay


## Capabilities Configuration

We list all the the managed capabilities line by line in
`managed-capabilities.yaml`. For example,


```
# This file list all the managed capabilities. These capabilities
# indicate the capabilities of the DUT.
- hw_dec_h264_1080_60     # Decode h264 1080p 60fps videos in hardware.
- hw_dec_h264_2160_30     # Decode h264 2160p 30fps videos in hardware.
- hw_enc_vp8_1080_30      # Encode vp8 1080p 30fps videos in hardware.
- hw_dec_jpeg             # Decode mjpeg in hardware.
- builtin_usb_camera      # DUT has a built-in USB camera.
- no builtin_mipi_camera  # DUT doesn't have a built-in MIPI camera.
- no vivid_camera         # vivid is not available on DUT.
- builtin_camera
- builtin_or_vivid_camera
```

An unlisted capability will be treated as unknown capabilities, and will raise
exceptions while parsing the configuration yaml files.

In the configuration of each level, it defines the most general capabilities.
For example, there could be the following capabilities defined
in `15-chipset-bsw-capabilities.yaml`,


```
- hw_dec_h264_1080_60
- builtin_usb_camera
- no builtin_mipi_camera
- no vivid_camera
- builtin_camera
- builtin_or_vivid_camera
```


It defines common capabilities for all `chipset-bsw` platforms.
We may override those settings in baseboard and board specific settings,
for example, removing camera capabilities and adding `hw_dec_h264_2160_30` in
`18-baseboard-jecht-capabilities.yaml`.


```
- hw_dec_h264_2160_30
- no builtin_or_vivid_camera
- no builtin_camera
- no builtin_usb_camera
```


Final capabilities after processing the above files:


```
hw_dec_h264_1080_60
hw_dec_h264_2160_30
```



### Disabling a capability temporarily

In some cases, we may like to disable a capability temporarily,
while fixing a known issue, to prevent lab tests from failing.
Depending on how we disable the feature, the `avtest_label_detect` may or may
not detect the capability. To ignore the result of `avtest_label_detect` for it,
`disable `*`capability`* can be added in the configuration yaml, e.g.,


```
- disable hw_dec_h264_2160_30
```


If a capability will be disabled forever, it should either be removed from
the applicable configuration file, or overridden using the `no `*`capability`*
syntax instead.


### SKU-specific Capabilities

There could be more than one SKU for a single board, with different hardware,
and thus different capability sets. In such cases it is not possible to use
static configuration files and runtime detection is required. To support that,
capability files may contain hardware specific sections to define those
capabilities. A capability is applied only if the hardware configuration
detected in runtime matches the condition.


### Detectors

We use detectors to detect the hardware type or the existence of the hardware.
Those detectors are installed by autotest package on
the DUT directory: `/usr/local/autotest/cros/video/detectors.`


#### Detector: CPU Type

There is a board which has a different specification if a cpu type is different.
For example, HW H264 encoding is unavailable only on panther boards whose cpu
type is intel celeron. The information is written in
"20-panther-capabilities.yaml."

```
# HW encoding
- detector: intel_cpu
  match:
    - intel_celeron_2955U
  capabilities:
    - no hw_enc_h264_1080_30
```

`detector` is the name of the running detector. In this case, `intel_cpu.py`
in the detector directory will be executed.
`match` is a list of all acceptable values, if the results of detector is one
of the values, then all capabilities in `capability` will be applied.

In this example, if `intel_cpu.py` returns `intel_celeron_2955U`,
we disable HW h264 encoding.

Detectors are python scripts which return a string.
It must have the function `detect()`.
For example, the following cpu detectors return `i5` or `m3` to indicate
the CPU on the DUT.


```
# cpu.py
def detect():

    cpu_data = lscpu()
    if ‘i5-7Y57’ in cpu_data.model_name: return ‘i5’
    if `m3-7y32’ in cpu_data.model_name: return ‘m3’
    throw Exception(“Unknown cpu: “ + cpu_data.model_name)
```

## Run video autotest with static capabilities

In the current autotest system, autotest scheduler looks the labels on DUT, and
only runs a test if the DUT has labels required for the test.

The goal of this work is to replace this mechanism and the need for autotest
labels with capability checks. All available tests would be executed
on all boards. Each test would first check if the required capabilities for it
are present. If a capability is found, the actual test is performed; if not,
the test returns `TEST_NA` as a test result.

This is realized by calling [`DeviceCapability().check_capability()`](https://chromium.googlesource.com/chromiumos/third\_party/autotest/+/HEAD/client/cros/video/device\_capability.py).

### DeviceCapability

`DeviceCapability` is a class to check, based on static capability,
if a required capability is available on DUT. It constructs all the capabilities
from yaml files installed in the specified directory
(default path is `/usr/local/etc/autotest-capability`).
A running detector is specified by a configuration file.

A user of `DeviceCapability` mainly calls the following two functions.

__get_capability(cap)__

Query the status of a capability, `|cap|`. `|cap|` must be one of capabilities in
`managed-capabilities.yaml`. The return value is either `yes`, `disable` or `no`.

`yes` means available, `no` means unavailable.
`disable` may be detectable and supported by hardware but we disable it due to
hardware/software issues.

__ensure\_capability(cap)__

This is a similar to `get_capability`. The difference is this throws
`test.TestNAError` unless the status of `|cap|` is `yes`.


### How to modify static capability

__Modify a capability in an existing chipset/baseboard/board overlay__

Edit the existing yaml file, if any, or add a new yaml file to an existing
overlay.
It is worth noting that we will be notified if a test runs on DUT
without required capabilities.
For example, since IvyBridge doesn't support HW VP8 encoding, HW VP8 encoding
test will fail if it runs on IvyBridge device.
Following this observation, we should maximize the available capability rather
than minimize them when we set up the configuration.
Concretely, when one writes `no `*`capability`*, we should minimize the targeted
devices.
For example, in `20-peppy-capabilities.yaml`, we disable HW h264 encoding
only if the CPU type is intel celeron 2955U. In other words, this describes
HW h264 encoding is available on all the peppy whose CPU type isn't intel
celeron 2955U.

```
# HW encoding
- detector: intel_cpu
  match:
    - intel_celeron_2955U
  capabilities:
   - no hw_enc_h264_1080_30
```

Conversely, when one writes *`capability`*, we should maximize the targeted
devices.

__add an existing to chipset/baseboard/board__

Example of adding a fictitional new chipset overlay, `chipset-mhl` (standing for
Meihua Lake).

Please create the following files.


```
chipset-mhl/chromeos-base/autotest-capability-chipset-mhl/autotest-capability-chipset-mhl.ebuild
chipset-mhl/chromeos-base/autotest-capability-chipset-mhl/files/15-chipset-mhl-capabilities.yaml
chipset-mhl/virtual/autotest-capability/autotest-capability-1.5.ebuild
```


The capabilities applicable to all boards for `chipset-mhl` should be listed
in the yaml file.

The first two digits of yaml file, here `15`, will be `18` and `20` for baseboard and
board, respectively.

The PV of ebuild in virtual, here `1.5`, will be `1.8` and `2.0` for baseboard and
board, respectively.

__add a new capability__

First of all, you need to add the new capability to
[`//third_party/chromiumos-overlay/chromeos-base/autotest-capability-default/files/managed-capabilities.yaml`](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/chromeos-base/autotest-capability-default/files/managed-capabilities.yaml).
Set up the capability in applicable [`//overlays`](https://chromium.googlesource.com/chromiumos/overlays/board-overlays/+/HEAD/) following two above ways.

__add a new detector__

If some capabilities depend on the hardware configuration, it is necessary
to create a new detector if it is not available yet. All the detectors are put
in [`//third_party/autotest/files/client/cros/video/detectors`](https://chromium.googlesource.com/chromiumos/third_party/autotest/+/HEAD/client/cros/video/detectors/).
