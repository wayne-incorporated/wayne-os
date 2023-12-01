# Touch Firmware Calibration

## Overview
This package includes command line tools needed to set calibration values to
evdev devices. When it is build, the following executable will be built:

    /lib/udev/override_max_pressure

See more details below.

## override\_max\_pressure

### Usage
| parameter     |  explain   |
|---------------|------------|
help            |    Show help message.
device          |    Set the device name. It should be eventX.
maxpressure     |    Set the max pressure.

### Example
Set the max pressure of /dev/input/event4 to 2048.

    $override_max_pressure --device=event4 --maxpressure=2048
