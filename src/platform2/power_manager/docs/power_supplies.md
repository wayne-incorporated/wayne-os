# Chrome OS Power Supplies

powerd's [PowerSupply] class is responsible for reading information about power
supplies (e.g. line power and batteries) from device directories under
`/sys/class/power_supply` in [sysfs]. The [kernel documentation] contains
incomplete information about these directories.

[TOC]

## Polling

powerd reads power supply information at startup and then polls periodically at
30-second intervals. The information is also refreshed immediately in response
to several events:

*   Resume (after suspending)
*   [udev] events concerning the `power_supply` subsystem

The information is copied to [PowerSupplyProperties] protocol buffers that are
included in `PowerSupplyPoll` D-Bus signals.

## Line Power

"Line power" refers to chargers or other external power sources; it's sometimes
also referred to as "AC" in the code. Information about line power sources is
read by `PowerSupply::ReadLinePowerDirectory`. The following sysfs nodes are
particularly relevant:

*   `type` describes the connected device's type. Notable values include:
    *   `Unknown` - A sink-only device that can't supply power to the Chrome OS
        device.
    *   `Mains` - A dedicated charger or direct power source. Most pre-USB-C
        chargers use this type. This type may also appear in conjunction with an
        `online` value of `0` when nothing is connected to a dedicated charging
        port on a pre-USB-C device.
    *   `USB`, `USB_ACA`, `USB_CDP`, `USB_DCP` - A low-power USB BC1.2 power
        supply. USB-C ports with nothing connected to them may report a `USB`
        type in conjunction with an `online` value of `0`. Note that some
        drivers use a static type of `USB` and report the active connection in
        `usb_type`, described below.
    *   `USB_C`, `USB_PD` - A USB Type-C power supply.
    *   `USB_PD_DRP` - A dual-role USB Type-C device (i.e. one capable of either
        delivering or receiving power).
    *   `BrickID` - An Apple legacy USB charger. May be either USB-A or USB-C.
*   `usb_type` is used by some drivers in newer kernels (4.19+) that have a
    `type` of USB to report all supported connection types, with the active
    connection value in brackets. For example, a `usb_type` of `C [PD] PD_PPS`
    is the same as a `type` of `USB_PD`.
*   `online` typically describes whether anything is connected to the port; a
    value of `1` indicates a connection. If `type` is `USB_PD_DRP`, an `online`
    value of `0` indicates that a dual-role device is connected but that it is
    not currently delivering power to the Chrome OS device.
*   `status` describes the status of a bidirectional/dual-role port. The node is
    expected to be nonexistent or to contain an empty value for non-dual-role
    ports. If the node is present, a value of `Charging` indicates that the port
    is delivering power to the Chrome OS device.
*   `voltage_max_design` and `current_max` are used to compute the maximum power
    that can be delivered by the power supply.
*   `voltage_now` and `current_now` are used to compute the instantaneous power.

### Multiple sources

If multiple line power directories are found, powerd will report all of them.
This typically happens in the case of Chrome OS devices with multiple USB Type-C
ports.

Only one power source may deliver power at a given time; Chrome displays the
active source at `chrome://settings/power`. If multiple sources are available,
the user may use this page to select which one to use. Chrome makes a
`SetPowerSource` D-Bus method call to powerd containing the ID of the desired
source (taken from an earlier [PowerSupplyProperties] protobuf), and
`PowerSupply::SetPowerSource` writes `0` to the device's
`charge_control_limit_max` sysfs node. Chrome can also pass an empty ID to
switch to battery power; powerd writes `-1` to the active power source's node in
this case.

### Barrel jack connectors

If a device has a barrel jack connector, the `has_barreljack` powerd pref must
be set to `1` in order for powerd to report it. This is `0` by default, and any
barrel jack connector will be ignored.

This pref is set automatically from Boxster if the power supply is created
correctly in a project's Boxster config (`config.star`). To enable a barrel
jack, the topology should be constructed as:

```
POWER_SUPPLY = hw_topo.create_power_supply(
    ...
    bj_present = True,
    ...
)
```

## Batteries

Battery information is read by `PowerSupply::ReadBatteryDirectory`. The
following sysfs nodes are relevant:

*   `status` describes the battery's current status. The [kernel documentation]
    describes possible values. powerd does not distinguish between `Charging`
    and `Full` and instead uses the battery's reported charge to determine if it
    is full.
*   `voltage_now` contains the instantaneous voltage.
*   `voltage_min_design` and `voltage_max_design` are read to determine the
    nominal voltage.
*   `current_now`, `charge_now`, and `charge_full` are read on `charge_battery`
    systems to get the battery's current and charge.
*   `power_now`, `energy_now`, and `energy_full` are read on `energy_battery`
    systems to get the battery's current and charge.

### Percentage and state

`PowerSupply::UpdateBatteryPercentagesAndState` uses the above information to
determine the battery status and charge that should be displayed by the UI. Many
batteries charge more slowly as they approach a full charge, so the
`power_supply_full_factor` powerd pref is used to set the charge percentage at
which powerd should report the battery as fully-charged. Similarly, powerd will
automatically shut the system down before the battery has fully discharged, so
the displayed percentage is also scaled based on the
`low_battery_shutdown_percent` pref.

Starting from M92 [crrev/c/2984168](https://crrev.com/c/2984168), on start-up,
powerd tries to read `low_battery_shutdown_percent` and `full_factor` from
[CrOS EC] using
`EC_CMD_DISPLAY_SOC`. `PowerSupply::UpdateBatteryPercentagesAndState` also reads
the display SoC (state of charge) from [CrOS EC] using `EC_CMD_DISPLAY_SOC`.
If the command isn't available, the display SoC is computed by powerd using
`low_battery_shutdown_percent` and `full_factor` read from the pref directories.

Note that low_battery_shutdown_percent_ and full_factor reported by [CrOS EC]
are for reference only: in case powerd may need to know how display_soc is
computed. Powerd should take action based on display_soc (and may use
the forementioned params for backward compatibility).

### Time-to-empty and time-to-full

`PowerSupply::UpdateBatteryTimeEstimates` attempts to estimate the time until
the battery will be fully charged or until the system will shut down due to a
low charge. To do this, `PowerSupply` maintains a rolling average of samples of
the battery's current. Sampling is temporarily deferred after events like system
resume, but these estimates may still be noisy, particularly when the system's
workload is changing frequently.

The [Battery Notifications] document contains more information about how these
estimates are computed and used.

### Multiple batteries

If the `multiple_batteries` pref is set, powerd will use
`PowerSupply::ReadMultipleBatteryDirectories` to read multiple battery power
supply directories if present. Most statistics, including the charge and full
charge, are just summed across all batteries. If any batteries are charging, the
overall state is reported as charging. The UI doesn't currently differentiate
between a single battery and multiple batteries; the main difference in the
latter scenario is that the displayed charge percentage may change when a
battery is connected or disconnected.

[PowerSupply]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/power_manager/powerd/system/power_supply.h
[sysfs]: https://en.wikipedia.org/wiki/Sysfs
[kernel documentation]: https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-power
[udev]: https://en.wikipedia.org/wiki/Udev
[PowerSupplyProperties]: https://chromium.googlesource.com/chromiumos/platform2/system_api/+/HEAD/dbus/power_manager/power_supply_properties.proto
[Battery Notifications]: battery_notifications.md
[CrOS EC]: https://chromium.googlesource.com/chromiumos/platform/ec/+/HEAD/README.md
