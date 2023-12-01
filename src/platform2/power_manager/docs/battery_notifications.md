# Chrome OS Battery Notifications

## Collecting Data

Every thirty seconds, powerd reads power-supply-related information from
`/sys/class/power_supply` and emits a `PowerSupplyPoll` D-Bus signal containing
a [PowerSupplyProperties] protocol buffer. (The information is also updated when
line power is connected or disconnected or when the system wakes from suspend.)
Chrome observes these signals and uses them to update the battery level and
remaining-time estimate in the system tray.

The "time-to-empty" estimate that powerd sends to Chrome is actually the
estimated time until powerd will shut down the system automatically, which
happens (by default) three minutes before the battery will be completely empty.
This time interval is specified via powerd's `low_battery_shutdown_time_s`
preference. See powerd's [PowerSupply] class and the [Power Supplies] document
for more details.

## Notifying the User

Chrome also displays notifications to the user when the battery reaches certain
levels; see [ash::TrayPower].

### With no external power source connected:

-   15 minutes remaining until automatic shutdown: low-power notification
-   5 minutes remaining until automatic shutdown: critically-low-power
    notification

### With a low-power USB charger connected (for systems that can charge over USB):

-   10% remaining: low-power notification
-   5% remaining: critically-low-power notification

Previously-shown notifications are automatically dismissed when the battery
rises above a threshold (30 minutes or 15%, respectively).

If a low-power USB charger is connected, a notification is also displayed to
warn the user that the system may be consuming more power than the charger can
supply.

## Remaining Time Estimates

To compute time-to-empty and time-to-full estimates, powerd maintains running
averages of the current, as measured on battery and line power, and uses them to
extrapolate the remaining time until the battery charge reaches 0 (when
discharging) or its full charge (when charging). These values are displayed in
the system tray and additionally used to display notifications or to shut the
system down automatically when the battery discharges to a critically-low level.
Several powerd preference files can be used to configure powerd's estimates:

-   `max_current_samples`: number of samples that are averaged
-   `battery_stabilized_after_startup_ms`: delay after powerd startup before
    collecting the first sample
-   `battery_stabilized_after_line_power_connected_ms`: delay after connecting
    line power
-   `battery_stabilized_after_line_power_disconnected_ms`: delay after
    disconnecting line power
-   `battery_stabilized_after_resume_ms`: delay after resuming from sleep

powerd previously used an exponential moving average, but the resulting code was
difficult to reason about or write tests for, and the estimates were even
noisier (as a result of decreasing the weighting of older samples).

Battery time estimates currently fluctuate wildly (sometimes by an hour or more
between updates) when the power load is also changing dramatically. This
behavior can be reduced by increasing the values in the above prefs, but doing
so makes the estimates slower to adjust when the load has actually changed.

When [Adaptive Charging] is enabled, the way that time-to-full estimates are
computed may change. Adaptive Charging may delay charging to full after reaching
a `display_battery_percentage` of 80%. At this point, the time-to-full estimate
will change to the current planned delay in charging plus 2 hours when slow
charging is disabled, or 3 hours when slow charging is enabled. The time at
which charging will resume may be made earlier, but it will not be pushed out.
The `adaptive_delaying_charge` field within PowerSupplyProperties indicates if
Adaptive Charging is actively delaying charging.

[PowerSupplyProperties]: https://chromium.googlesource.com/chromiumos/platform2/system_api/+/HEAD/dbus/power_manager/power_supply_properties.proto
[PowerSupply]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/power_manager/powerd/system/power_supply.h
[Power Supplies]: power_supplies.md
[Adaptive Charging]: adaptive_charging.md
[ash::TrayPower]: https://chromium.googlesource.com/chromium/src/+/HEAD/ash/system/power/tray_power.cc
