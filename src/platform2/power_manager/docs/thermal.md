# Chrome OS Power Manager Thermal Event

powerd monitors thermal devices (e.g. fan speed, cpu throttling state) in sysfs
to approximately determine the thermal state of the entire device (Chromebook)
to provide thermal hinting to user space via [ThermalEvent].

There are 4 thermal states.
* Nominal - The device's temperature-related conditions (thermals) are at an
acceptable level. There is no noticeable negative impact to the user.
* Fair - Thermals are minimally elevated. On devices with fans, those fans may
become active, audible, and distracting to the user. Energy usage is elevated,
potentially reducing battery life.
* Serious - Thermals are highly elevated. Fans are active, running at maximum
speed, audible, and distracting to the user. System performance may also be
impacted as the system begins enacting countermeasures to reduce thermals to a
more acceptable level.
* Critical - Thermals are significantly elevated. The device needs to cool down.

The thermal state are approximately similar to [NSProcessInfoThermalState].

When there are multiple thermal devices, the system overall thermal state is the
highest state of all devices.

[NSProcessInfoThermalState]: https://developer.apple.com/library/archive/documentation/Performance/Conceptual/power_efficiency_guidelines_osx/RespondToThermalStateChanges.html
[ThermalEvent]: https://chromium.googlesource.com/chromiumos/platform2/system_api/+/HEAD/dbus/power_manager/thermal.proto
