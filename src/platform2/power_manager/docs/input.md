# Chrome OS Power Manager Input

powerd uses user input to determine when the system should turn its backlight
off or suspend in response to inactivity. powerd does not listen for this input
directly; rather, it receives periodic `HandleUserActivity` D-Bus method calls
from Chrome while the user is active. These method calls include a
[UserActivityType] enum describing the type of activity that was observed,
allowing powerd to e.g. avoid turning the screen back on if the user presses the
Brightness Down key while the screen is already off.

[`powerd/system/input_watcher.cc`] uses the kernel's input subsystem to observe
power button and lid switch events. (ACPI power button events may be
additionally received by Chrome as standard keyboard input, but they are
ignored there since button releases are not reported correctly.) These events
are reported to Chrome via `InputEvent` D-Bus signals containing [InputEvent]
protocol buffers; Chrome uses the power button notifications to display
screen-lock and shutdown animations.

See the [Power Buttons] document for more information about power button
behavior.

[UserActivityType]: ../../system_api/dbus/power_manager/dbus-constants.h
[`powerd/system/input_watcher.cc`]: ../powerd/system/input_watcher.cc
[InputEvent]: ../../system_api/dbus/power_manager/input_event.proto
[Power Buttons]: power_buttons.md
