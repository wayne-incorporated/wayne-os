# Chrome OS Power Management udev Usage

powerd uses the udev interface to learn about hardware changes.

## Inhibiting and configuring wakeup for input devices

The [InputDeviceController] class is responsible for setting input devices'
`inhibit` udev system attributes (to suppress events) and [wakeup sysfs
attributes] (to enable or disable their ability to wake the system)
appropriately depending on the system's current mode. For example, the
touchscreen should be ignored while the system is in docked mode with its lid
closed.

This behavior is configured via udev tags that are set on devices by the
[90-power-id.rules] and [92-powerd-tags.rules] files:

|Tag|Description|
|---|-----------|
|`inhibit`|If set, powerd will inhibit the device when not usable|
|`usable_when_docked`|Device is usable when system is docked|
|`usable_when_display_off`|Device is usable when in clamshell mode with display off|
|`usable_when_laptop`|Device is usable when in clamshell mode|
|`usable_when_tablet`|Device is usable when in tablet mode|
|`wakeup`|If set, powerd will manage the device's `wakeup` attribute|
|`wakeup_when_docked`|Enable wakeup when system is docked|
|`wakeup_when_display_off`|Enable wakeup when in clamshell mode with display off|
|`wakeup_when_laptop`|Enable wakeup when in clamshell mode|
|`wakeup_when_tablet`|Enable wakeup when in tablet mode|
|`wakeup_only_when_usable`|Shorthand for enabling wakeup only when usable|
|`wakeup_disabled`|Unconditionally disable wakeup (if `wakeup` is also set)|

If only the `wakeup` tag is set, wakeup will be unconditionally enabled. If one
or more `wakeup_when_*` tags are also present, wakeup will be enabled only while
in the requested modes.

Boards can create and install their own udev rules with prefix `91-` to override
generic `internal/external_[type]` roles, or create udev rules with prefix `93-`
to override the specific tags above.

[InputDeviceController]: ../powerd/policy/input_device_controller.h
[wakeup sysfs attributes]: https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-devices-power
[90-power-id.rules]: ../udev/90-powerd-id.rules
[92-powerd-tags.rules]: ../udev/92-powerd-tags.rules
