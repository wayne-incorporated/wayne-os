# Chrome OS Power Buttons

This document describes the expected behavior of power buttons on Chrome OS
devices as of M71. Earlier versions of Chrome OS have used different behavior.

[TOC]

## Form Factors

A device's form factor affects the behavior of its power button. The following
descriptions of form factors provide shared vocabulary.

### Convertibles

Convertible Chromebooks have 360-degree hinges that allow them to be used in
both **laptop mode** and **tablet mode** (sometimes also called **Touchview
mode**). As such, they typically feature power buttons located on their sides
that are accessible in all configurations. They may have a dedicated Lock key on
the keyboard.

### Clamshells

Clamshell Chromebooks have hinges that stop before reaching 180 degrees,
supporting only traditional laptop form factors. Their power buttons are
typically located at the top-right corner of the keyboard (i.e. to the right of
Volume Up and just above Backspace). Clamshells are always in laptop mode.

### Tablets, Slates, and Detachables

Some Chrome OS devices look like tablets. They may or may not support a
detachable keyboard or base. These devices are typically in tablet mode but may
switch to laptop mode when a keyboard is attached.

### Chromeboxes and Chromebases

Chromeboxes, Chromebases, and related devices that lack integrated keyboards
typically feature [legacy ACPI-style power buttons](#Legacy-ACPI-Power-Buttons).

### Chromebits

Chromebits don't have power buttons.

## User Experience

### Tablet Mode

While a Chrome OS device is in tablet mode, tapping the power button once turns
the screen off.  This is intended to give users an easy way to turn the screen
off before carrying the device, and it happens regardless of whether a user is
logged in or not. If a user is logged in and the "Show lock screen when waking
from sleep" setting is enabled, the screen is additionally locked immediately.
Tapping the power button a second time after the screen has been turned off
turns the screen back on.

If Volume keys are pressed in combination it works as a shortcut for some
features, see [debug buttons] documentation for more key combinations with power
buttons.

If the power button is held for a half second or longer before being released,
the screen remains on and a power menu with `Power off`, `Sign out`,
`Lock screen` and `Feedback` options is displayed. The power button may be
tapped again to dismiss the menu. Note that the options shown might differ based
on the user session state. For example, if the device is already locked, options
will not include `Lock screen`.

If the user holds the power button for an additional 650 milliseconds while the
menu is displayed, a cancellable pre-shutdown animation begins in which the
screen fades to white. After the animation finishes, the screen turns off and
the system shuts down. The user may also shut the system down by holding the
power button from the menu-not-shown state.

Some of the above delays are lengthened slightly if the screen was initially off
when the user began holding the power button.

If the display is off due to [user inactivity](inactivity_delays.md) or manually
setting the screen brightness to zero, the power button turns the display back
on rather than locking the screen or shutting down the system.

[debug_buttons]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/debug_buttons.md#devices-without-keyboards

### Laptop Mode

The behavior of the power button while in laptop mode is identical to the
behavior while in tablet mode, with one exception: tapping the power button has
no effect. Turning the screen off is less useful while in laptop mode, and
ignoring taps may mitigate accidental power button presses.

### Touch-centric Devices

Tablet and slate devices that are considered "touch-centric" (typically meaning
that they're distributed without a keyboard folio) use tablet-like power button
behavior even when a folio or other external keyboard is attached.

[session_manager]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/login_manager/

### Legacy ACPI Power Buttons

On devices that don't report power button releases properly, tapping the power
button displays the power menu described above. Tapping the power button again
while the menu is displayed shuts the system down.

### Universal Behavior

Some power button behavior is consistent across all Chrome OS devices to date:

*   An initial press of the power button turns the system on.
*   Pressing the power button while the system is asleep wakes it.
*   Holding the power button for a full 8 seconds forces a hard power-off in
    firmware. This may result in data loss.

## Implementation

powerd receives power button events from the kernel's input subsystem and
reports them to Chrome via D-Bus as described in the [Input](input.md) document.

User-facing behavior power button behavior is spread across multiple classes in
Chrome:

*   [`chromeos::PowerManagerClient`] receives D-Bus notifications about power
    button events from powerd.
*   [`ash::PowerButtonController`] initiates action in response to power button
    events received from powerd.
*   [`ash::LockStateController`] contains the high-level logic for transitioning
    between different animations and performing actions when they complete.
*   [`ash::SessionStateAnimator`] displays animations and contains durations.
*   [`ash::PowerButtonDisplayController`] contains logic related to forcing the
    display off in response to power button events.

The always-tablet-like power button behavior used on touch-centric devices is
controlled by the presence of the `touch_centric_device` USE flag, which
instructs [session_manager] to pass a `--force-tablet-power-button` command-line
flag to Chrome.

Chromebox- and Chromebase-style behavior is enabled by setting the
`legacy_power_button` USE flag in a Portage overlay, which causes powerd's
`legacy_power_button` pref to be set and the `--aura-legacy-power-button` flag
to be passed to Chrome.

[`chromeos::PowerManagerClient`]: https://source.chromium.org/chromium/chromium/src/+/HEAD:chromeos/dbus/power/power_manager_client.h
[`ash::PowerButtonController`]: https://source.chromium.org/chromium/chromium/src/+/HEAD:ash/system/power/power_button_controller.h
[`ash::LockStateController`]: https://source.chromium.org/chromium/chromium/src/+/HEAD:ash/wm/lock_state_controller.h
[`ash::SessionStateAnimator`]: https://source.chromium.org/chromium/chromium/src/+/HEAD:ash/wm/session_state_animator.h
[`ash::PowerButtonDisplayController`]: https://source.chromium.org/chromium/chromium/src/+/HEAD:ash/system/power/power_button_display_controller.h
