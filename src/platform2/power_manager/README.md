# ChromeOS Power Management

The ChromeOS power manager consists of several components:

-   `powerd`: C++ system daemon running as the `power` user that initiates
    dimming the screen, suspending the system, etc.
-   `powerd_setuid_helper`: setuid root binary used by powerd to perform actions
    requiring additional privileges.
-   `powerd_suspend`: shell script executed by powerd (by way of
    `powerd_setuid_helper`) to suspend and resume the system.
-   `send_metrics_on_resume`: shell script executed by `powerd_suspend` and by
    the `send-boot-metrics` Upstart job to report suspend-related metrics.

## Documentation

The [`docs/`](docs/) subdirectory contains additional documentation. Along with
answers to [frequently-asked questions](docs/faq.md), the following information
is available:

-   [Adaptive Charging](docs/adaptive_charging.md) describes how charging is
    delayed for maintaining battery health.
-   [ALS Backlight](docs/als_backlight_prefs.md) describes ALS prefs for backlight
    in powerd.
-   [Battery Notifications](docs/battery_notifications.md) describes when
    low-battery notifications are shown by the UI.
-   [Hibernation](docs/hibernation.md) describes how powerd handles the
    hibernation process.
-   [Inactivity Delays](docs/inactivity_delays.md) describes powerd's logic for
    taking action (e.g. dimming the backlight or suspending) when the user is
    inactive.
-   [Input](docs/input.md) describes how powerd handles input events.
-   [Keyboard Backlight](docs/keyboard_backlight.md) describes powerd's logic
    for controlling the keyboard backlight.
-   [Logging](docs/logging.md) describes where and how powerd logs informative
    messages.
-   [Power Buttons](docs/power_buttons.md) describes how power buttons work.
-   [Power Supplies](docs/power_supplies.md) describes powerd's logic for
    determining the state of power supplies (e.g. batteries or line power).
-   [Screen Brightness](docs/screen_brightness.md) describes powerd's logic for
    controlling the display backlight.
-   [Shutdown and Reboot](docs/shutdown.md) describes why and how ChromeOS
    systems shut down and reboot.
-   [Suspend and Resume](docs/suspend_resume.md) describes powerd's process for
    suspending and resuming the system.
-   [Thermal](docs/thermal.md) describes how powerd monitors system thermal
    state to provide thermal hinting to Chrome.
-   [udev Usage](docs/udev.md) describes how powerd uses the udev system to
    learn about hardware changes.

## Code Overview

This repository contains the following subdirectories:

| Subdirectory    | Description |
|-----------------|-------------|
| `common`        | Code shared between powerd and tools |
| `dbus`          | D-Bus policy configuration files |
| `default_prefs` | Default pref files installed to `/usr/share/power_manager` |
| `docs`          | Detailed documentation in Markdown format |
| `init/shared`   | Scripts shared between Upstart and systemd |
| `init/systemd`  | systemd-specific config files |
| `init/upstart`  | Upstart-specific config files installed to `/etc/init` |
| `optional_prefs`| Pref files conditionally installed based on USE flags |
| `powerd`        | Power manager daemon |
| `powerd/policy` | High-level parts of powerd that make policy decisions |
| `powerd/system` | Low-level parts of powerd that communicate with the kernel |
| `tools`         | Utility programs; may depend on `powerd` code |
| `udev`          | udev configuration files and scripts |
