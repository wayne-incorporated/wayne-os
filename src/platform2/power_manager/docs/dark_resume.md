# Chrome OS Dark Resume

[TOC]

## Introduction

Dark resume describes a state where the system resumes after being suspended
but keeps its display off. Dark Resume helps the device to resume from [sleep
states] to perform tasks that do not require user attention. powerd makes this
decision of whether to enter Dark/Full Resume. This document describes how and
when powerd decides to enter into Dark Resume. This document also covers the
driver level support needed for powerd to make this decision properly.

## Design & Implementation Details

### powerd

#### Determining whether to enter Full/Dark Resume

powerd decides whether to enter Dark/Full Resume based on the wake source. All
[input devices] that are wake capable (have [power/wakeup] attribute) are
considered as potential sources for Full Resume. Other devices are treated as
sources of Dark Resume.

Input devices need not be wake-capable by themselves. powerd traverses the
sysfs path of the device node, to find the closest [wake-capable parent]. If
found, powerd [monitors the wakeup-count] of the parent device. This helps in
handling [mfd devices] where the mfd node aggregates and report wakeups from
all its children. If powerd cannot find any wake-capable parent, it assumes
this input device cannot wake the system up.

On path to suspend, powerd takes a [snapshot of wakeup count] for all the
input devices that it is monitoring. On resume, powerd [checks the wakeup
count] of these devices again to see if there is a difference. If so, powerd
deems the wake as Full Resume. Otherwise, the wake is treated as a Dark Resume.

#### After waking up in Dark Resume

*   If in Dark Resume, powerd will start a timer for next suspend based on the
    registered Dark Resume suspend delays and emit the [`DarkSuspendImminent`]
    D-Bus signal.
*   Once the delay timer expires or when all Dark Resume clients respond with
    [`HandleDarkSuspendReadiness`] method call, the system re-suspends again.

#### Transitioning from Dark Resume to Full Resume

powerd transitions from Dark Resume to Full Resume in the following scenarios :

*   If any of the [input devices that powerd polls] report an input event.
*   If powerd receives a call to [`HandleUserActivity`] D-Bus method.

powerd does the following as part of transitioning from Dark Resume to Full
Resume:

*   Stops re-suspend process.
*   Emits [`SuspendDone`] D-Bus signal.

### Drivers

For a device to be wake-capable, the driver attached to the device should
call `device_init_wakeup()` in its `probe()` or `init()` methods. This call
sets the `power.can_wakeup` attribute of the device to true. This call also
adds device-specific wakeup related attributes to sysfs.

Further, drivers should call `pm_wakeup_event()` after processing a wake
interrupt. This results in a increment in per-device wakeup count along with
the aggregated wakeup count (`/sys/power/wakeup_count`) of all devices.

Note that it is okay to call `pm_wakeup_event()` on every interrupt. Per-device
wakeup count increments only when `events_check_enabled` is set. This bool is
set whenever we write current wakeup count to `/sys/power/wakeup_count` from
the userspace. Userspace is expected to write to `/sys/power/wakeup_count`
just before suspend. Also `events_check_enabled` is cleared on every resume.

On Chrome OS devices, powerd writes the current wakeup count into
`/sys/power/wakeup_count` before every suspend. This way, when
`pm_wakeup_event()` is called from IRQs, per-device `wakeup_count` increments
only if the system is in a system-wide suspend/resume cycle.

## Enabling Dark Resume on a new device

Please follow these steps to enable Dark Resume on a new device.

*   Raise a tracking [chromium bug].
*   Make sure [power_WakeSources] Autotest test passes on the device.
*   [power_WakeSources] might not test all the wake sources. Please make sure to
    test missing wake sources manually.
*   Add `disable-dark-resume` to the board's `model.yaml`
    ([example](https://crrev.com/c/1989434)).

## Debugging Dark Resume

### Enabling Dark Resume

Perform the following steps to enable Dark Resume:

```sh
echo 0 > /var/lib/power_manager/disable_dark_resume
```

### Disabling Dark Resume

Perform the following steps to disable Dark Resume:

```sh
echo 1 > /var/lib/power_manager/disable_dark_resume
```

### Manual Test of Dark Resume using RTC as wakeup

The commands below should facilitate a dark resume via the RTC wake source.
Note, any issues with failures to suspend or spurious wakes should be resolved
first in order to not block this testing.

Enable it
```sh
echo 0 > /var/lib/power_manager/disable_dark_resume
```

Create an RTC wake that is always meant to be a dark resume.
```sh
powerd_dbus_suspend --disable_dark_resume=false --wakeup_timeout=10
```

Note after ~10 secs device should wake without screen on.  It should be
perceivable via things like:

*   LED change
*   fan noise
*   network connectivity
*   EC console output

Note device should return to suspend fairly quickly.

Wake manually via input device (keyboard, trackpad)

Examine powerd log for success
```sh
grep "In dark resume" /var/log/power_manager/powerd.LATEST
```

You should see something like:
```sh
[0908/104512.488613:INFO:dark_resume.cc(41)] In dark resume
```

### Check if Dark Resume is currently enabled

Look for `Dark resume enabled` in
`/var/log/power_manager/powerd.LATEST`.

You should see *"Dark resume disabled"* in the powerd logs if Dark
Resume is disabled.

### Debugging Incorrect Dark Wakeups

If a wake from a particular wake source results in Dark Resume when it is not
supposed to, these steps might help in debugging what went wrong.

*   Check if the wake source is waking the device up when Dark Resume is
    disabled. Otherwise Dark Resume logic might not be at fault.
    *    Disable Dark Resume.
    *    Suspend the device: `powerd_dbus_suspend`
    *    Trigger a wake using the wake source under test.
    *    Check if the system resumes.

*   Check if the driver registers an input device to report events.
    `cat /proc/bus/input/devices` lists all the input devices and their
    attributes. Otherwise fix the driver to register an input device.

*   Check if powerd is [monitoring this specific input device] for wakeups. You
    should see a log similar to `Monitoring input device event* with sysfs
    path /sys/devices/*/input/input*/event* to identify the wake source`
    in `/var/log/power_manager/powerd.LATEST`. If not, the driver might not
    have called `device_init_wakeup()` in the `probe()` or `init()` method.

*   Check if the device driver is incrementing the wakeup counts correctly.
    Otherwise the driver might need to call `pm_wakeup_event()` when handling
    interrupt.
    *   Disable Dark Resume.
    *   Note the wakeup count of the device before suspend.
    *   Suspend the device.
    *   Trigger the wake using the wake source.
    *   Resume the device.
    *   Check if the wakeup count has incremented.

### Debugging Incorrect Full Wakeups

If a wake from a particular wake source trigger a Full Resume when it is not
supposed to, this might help in debugging what went wrong.

Powerd only tracks input devices that can trigger Full Resume. If a wake from
other wake sources result in Full Resume, then one of the input devices is
incrementing the wakeup count even when it is not the source of the wake.
powerd prints the details of the device that incremented the wakeup count
after resume. Look for a log similar to `Device /sys/devices/\*/\* had wakeup
count \* before suspend and \* after resume` in powerd logs. This is the
device that need to be fixed.

## Things to consider during platform bring-up

*   Please check every wake-capable input device triggers a Full Resume.
*   Please check RTC, AC connect & AC disconnect trigger a Dark Resume.
*   Shared interrupt lines can be a problem. When there is an interrupt on a
    shared line, kernel invokes the interrupt handler of every driver that
    shares the line. Individual drivers should then be able to distinguish if
    the device they handle has caused the interrupt and increment the wakeup
    count only then.

## Adding support for a device under ChromeOS EC

[mfd/cros\_ec.c] handles the interrupts from ChromeOS EC. On an interrupt
`mfd/cros_ec.c` driver calls `cros_ec_get_next_event` to get further details.
If the call succeeds, the driver then [notifies all the interested drivers]
about the event. Individual drivers like [cros\_ec\_keyb.c] can [increment the
wakeup count] if the event is for them. This way we can identify the actual
sub device that woke us up.

Thus when adding a new device under EC that can wakeup the system

*   Call `device_init_wakeup()` in the probe method of the driver.
*   Call `pm_wakeup_event()` if the  event is for this particular driver in
    the notification handler.

## Dark Resume Wake Sources

The following wake sources result in a dark resume if the feature is enabled.

* RTC
* AC connected
* AC disconnected

## Features dependent on Dark Resume

### shutdown-from-suspend

[shutdown-from-suspend] extends battery life of ChromeOS device during prolonged
non-use by proactively shutting down.

## FAQS

*   **Why does `/sys/power/wakeup_count` increase even when the system is not
    in suspend/resume path?**

    [`/sys/power/wakeup_count`] is a misnomer. Instead of printing the
    `wakeup_count`, the kernel currently prints [combined_event_count]. Thus
    you might see the wakeup count incrementing even when the system is not in
    the suspend resume path. Note that, [per-device wakeup count has been
    fixed] and reports properly.

*   **Do we have support for USB devices?**

    Yes. The patch set [adds the support for USB].

*   **Can we find the wake source from the logs?**

    Currently powerd only tracks input events. So, if the wake source is one
    of the input devices, you should see a log similar to
    `Device /sys/devices/*/* had wakeup count * before suspend and * after
    resume`. If the wake source is not a input device, then you should see log
    saying `In Dark Resume`.

*   **Can we see the summary of wakeup stats all devices somewhere?**

    Summary of all wakeup sources can be found at
    `/sys/kernel/debug/wakeup_sources`.


[sleep states]: https://www.kernel.org/doc/Documentation/power/states.txt
[power/wakeup]: https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-devices-power
[per device wakeup count]: https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-devices-power
[i8042 driver]: https://github.com/torvalds/linux/blob/HEAD/drivers/input/serio/i8042.c#L577
[cros\_ec\_keyb.c]: https://chromium.googlesource.com/chromiumos/third_party/kernel/+/chromeos-4.4/drivers/input/keyboard/cros_ec_keyb.c#278
[input devices that powerd polls]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/power_manager/powerd/system/input_watcher.cc#394
[`HandleUserActivity`]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/power_manager/dbus_bindings/org.chromium.PowerManager.xml#61
[`SuspendDone`]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/power_manager/dbus_bindings/org.chromium.PowerManager.xml#205
[wake-capable parent]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/power_manager/powerd/system/udev.cc#257
[mfd devices]: https://www.kernel.org/doc/Documentation/devicetree/bindings/mfd/mfd.txt
[monitors the wakeup-count]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/power_manager/powerd/system/wakeup_device.cc
[checks the wakeup count]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/power_manager/powerd/system/dark_resume.cc#54
[snapshot of wakeup count]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/power_manager/powerd/system/input_watcher.cc#241
[mfd/cros\_ec.c]: https://chromium.googlesource.com/chromiumos/third_party/kernel/+/chromeos-4.14/drivers/mfd/cros_ec.c
[notifies all the interested drivers]: https://chromium.googlesource.com/chromiumos/third_party/kernel/+/chromeos-4.14/drivers/mfd/cros_ec.c#71
[increment the wakeup count]: https://chromium.googlesource.com/chromiumos/third_party/kernel/+/chromeos-4.14/drivers/input/keyboard/cros_ec_keyb.c#278
[`/sys/power/wakeup_count`]: https://chromium.googlesource.com/chromiumos/third_party/kernel/+/chromeos-4.14/kernel/power/main.c#545
[combined_event_count]: https://chromium.googlesource.com/chromiumos/third_party/kernel/+/chromeos-4.14/drivers/base/power/wakeup.c#39
[per-device wakeup count has been fixed]: https://github.com/torvalds/linux/commit/2d5ed61ce9820a1fe7b076cc45c169524d767746
[patchset by alan]: https://chromium-review.googlesource.com/c/chromiumos/third_party/kernel/+/1121663/2
[`DarkSuspendImminent`]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/power_manager/dbus_bindings/org.chromium.PowerManager.xml#219
[`HandleDarkSuspendReadiness`]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/power_manager/dbus_bindings/org.chromium.PowerManager.xml#145
[input devices]: https://www.kernel.org/doc/Documentation/input/input.txt
[monitoring this specific input device]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/power_manager/powerd/system/input_watcher.cc#479
[power_WakeSources]: https://chromium.googlesource.com/chromiumos/third_party/autotest/+/HEAD/server/site_tests/power_WakeSources/README.md
[chromium bug]: https://bugs.chromium.org/p/chromium/issues/list
[shutdown-from-suspend]: ./shutdown_from_suspend.md
