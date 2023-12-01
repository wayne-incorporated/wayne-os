# Chrome OS Power Manager Logging

## Locations

powerd writes logs to the `/var/log/power_manager` directory. It creates a new
file every time it starts and updates `powerd.LATEST` and `powerd.PREVIOUS`
symlinks to point to the current and previous files. These files can be viewed
on a live non-dev-mode system by browsing to `file:///var/log/power_manager`
(note the triple slashes).

Any output written to `stdout` or `stderr` (including messages that are printed
before the logging library has been initialized, and output from other
executables that powerd runs) is redirected to `/var/log/powerd.out`.

Output from the `powerd_suspend` script, along with suspend- and resume-related
kernel messages, are written to `/var/log/messages`.

## Interpreting logs

powerd logs detailed information about what it's doing and why. Each line begins
with a header similar to `[1219/195923:INFO:input_watcher.cc(430)]`:

*   The first four digits are the zero-prefixed month and day-of-month in the
    system's local time zone.
*   The next six digits are zero-prefixed hours, minutes, and seconds.
*   The next string, `INFO`, `WARNING`, or `ERROR`, describes the severity of
    the message.
*   The next string is the name of the file within the powerd source code that
    logged the message.
*   The final number in parentheses is the line in the file that logged the
    message.

Here are examples and explanations of some of the more-useful messages (with
date/time and file/line prefixes omitted):

*   `On battery at 81% (displayed as 83%), 4.242/5.248Ah at 0.483A, 8h19m9s
    until empty (7h54m27s until shutdown)`

    powerd periodically polls sysfs for power supply information. This line
    includes information about the battery's state, whether it's charging or
    discharging, and the estimated time until the battery will be empty/full or
    until the system will shut down automatically. If a charger is connected,
    additional information about it is included. The "displayed as" percentage
    indicates what will be displayed in the UI after the actual percentage has
    been adjusted to compensate for trickle charging.

*   `User activity reported`

    powerd periodically logs user activity (i.e. input events), which (along
    with video and audio activity) can affect [inactivity delays].

*   `Video activity reported`

    Chrome attempts to detect video activity (defined as frequent updates to a
    fixed region of a window). When it believes a video is being played, it
    notifies powerd.

*   `Audio activity started`

    [CRAS] notifies powerd about changes to audio output streams. Audio activity
    is defined as the existence of one or more active output streams.

*   `Received updated external policy: ac_dim=0s ac_screen_off=0s ac_lock=0s
    ac_idle_warn=0s ac_idle=30m battery_dim=0s battery_screen_off=0s
    battery_lock=0s battery_idle_warn=0s battery_idle=10m ac_idle=no-op
    battery_idle=no-op lid_closed=suspend use_audio=1 use_video=1
    presentation_factor=2.0 user_activity_factor=2.0
    wait_for_initial_user_activity=0
    force_nonzero_brightness_for_user_activity=1 (Prefs, Playing video, Playing
    audio)`

    This lengthy line describes a power management policy that Chrome sent to
    powerd:

    *   The first set of values describe various [inactivity delays].
    *   The next `ac_idle`, `battery_idle`, and `lid_closed` values describe
        actions to be taken when the system is deemed idle on AC or battery
        power or its lid is closed.
    *   `use_audio` and `use_video` describe whether powerd should adjust its
        behavior in response to audio and video activity.

    See [policy.proto] for descriptions of all of the fields. The final
    parenthesized list describes Chrome's reasoning in constructing this policy.
    In this case, power-management-related prefs were set, HTML5 video was
    playing (this is distinct from the inferred "video activity" described
    above), and HTML5 audio was playing (also distinct from CRAS-reported "audio
    activity").

*   `Updated settings: dim=0s screen_off=0s lock=0s idle_warn=0s idle=10m
    (no-op) lid_closed=suspend use_audio=1 use_video=1 wake_locks=screen`

    This line describes the actual settings that powerd is currently using.
    These are based on the external policy described above, but also take into
    the current power source and other state. See the [StateController] class
    for the implementation.

Most other messages are hopefully self-explanatory, but more context can be
found by looking at the code (a filename and line number are embedded at the
beginning of each message).

## Guidelines

powerd receives input (e.g. user/video/audio activity, lid events, etc.) and
performs actions sporadically; thirty-second intervals where nothing happens are
common for an idle system. Having logs of these events is essential to
reconstruct the past when investigating user feedback reports.

powerd's unit tests, on the other hand, send a bunch of input very quickly.
Logging all events drowns out the rest of the testing output.

To produce useful output when running in production while producing readable
output from tests, powerd logs messages at the `INFO` level and above by
default, while unit tests log `WARNING` and above.

Please use logging macros as follows within powerd:

| Macro          | Usage |
|----------------|-------|
| `VLOG(1)`      | Debugging info that is hidden by default but can be selectively enabled by developers |
| `LOG(INFO)`    | Input from other systems or actions performed by powerd (i.e. things that would be useful when trying to figure out what powerd was thinking when investigating a bug report) |
| `LOG(WARNING)` | Minor errors (e.g. bad input from other daemons) |
| `LOG(ERROR)`   | Major errors (e.g. problems communicating with the kernel) |
| `LOG(FATAL)`   | Critical problems that make powerd unusable or that indicate problems in the readonly system image (e.g. malformed preference defaults) |
| `CHECK(...)`   | Same as `LOG(FATAL)` |

[inactivity delays]: inactivity_delays.md
[CRAS]: https://www.chromium.org/chromium-os/chromiumos-design-docs/cras-chromeos-audio-server
[policy.proto]: https://chromium.googlesource.com/chromiumos/platform2/system_api/+/HEAD/dbus/power_manager/policy.proto
[StateController]: ../powerd/policy/state_controller.h
