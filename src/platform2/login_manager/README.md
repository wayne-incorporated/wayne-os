# Chrome OS Session Manager

`session_manager` is responsible for managing the lifecycle of the Chrome
process. It confusingly lives in the `login_manager` directory and is installed
by the [chromeos-login] package.

`session_manager` communicates with other processes using [D-Bus]. It owns the
service name `org.chromium.SessionManager` at service path
`/org/chromium/SessionManager` and exports an interface named
[`org.chromium.SessionManager`](dbus_bindings/org.chromium.SessionManagerInterface.xml).

This document contains an overview of what `session_manager` does. See the
[docs](docs/) directory for more information.

## Startup

The [`ui`](init/upstart/ui.conf) Upstart job is responsible for running
`session_manager`. Before executing it, it runs
[`ui-pre-start`](init/scripts/ui-pre-start) to create necessary files and
directories.

`session_manager` constructs a command line for running Chrome and fork-execs
it. The command line is built by [`chrome_setup.cc`](chrome_setup.cc) and
`libchromeos-ui`'s [ChromiumCommandBuilder] class. The command line's contents
are dependent on the presence of various [USE flags]. The
[libchromeos-use-flags] package lists a number of USE flags in its `IUSE`
variable; at build-time, it writes all of the set flags to
`/etc/ui_use_flags.txt`. `session_manager` then reads this file at startup.
(Generating `ui_use_flags.txt` in a tiny ancillary package rather than in
`chromeos-login` avoids the need to build a different copy of the
`chromeos-login` package for every board.)

Developers should take note of [`/etc/chrome_dev.conf`](chrome_dev.conf), a
configuration file that may be modified on-device to add or remove flags from
Chrome's command line. The file contains documentation about its format.

After Chrome has displayed its login prompt, it calls `session_manager`'s
`EmitLoginPromptVisible` D-Bus method. `session_manager` writes a
`login-prompt-visible` bootstat event, emits a `LoginPromptVisible` D-Bus signal
on its interface, and makes an asynchronous D-Bus call to Upstart to tell it to
emit a `login-prompt-visible` event; this latter event is used to trigger other
jobs.

## Login

When the user successfully logs in within Chrome, Chrome calls
`session_manager`'s `StartSession` D-Bus method and emits a
`start-user-session` upstart signal. `session_manager` makes an
asynchronous D-Bus call to Upstart's `StartUserSession` method and emits a
`SessionStateChanged` D-Bus signal on its own interface.

Additional `SessionStateChanged` signals are emitted if additional users are
added to the session.

## Screen Locking

Other processes on the system may decide to lock the screen after the user has
logged in:

-   Chrome locks the screen in response to a request from the user, or just
    before the system suspends if the "Require password to wake from sleep"
    setting is enabled.
-   [powerd] locks the screen in response to [user inactivity].

To do this, these processes call `session_manager`'s `LockScreen` D-Bus method.
`session_manager` records the locked state internally, triggers the
`screen-locked` upstart signal, and calls Chrome's `ShowLockScreen` D-Bus method
via `org.chromium.ScreenLockService`. Once Chrome has successfully displayed the
lock screen it calls `session_manager`'s `HandleLockScreenShown` D-Bus method.
`session_manager` then emits a `ScreenIsLocked` D-Bus signal.

After the user successfully types their password to unlock the screen, Chrome
calls `session_manager`'s `HandleLockScreenDismissed` D-Bus method.
`session_manager` updates its internal state to record that the screen is no
longer locked and emits both a `screen-unlocked` upstart event and a
`ScreenIsUnlocked` D-Bus signal. Note that the lock events are not necessarily
followed by unlock events because the active session can crash in which case the
device is no longer locked.

## Logout

When the user signs out, Chrome calls `session_manager`'s `StopSession` D-Bus
method. `session_manager` sends `SIGTERM` to the browser process and waits (3
seconds, by default) for it to exit. If the process is still running, it sends
`SIGABRT`. `session_manager` then exits.

At this point, the [`ui-post-stop`](init/scripts/ui-post-stop) script runs. It
writes a `ui-post-stop` bootstat event and forcibly cleans up by sending
`SIGKILL` to any remaining `chronos` processes and killing orphaned containers.

The [`ui-respawn`](init/upstart/ui-respawn.conf) Upstart job then executes the
[`ui-respawn`](init/scripts/ui-respawn) script, which is responsible for
restarting the `ui` job.

## Crashes

If Chrome exits unexpectedly, `session_manager` typically restarts it (without
the `--login-manager` flag). If the screen was locked at the time of the crash,
`session_manager` instead ends the session to avoid exposing a logged-in desktop
on a potentially-unattended system.

If Chrome crashes repeatedly, `ui-respawn` reboots the system. If the crashes
continue, it stops rebooting the system with the hope that it'll eventually be
autoupdated to a new version that doesn't crash. See the
[`ui-respawn`](init/scripts/ui-respawn) script for specifics.

[D-Bus]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/dbus_best_practices.md
[chromeos-login]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/chromeos-base/chromeos-login/
[ChromiumCommandBuilder]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/chromeos-base/libchromeos-use-flags/
[USE flags]: https://www.chromium.org/chromium-os/how-tos-and-troubleshooting/portage-build-faq
[libchromeos-use-flags]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/chromeos-base/libchromeos-use-flags/
[powerd]: ../power_manager/
[user inactivity]: ../power_manager/docs/inactivity_delays.md
