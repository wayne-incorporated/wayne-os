# Chrome OS Shutdown and Reboot

This document describes why and how Chrome OS devices shut down or reboot.

> "Shut down" is a verb. "Shutdown" is a noun.

## Why we shut down

### Requests from other processes

Shutdown and reboot are initiated on Chrome OS devices through `RequestShutdown`
or `RequestRestart` D-Bus method calls to `powerd`. These methods are typically
called by Chrome in response to requests from the user, but they can also be
invoked by other processes in some cases (e.g. by `update_engine` to reboot to
apply a system update, or by shell scripts in the lab to reboot devices that
don't have working network connections).

Both D-Bus methods accept two arguments:

*   an int32 `power_manager::RequestShutdownReason` or
    `power_manager::RequestRestartReason` value from the [powerd constants file]
    in `system_api`
*   a string containing a human-readable description of the reason for the
    request

`powerd` logs both arguments to the [current log file] within
`/var/log/power_manager` before handling the request; look for messages like
these near the end of the file:

```
[0429/234951:INFO:daemon.cc(1175)] Got RequestShutdown message from :1.62 with reason user-request (UI request from ash)
```

```
[0425/211426:INFO:daemon.cc(1046)] Got RequestRestart message from :1.33 with reason system-update (update_engine applying update)
```

#### Sending DBus Method Calls from the CLI

Shutdown and reboot DBus method calls can be triggered in the CLI with:

* `powerd_dbus_shutdown`
* `powerd_dbus_reboot`

These executables send the `RequestShutdown` or `RequestRestart` method calls,
respectively, and can be used to test `powerd` or gracefully shutdown/reboot the
device.

### Requests within `powerd`

`powerd` may also decide to shut the system down without input from other
processes in some cases, including:

*   the battery charge dropping below its shutdown threshold
*   the lid being closed while Chrome has sent a policy requesting a lid-closed
    action of "shut down" (e.g. because the login screen is displayed)
*   the kernel repeatedly failing to suspend
*   the power button being pressed while no displays are connected

In all cases, `powerd` will also log a terse message just before it shuts down
or reboots:

```
[0429/234952:INFO:daemon.cc(1606)] Shutting down, reason: user-request
```

```
[0425/211426:INFO:daemon.cc(1263)] Restarting, reason: system-update
```

## How we shut down

`powerd`'s [Daemon] class runs [powerd_setuid_helper], its setuid-root helper
binary, with `--action=shut_down` or `--action=reboot`. `powerd_setuid_helper`
runs:

```
initctl emit --no-wait runlevel RUNLEVEL=<runlevel> SHUTDOWN_REASON=<reason>
```

to instruct [Upstart] to either shut down (runlevel 0) or reboot (runlevel 6) the
system. The `SHUTDOWN_REASON` argument contains a short dash-separated string
describing the reason for the request.

The Upstart [halt job] or [reboot job] is triggered by the runlevel change. This
triggers a cascade of other jobs within Upstart's `/etc/init` directory. The
[pre-shutdown job] logs a message to `/var/log/messages` to make it easier to
see when and why the system shut down or rebooted while examining logs:

```
2018-04-24T21:30:08.513032-07:00 NOTICE pre-shutdown[22132]: Shutting down for reboot: not-via-powerd
```

> In the above case, `not-via-powerd` indicates that this clean reboot was
> initiated by the `reboot` command being run directly rather through powerd.
> Requests should always go through `powerd` when possible, both for consistency
> and for correctness (e.g. `powerd` knows to defer shutting down if a firmware
> update is in progress).

After other jobs have completed, the `halt` or `reboot` job executes the
[chromeos_shutdown] script. `chromeos_shutdown` handles various tasks:

*   Remaining processes are killed.
*   Partitions are unmounted.
*   If powerd passed a `SHUTDOWN_REASON` argument with value `low-battery`, the
    [display_low_battery_alert] script is executed to use [frecon] to display a
    brief animation before shutting down.

Finally, the `halt` or `reboot` job executes the `halt` or `reboot` command with
`--force` to instruct the kernel to immediately halt or reboot the system.

[powerd constants file]: https://chromium.googlesource.com/chromiumos/platform2/system_api/+/HEAD/dbus/power_manager/dbus-constants.h
[current log file]: logging.md
[Daemon]: ../powerd/daemon.cc
[powerd_setuid_helper]: ../powerd/powerd_setuid_helper.cc
[Upstart]: http://upstart.ubuntu.com/
[halt job]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/init/upstart/halt/halt.conf
[reboot job]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/init/upstart/reboot.conf
[pre-shutdown job]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/init/upstart/pre-shutdown.conf
[chromeos_shutdown]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/init/chromeos_shutdown
[display_low_battery_alert]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/init/display_low_battery_alert
[frecon]: https://chromium.googlesource.com/chromiumos/platform/frecon/
