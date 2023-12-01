# Chrome OS Inactivity Delays

By default, the power manager performs various actions when the system is
inactive for a given period of time:

| Power source | Smart Dim | Dim screen | Turn screen off | Suspend / sleep |
|--------------|-----------|------------|-----------------|-----------------|
| Battery      | early     |  5 minutes |  5.5 minutes    |  6.5 minutes    |
| AC           | early     |  7 minutes |  7.5 minutes    |  8.5 minutes    |
| Battery      | defer     | 10 minutes | 10.5 minutes    | 11.5 minutes    |
| AC           | defer     | 14 minutes | 14.5 minutes    | 15.5 minutes    |

At the half point of inactivity delay, the [Smart Dim] ML model will predict
whether the user is likely to remain inactive and tell powerd to dim screen
early or defer dim accordingly.

There are different ways to define "activity":

-   User activity (keyboard or touchpad events or other events that indicate a
    human is present, like changing the power source or connecting or
    disconnecting an external display)
-   Video activity (currently defined as 15 or more 333x250 or larger updates
    within a second in an active tab in an onscreen window)
-   Audio activity (currently defined as active output streams)

User activity and video activity block all of the above actions from being
performed. The screen will still dim and be turned off while audio is being
played, but the system will not suspend. Once activity ceases, the inactivity
timer starts again.

When the suspend delay is reached while no user is logged in and the system is
on battery power, the system will shut down instead of suspending.

As of M41, if the lock screen is displayed, the screen will be dimmed after just
30 seconds of inactivity and turned off after 40 seconds as described in [issue
190499].

Several events can result in the above delays being lengthened (specifically,
the screen-dimming delay is doubled and the other delays' distances from the
dimming delay are maintained; for example, on battery, the delays are changed to
10/11/15 minutes):

-   An external monitor is connected
-   User activity occurs while the screen is dimmed or soon after it is turned
    off (delays are reset after the current user logs out)

If the "Require password to wake from sleep" setting is enabled, the screen will
be locked ten seconds after the screen is turned off due to inactivity (in
addition to being locked immediately before the system suspends when the lid is
closed).

As of M71, an ML model has been enabled to run in Chrome to predict whether a
screen dim should be deferred. When powerd is about to dim the screen in
response to user inactivity, the model will predict whether the user is likely
to reactivate the device after dimming. If reactivation seems likely, Chrome
will tell powerd to defer dimming. To reduce the risk of incorrect predictions
keeping the system awake indefinitely, dimming will only be deferred once until
the user begins interacting with the system again. When the model is enabled,
powerd's delay-doubling behavior for "presentation mode" or user activity is
disabled.

The above delays and actions can be configured by Chrome and are sent to the
power manager as `PowerManagementPolicy` protocol buffers via D-Bus. Chrome's
settings are controlled by "Power management" [enterprise policies] and by the
[chrome.power extension API].

On a running system, `/var/log/power_manager/powerd.LATEST` should contain
enough details to understand why a given action was taken. This file is
accessible via `chrome://system` or by browsing to `file://var/log`.

## Further reading

-   `src/platform2/system_api/dbus/power_manager/policy.proto`: definition of
    `PowerManagementPolicy` protocol buffer
-   `src/platform2/power_manager/powerd/policy/state_controller.{h,cc}`:
    `StateController` class in power manager; responsible for managing delays

[issue 190499]: https://crbug.com/190499
[enterprise policies]: https://cloud.google.com/docs/chrome-enterprise/policies
[chrome.power extension API]: https://developer.chrome.com/extensions/power.html
[Smart Dim]: https://chromium.googlesource.com/chromium/src/+/HEAD/chrome/browser/ash/power/ml/smart_dim
