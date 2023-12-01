# Chrome OS Adaptive Charging

## Delaying Charge

Since maintaining a full charge on a lithium-ion battery is detrimental to its
long-term capacity, [Adaptive Charging] will delay charging at 80% charge as
long as an ML model predicts that the charger will not be unplugged within 2
hours.

Charging is delayed via the Battery Sustainer feature in the EC. This is run via
the command `ectool chargecontrol normal <lower> <upper>`. `lower` is the lower
limit battery percent, and `upper` is the upper limit for the battery percent.
The battery will charge and discharge between these two charge values while the
Battery Sustainer is active. If `lower` and `upper` are the same, the charger
will idle (no current to or from the battery) while at that charge.

## Prediction

The prediction of when the system will be unplugged from the AC power source is
handled via the `org.chromium.MachineLearning.AdaptiveCharging DBus service`.
The power manager requests predictions from this service every 30 minutes. It
creates a probability for each of the next 8 hours, plus a prediction for
anytime greater than 8 hours, on whether the AC charger will be unplugged then.
If the largest probability is at least `adaptive_charging_min_probability`,
charging will be delayed up until 2 hours before the charger is expected to be
unplugged (the hour associated with the highest probability).

## Notifying the User

The user will be notified of any delays when the `display_battery_percentage`
reaches 80%, if charging will be delayed.

## Enabling

The feature is enabled by default for systems with firmware support for
maintaining specific battery charge percentages, and waking from sleep on AC
plug and unplug.

The Settings app contains a toggle for enabling/disabling the feature under the
Power section. This triggers a policy update via the [PowerManagementPolicy]
proto for the power manager. These fields are available to Chrome to manage
Adaptive Charging settings:

*   `adaptive_charging_enabled` - bool that enables/disables Adaptive Charging.
*   `adaptive_charging_hold_percent` - Change the battery percentage at which to
    delay charging. Default value of `80`. Valid values are within [1, 99].
*   `adaptive_charging_min_probability` - Change the min probability that is
    required from the prediction to delay charging. Default value of `0.2`.
    Valid values are within [0.0, 1.0].

## Slow Charging

As quick charging of a lithium-ion battery is detrimental to its capacity and
ability to retain charge over time, slowing down charging where possible is
beneficial for long-term battery health. Slow charging is a feature implemented
in Adaptive Charging to limit the charge current to the battery when charging
commences after the period of delay at 80% charge.

When slow charging is enabled, Adaptive Charging will delay charging at 80%
charge up until 3 hours before the charger is expected to be unplugged. A charge
current limit of 0.1C (i.e., 10% of the battery's design capacity per hour) will
be set when charging commences after the delay period. If the unplug time
prediction moves earlier while slow charging, resulting in insufficient time to
finish charging using the limited charge current, the charge current limit will
be removed.

The charge current limit is set via the EC and is run using the command `ectool
chargecurrentlimit <max_current_mA>` where `max_current_mA` is the maximum
charge current that will be supplied to the battery.

The slow charging feature is yet to be launched and will be rolled out gradually
via Finch, the Chrome experimentation framework.

[Adaptive Charging]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/power_manager/powerd/policy/adaptive_charging.h
[PowerManagementPolicy]: https://chromium.googlesource.com/chromiumos/platform2/system_api/+/HEAD/dbus/power_manager/policy.proto
