# Chrome OS Screen Brightness Behavior

[TOC]

This document describes how `powerd` manages the display's backlight brightness.
For the vast majority of devices this is the internal display of the device, but
for a small set of devices (e.g., Chromeboxes) this may be an external display.

## Brightness calculations

`powerd` internally deals with two types of brightness values:

*   A user-visible *brightness percentage*, represented as a value between 0%
    and 100%.

*   A hardware-specific *brightness level*, used by the drivers and kernel.

The two values do not have a linear relationship. Instead, given a
hardware-specific minimum-visible level and maximum level, the mapping from a
user-visible percentage `percent` to the hardware level `level` is calculated as
follows:

```
fraction = (percent - 6.25) / (100 - 6.25)
linear_level = fraction²
level = min_visible_level + linear_level * (max_level - min_visible_level)
```

See `policy::InternalBacklightController::PercentToLevel()` for the full
implementation.

In this document, we refer to the hardware level as a *hardware level*,
and the brightness *non-linear brightness percent*. The intermediate
calculation *linear level* is also discussed: this roughly corresponds
to the fraction of the display is driven at, where zero is "minimum
visible level" and one is "full brightness".

## Automatic brightness changes

By default, powerd will automatically choose a backlight brightness based on the
current power source (AC / battery), and the level of ambient light (direct
sunlight / something dimmer than that). When the one of these changes, powerd
will transition to a new brightness level.

The automatically-chosen non-linear brightness percentages are as follows:

| Power source | Direct sunlight (>= 400 lux) | Normal ambient light |
|--------------|------------------------------|----------------------|
| AC           | 100% (100% linear)           | 80% (~62% linear)    |
| Battery      | 80% (~62% linear)            | 63% (~37% linear)    |

Devices that lack ambient light sensors just use the "normal ambient light"
levels listed above. Note that these levels may be set differently for different
devices.

In the past, powerd made continuous adjustments to the screen brightness based
on the ambient light level. This was distracting to users and also generally
ineffective: the majority of indoor environments occupy the bottom end of the
range reported by our ambient light sensors. Due to the coarse readings within
this range, the automatically-chosen brightness levels were frequently
undesirable. We decided to switch to just two levels: one that would work well
in most indoor environments, and a very-bright level for outdoor environments.

### Improved automatic brightness on some devices

Some devices, such as the Pixelbook, are equipped with a better ambient light
sensor. Such devices have a more finely-tuned configuration consisting of
seven levels as follows:

|Situation          |Lux Step Down|Lux Step Up|Brightness UI|Brightness Linear|
|-------------------|------------:|----------:|------------:|----------------:|
|Low light          |   *N/A*     |      90   |   36.14%    |      10.75%     |
|Indoor - normal    |      40     |     250   |   47.62%    |      20.00%     |
|Indoor - bright    |     180     |     360   |   60.57%    |      34.00%     |
|Outdoor - dark     |     250     |     500   |   71.65%    |      49.00%     |
|Outdoor - overcast |     350     |    1700   |   85.83%    |      72.24%     |
|Outdoor - clear sky|    1100     |    7000   |   93.27%    |      86.25%     |
|Direct sunlight    |    5000     |   *N/A*   |  100.00%    |     100.00%     |

Additionally, simple exponential smoothing is applied to the raw values read
from the ambient light sensor. This acts as a low-pass filter to remove noise
from the data, to avoid adjusting the brightness too frequently in some
lighting conditions such as an overhead source of warm white LED lighting.
[issue 826968]

In M88, a small number of devices were moved to an ML-based brightness control
logic. This logic is not hosted in powerd directly; rather, the [logic is in
Ash][ml-backlight], which calculates a desired backlight level and
communicates the result to powerd via a D-Bus API.

## Manual brightness changes

Before the user has touched a brightness key, the brightness will update
automatically based on ambient light or when AC power is connected or
disconnected. However, when the user presses the brightness-up or
brightness-down keys, powerd animates to the requested level and stops making
further ambient-light-triggered or power-source-triggered automated adjustments
until the system is rebooted.

A single user-configured brightness is tracked for both AC and battery power;
once the user has adjusted the brightness via the brightness keys, the
brightness remains at that level until the next time the system boots. (Prior to
M36, separate user-configured levels were maintained for AC and battery power --
see [issue 360042].) There are 16 user-selectable
brightness steps, divided evenly between the full non-linear percentage-based
range (i.e. each button press moves the brightness by 100 / 16 = 6.25%). The
brightness popup that appears when a button is pressed actually contains a
draggable slider that can be used to select a brightness percentage that doesn't
match one of the pre-defined steps.

In the past, the previous user-configured level was restored at boot, but this
was deliberately removed. A given device is frequently used in many different
environments: dark rooms, well-lit rooms with lots of ambient light, etc. We
decided that always booting with a reasonable default brightness was preferable
to sometimes restoring a blindingly-high brightness when booting in a dark room
or restoring an extremely-dim brightness when booting in a bright room.

## Screen dimming and power off

When the user is inactive for an extended period of time, the screen is dimmed
to 10% of its maximum level (computed linearly) and then turned off. The screen
is turned back on in response to user activity (which is interpreted broadly:
keyboard or touchpad activity, power source change, external display being
connected or disconnected, etc.).

Users may reduce the backlight brightness to 0% using the brightness-down (F6)
key; this may be desirable to conserve battery power while streaming music. The
backlight is automatically increased to a low-but-visible level when user input
is observed after the brightness has been manually set to 0%.

## Boot time brightness selection

At boot, the panel backlight's brightness is set to 40% (computed linearly) of
its maximum level by the `boot-splash` Upstart job. This happens before the boot
splash animation is displayed by frecon.

After powerd starts, it chooses an initial backlight brightness based on the
power source (either AC or battery) and the ambient light level, as described in
the "Automatic brightness changes" section.

## External monitor brightness

As of M35, Chromeboxes' brightness keys (or F6 and F7 keys) attempt to use
[DDC/CI] to increase or decrease external displays' brightness ([issue 315371]).

[issue 360042]: https://crbug.com/360042
[DDC/CI]: https://en.wikipedia.org/wiki/Display_Data_Channel#DDC.2FCI
[issue 315371]: https://crbug.com/315371
[issue 826968]: https://crbug.com/826968
[ml-backlight]: https://source.chromium.org/chromium/chromium/src/+/main:chrome/browser/ash/power/auto_screen_brightness/;drc=332308c0de709e7872c1ad93589bcfc40d555f9e
