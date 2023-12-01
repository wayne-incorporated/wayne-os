# Chrome OS Keyboard Backlight Behavior

On devices that possess backlit keyboards, powerd is responsible for adjusting
the backlight brightness.

## Backlight triggers

For most devices, the backlight is turned on in response to the user activity
(including keyboard presses, touchpad events, or plugging/unplugging the device
into AC) instead. After user activity stops, the backlight remains on for
a period of time (the duration is supplied by the
`keyboard_backlight_keep_on_ms` preference, which defaults to 30 seconds), and
then fades to off.

A small number of devices have sensors capable of detecting when the user's
hands are hovering over it. For such devices, the backlight turns on when the
user's hands are hovering over the device, and then remains on for a further
period of time, again controlled by the `keyboard_backlight_keep_on_ms`
preference.

### Full screen video

When full screen video is detected, powerd turns the keyboard backlight off more
quickly so as to not distract the user. This time is configured by the
`keyboard_backlight_keep_on_during_video_ms` preference, which defaults to three
seconds.

## Backlight brightness

Powerd reads raw percentages from `keyboard_backlight_user_steps` preference,
scales the first step as 0%, second step as 10% and last step as 100%, and
calculates the rest of the scaled percentages linearly.

If an ambient light sensor is present, powerd uses its readings to determine the
keyboard backlight brightness level. In a well-lit environment, the backlight is
turned off. In a dark environment, the backlight is turned on at a moderate
level (pursuant to user activity, as described below). The ambient light ranges
and corresponding backlight brightness percentages are read from the
`keyboard_backlight_als_steps` preference. The percentages in this preference
should be scaled percentages.

If no ambient light sensor is present, powerd reads a single brightness
percentage from the `keyboard_backlight_no_als_brightness` preference and uses
that instead when the backlight is turned on. The percentage in this preference
should be scaled percentage.

## Manual brightness adjustments

The user is able to adjust the keyboard backlight brightness by holding Alt
while pressing the Brightness Up or Brightness Down keys. The brightness moves
between the raw percentage steps in the `keyboard_backlight_user_steps`
preference. On the UI, the keyboard backlight brightness controller bar moves
between the scaled percentage steps. Once the user has manually adjusted the
brightness, powerd refrains from making any automated adjustments until the
system reboots. The backlight will still be dimmed or off for extended periods
of inactivity, but this becomes based on the longer timeouts used to dim the
display, and not the shorter timeouts used by default.

On devices that have it on their keyboard, pressing the keyboard backlight
toggle key turns the keyboard backlight on/off. Toggling the keyboard backlight
on/off is functionally the same as forcing it on/off, with two differences.
First, if a user-initiated brightness adjustment, e.g. an increase or decrease,
is made while we're toggled off, we are no longer toggled off.  Second,
a brightness change signal is emitted any time the user changes the toggle
state, even if the brightness percentage has not changed.

## Historical behaviors

Prior to M52 (mid 2016), for devices without a hover sensor, the keyboard
backlight used to turn on and off in lock-step with the display.
https://crrev.com/c/340927 changed the behavior to turn off the backlight more
quickly after user activity ceased to reduce power consumption.
