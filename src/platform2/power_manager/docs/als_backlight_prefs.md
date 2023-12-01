# ALS + backlight powerd prefs

[TOC]

## Introduction
This document describes the interaction between `powerd` prefs related to ambient light sensors (ALS), backlights (both internal / panel and keyboard), and Ambient EQ.

## Keywords
|  |Description|
|--|-----------|
|ALS|Ambient light sensor.|
|`powerd` pref| Parameters in `powerd` that can be set per board or model. File name format is `internal_backlight_als_steps` in `powerd`.|
|[Default pref]|Part of `powerd` pref. Default value is in the file.|
|[Optional pref]|Part of `powerd` pref. Default value is in the code.|
|Panel|Internal display.|
|Ambient EQ|Color temperature of the internal display.|

## Powerd pref and chromeos_config
Used in the [order listed in Chrome OS Power Management FAQ]. If you intend to set a pref to a different value from in `powerd`, please set in `chromeos_config` and/or boxster. Links to pref files in `powerd` are provided as example values.

## No ALS
* No need to set [has_ambient_light_sensor] or set to 0.
* If necessary, set [internal_backlight_no_als_ac_brightness], [internal_backlight_no_als_battery_brightness].
### No keyboard backlight
* No need to set [has_keyboard_backlight] or set to 0.
### With keyboard backlight
* Set [has_keyboard_backlight] to 1.
* If necessary, set [keyboard_backlight_no_als_brightness].
* [Doc](https://chromium.googlesource.com/chromiumos/platform2/+/main/power_manager/docs/keyboard_backlight.md) explaining how keyboard backlight related prefs work.
## 1 ALS
* Set [has_ambient_light_sensor] to 1.
* If necessary, set [internal_backlight_als_steps] ([example](https://chromium-review.googlesource.com/c/chromiumos/overlays/board-overlays/+/1275349/2/overlay-nocturne/chromeos-base/chromeos-bsp-nocturne/files/powerd_prefs/internal_backlight_als_steps)).
* [Doc](https://chromium.googlesource.com/chromiumos/platform2/+/main/power_manager/docs/screen_brightness.md) explaining how internal display backlight related prefs work.
### No keyboard backlight
* No need to set [has_keyboard_backlight] or set to 0.
### With keyboard backlight
* Set [has_keyboard_backlight] to 1.
* If necessary, set [keyboard_backlight_als_steps].
## 2 ALS: 1 for internal display backlight, 1 for keyboard backlight
* In EC, make sure that ALS for internal display backlight has location `lid` ([example](https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/platform/ec/board/kohaku/board.c;l=342)) and ALS for keyboard backlight has location `base` ([example](https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/platform/ec/board/kohaku/board.c;l=309)).
* Set [has_ambient_light_sensor] to 2.
* Set [has_keyboard_backlight] to 1.
* If necessary, set [internal_backlight_als_steps] and [keyboard_backlight_als_steps].

## Summary of the above
|ALS|KB backlight|has_ambient_light_sensor|has_keyboard_backlight|Consider set other powerd prefs|
|---|------------|------------------------|----------------------|-------------------------------|
|0|N|0 or not set|0 or not set|internal_backlight_no_als_ac_brightness, internal_backlight_no_als_battery_brightness |
|0|Y|0 or not set|1|internal_backlight_no_als_ac_brightness, internal_backlight_no_als_battery_brightness, keyboard_backlight_no_als_brightness|
|1|N|1|0 or not set|internal_backlight_als_steps|
|1|Y|1|1|internal_backlight_als_steps, keyboard_backlight_als_steps|
|2|Y|2|1|internal_backlight_als_steps, keyboard_backlight_als_steps|

## Ambient EQ
Needs official sign off to enable Ambient EQ.
Make sure that the color ALS is well tuned, and set the coefficients in EC ([example](https://chromium-review.googlesource.com/c/chromiumos/platform/ec/+/1984893)).
On top of the settings above, set [allow_ambient_eq] to 1.

[order listed in Chrome OS Power Management FAQ]: https://chromium.googlesource.com/chromiumos/platform2/+/main/power_manager/docs/prefs.md#prefs
[Default pref]: https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/platform2/power_manager/default_prefs/
[Optional pref]: https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/platform2/power_manager/optional_prefs/
[has_ambient_light_sensor]: https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/platform2/power_manager/optional_prefs/has_ambient_light_sensor
[internal_backlight_no_als_ac_brightness]: https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/platform2/power_manager/default_prefs/internal_backlight_no_als_ac_brightness
[internal_backlight_no_als_battery_brightness]: https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/platform2/power_manager/default_prefs/internal_backlight_no_als_battery_brightness
[internal_backlight_als_steps]: https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/platform2/power_manager/default_prefs/internal_backlight_als_steps
[keyboard_backlight_als_steps]: https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/platform2/power_manager/default_prefs/keyboard_backlight_als_steps
[has_keyboard_backlight]: https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/platform2/power_manager/optional_prefs/has_keyboard_backlight
[keyboard_backlight_no_als_brightness]: https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/platform2/power_manager/default_prefs/keyboard_backlight_no_als_brightness
[allow_ambient_eq]: https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/platform2/power_manager/default_prefs/allow_ambient_eq
