# Suspend and Memory stress testing
*[go/suspend-stress-test]*

[TOC]

## Description

`suspend_stress_test` is a shell script that asks powerd to suspend the system
for a given number of seconds for configurable iterations. powerd then notifies
every interested daemon about imminent suspend. Once all daemons are ready for
suspend, powerd sets an RTC that fires after asked seconds and suspends either
to idle (S0iX) or ram (S3) based on the configuration of the device. Thus this
test helps us catch bugs in suspend/resume path of drivers and devices. This
test (with memory_check flag) also helps in verifying that memory does not get
corrupted during the suspend/resume process.

## Running

To run the test first [flash a test image] onto the device. Then execute the
following command on the device.

```sh
# suspend_stress_test
```

Note that this test suspends to ram (S3) or idle (S0iX) based on existing
configuration. Existing configuration can be verified using
`check_powerd_config`.

```sh
# check_powerd_config --suspend_to_idle; echo $?
```

If the above command returns 0, the device will suspend to idle (S0iX) otherwise
it will suspend to ram (S3). To configure the suspend state temporarily
for test, execute the following command. Writing 1 to the below file makes sure
device suspends to idle (S0iX). Writing 0 will make sure device suspends to
ram (S3).

```sh
# echo 0/1 > /var/lib/power_manager/suspend_to_idle
# restart powerd
```

This test by default runs 10000 cycles of suspend/resume. Number of iterations
can be configured using `count` option.

```sh
# suspend_stress_test --count=2500
```

Duration of suspend can be configured using `suspend_max` and `suspend_min`
options. Device spends random seconds between `suspend_min` and `suspend_max`
in S3/S0iX. If configured to same value, device spends the exact specified
time in suspend on every iteration.

```sh
# suspend_stress_test --count=2500 --suspend_min=5 --suspend_max=10
```

Note that this test generates several GB of logs. Most of the log includes
suspend/resume times of individual drivers on every suspend. If you are not
interested in suspend/resume times of individual drivers, you can turn that off
using the `nopm_print_times` option. Note that this is not recommended as it
will hide the exact driver that caused the suspend failure.

```sh
# suspend_stress_test --count=2500 --suspend_min=5 --suspend_max=10 --nopm_print_times
```

After running the test, check for any crashes in `/var/spool/crash`. Also check
if all functionality such as display, touchpad, Keyboard, mouse, media playback
etc. are still working as intended.

### Running memory stress test

Simply pass `memory_check` option to suspend_stress_test script to verify that
memory does not get corrupted during suspend/resume process.

```sh
# suspend_stress_test --count=2500 --suspend_min=5 --suspend_max=10 --memory_check
```

[go/suspend-stress-test]: http:/go/suspend-stress-test]
[flash a test image]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/developer_guide.md#Installing-Chromium-OS-on-your-Device
