# CrOS bootstat

This is the Chromium OS 'bootstat' utility.  The utility is used
to generate timestamps and other performance statistics during
system boot.

## CLI Specification

### bootstat

```sh
bootstat <event-name>
```

This command gathers and records the contents of `/proc/uptime` and disk
statistics for the boot disk (the full disk, not the boot partition), and
associates the data with the passed in `<event-name>`.

### bootstat_get_last

```sh
bootstat_get_last <event-name> [ <stat> [before <value>] ... ]
```

Print on standard output the value of the selected statistics recorded when
the specified event occurred.  These are the available statistics:

*   `time`: Total time since kernel startup at the time of the event.
*   `time-ms`: Total time since kernel startup at the time of the event
    converted to milliseconds.
*   `read-sectors`: Total sectors read from any partition of the boot device
    since kernel startup.
*   `write-sectors`: Total sectors written to any partition of the boot device
    since kernel startup.

If multiple statistics are requested, they are reported in order, one
per line.  If no statistics are listed on the command line, the
default is to report `time`.

If an event has occurred more than once since kernel startup, only
the statistics from the last occurrence are reported.

If the `before` <value> option is specified after the statistics name the
reported event will be from the last occurrence having value less than the
specified `before` value. This way for time events it returns the last event
happened before the specified time. For the sectors count statistics it will
return values that are strictly less than the value specified.

## API Specification

The C and C++ API is defined in [`bootstat.h`](./bootstat.h).
See that header for specification details.

## Design and Implementation Details

Uptime data are stored in a file named `/tmp/uptime-<event-name>`;
disk statistics are stored in a file named `/tmp/disk-<event-name>`.
This convention is a concession to pre-existing code that depends on
these files existing with these specific names, including the
[platform.BootPerf] test, the boot-complete upstart job,
and the Chrome code to report boot time on the login screen.

New code should treat the file names as an implementation detail,
not as the interface.  You should not add new code that depends on
the file names; instead, you should enhance the bootstat command
and/or library to provide access to the data you need.

[platform.BootPerf]: https://chromium.googlesource.com/chromiumos/platform/tast-tests/+/HEAD/src/chromiumos/tast/remote/bundles/cros/platform/boot_perf.go
