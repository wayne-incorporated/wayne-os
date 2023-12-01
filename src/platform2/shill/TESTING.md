# Testing Shill

## Introduction to shill testing

We test shill using unit tests and integration tests. The unit tests are built
using [Google Test](https://github.com/google/googletest) and [Google
Mock](https://github.com/google/googletest/tree/HEAD/googlemock). The
integration tests use [Tast] and [Autotest].

### Running unit tests for Chrome OS

Shill unit tests are run just like any other unit test in the platform2
directory. See the [platform2 unittest docs] for more information.

### Running integration tests

There are a variety of integration tests for shill, using either [Tast] or
Autotest. WiFi autotests mostly require a special test AP setup (see [Autotest
wificell documentation]).

### Debug logs

Most networking-related daemons (including shill and its subprocesses) log to
syslog, redirected to `/var/log/net.log`. Syslog prefixes log messages with the
process name, so one can filter for `shill`, `wpa_supplicant`, etc., depending
on what you're looking for.

Shill has many log severities, and they go to various places:

*   Critical messages (`ERROR`-level and higher) go to the main
    `/var/log/messages` as well as to `net.log`.
*   Informational messages (`INFO` and lower) go only to `net.log`.
*   `VERBOSE` messages (e.g., all those produced by `SLOG()`) are silent by
    default.

#### Verbose messages

In case you don't think shill's logging is verbose enough already, there are
plenty of more-verbose log messages that can be enabled dynamically.

**Scopes**: there a variety of component-specific scopes that can be enabled,
like `wifi`, `ethernet`, or `dbus`. One can manipulate the current running
instance of shill with the `ff_debug` tool. Settings do not survive daemon
restart.

```bash
# Enable ethernet scope.
ff_debug +ethernet
# Disable dbus scope.
ff_debug -dbus
# List all valid scope tags.
ff_debug --list_valid_tags
```

**Levels**: by default, shill logs at level 0 (i.e., everything INFO or
higher). Negative numbers represent VERBOSE (i.e., from `SLOG()`) levels.

```bash
# Enable SLOG(<tag>, 2) and SLOG(<tag>, 1) messages, if <tag> is in the enabled
# scopes list.
ff_debug --level -2
# Only log FATAL messages
ff_debug --level 4
# See ff_debug --help for more.
```

The shill upstart job also accepts a few environment variables, so you can see
verbose messages even at startup:

```bash
# Stop shill and restart it with WiFi debugging at level -2.
stop shill; start shill SHILL_LOG_LEVEL=-2 SHILL_LOG_SCOPES=wifi
```

`wpa_supplicant` also has its own logging verbosity; shill will change this
dynamically at times (e.g., when it thinks there are WiFi connection issues),
but you can change these manually with the `wpa_debug` command. See `wpa_debug
--help` for more info.

*** note
Note that integration tests may adjust logging verbosity automatically,
depending on their needs.
***

[platform2 unittest docs]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/platform2_primer.md#running-unit-tests
[Tast]: https://chromium.googlesource.com/chromiumos/platform/tast/
[Autotest]: https://dev.chromium.org/chromium-os/testing/autotest-developer-faq
[Autotest wificell documentation]: https://chromium.googlesource.com/chromiumos/third_party/autotest/+/HEAD/docs/wificell.md
