# ChromiumOS Crash Reporter

This is the project for handling all crash related operations on the device.
The intention is to be as low-overhead as possible while still maximizing
the usefulness of crash reports and minimizing collection of any & all PII data.

For more background details, see the [original design doc](docs/design.md).
This document focuses on the current state of the project.

Most bugs/features can be found via [component:OS>Systems>CrashReporting
](https://bugs.chromium.org/p/chromium/issues/list?q=component:OS>Systems>CrashReporting).
We're in the process of migrating to buganizer:
[ChromeOS > Data > Engineering > Crash Reporting
](https://issuetracker.google.com/issues?q=status:open%20componentid:1032705)

[TOC]

## Data Consent

No crashes get collected without explicit consent from the device owner AND
the currently logged in user.  This is normally part of the OOBE setup flow (but
can also be controlled via OS Settings).

Consent is first set up by the device owner and covers all users of that device.
If no consent has been granted, then `crash_reporter`  will generally exit
rather than doing any further processing (e.g. running collectors). If the
device owner consents, users will be able to opt in or out as well, post M-103.
`metrics_library` determines whether the currently logged-in-user consents to
crash collection, with one exception: boot crash collection.

When the device kernel panics or otherwise forcibly reboots, we use the
`/home/chronos/boot-collect-consent` file to determine whether the user that was
signed in *at the time of the crash* consented to crash collection, since no
user will be logged in when the boot collector runs. If the last-logged-in user
consented to collection, we then fall back to device policy.

The only case where `crash_reporter` collects crashes even without consent is
for early crashes that occur before stateful partitions are mounted (because we
cannot check consent then). `crash_sender` still checks consent before it
uploads crashes.

Even if consent has been granted, there is one notable scenario where
crash reports are still not uploaded -- guest mode.
While system crashes are still collected (as they shouldn't have any user PII
in them), browser and user crashes are not uploaded.
This leads to a bit of a chicken & egg where real crashes in guest mode are not
caught and uploaded for tracking, but we're willing to accept that for the user
privacy guarantees.

*** aside
Crashes are technically collected, but because they are saved in the guest's
informal profile, they are all automatically thrown away on log out.
***

If consent is later revoked, we do not upload any crashes that had been queued.
In general, `crash_sender` will remove crashes that are present if consent is
revoked, but in some cases it will not: most notably, if a crash is stored to a
system directory (i.e., not in a cryptohome) and we're using per-user consent,
`crash_sender` keeps the report around in case it is associated with a
consenting user that later logs in again.

## Life Cycle

Setting up the crash reporter early in the boot process is tricky:
before the encrypted stateful mount is setup, crash reporter does not have
access to persistent storage to store crashes in.
We run [crash-reporter-early-init.conf] early in the boot process to configure
the kernel to pass crashes to us with an "early" flag to use a tmpfs path
instead of a persistent location for storing crash reports.

After the encrypted stateful mount setup is complete, we run
[crash-reporter.conf] which sets the crash path back to the persistent storage
crash directory and initializes any system state that depends on it.

Then during boot, but not in the critical path, we run [crash-boot-collect.conf]
to gather up any previous crashes in the system.
For example, if the system had rebooted due to a kernel panic, or some firmware
(like the [EC]) had crashed.
This also includes crashes that occurred during early boot before persistent
storage was available: such crashes are stored into `/run/crash_reporter/crash`
(or sometimes `/mnt/stateful_partition/reboot_vault/crash`)
and collected into `/var/spool/crash` once boot completes.

We run the [anomaly_detector] in the background to monitor for system
"anomalies" for which a notification mechanism is not available.
This daemon operates by monitoring syslog messages at a predefined interval.
Depending on the anomaly, it generates crashes and D-Bus signals.

We also run the [crash_sender] service in the background to periodically upload
crashes.  See [Uploading Crashes] for more details.

At this point, if no crashes occur, nothing ever happens!
And of course, since we never have bugs, that's precisely what happens!

If a userland crash occurs that would trigger a coredump, the kernel will
execute [crash_reporter] directly (via `/proc/sys/kernel/core_pattern`) and pass
in the coredump and some metadata.  We process it directly and queue the report
in the right crash directory.
The exact processing steps depend on the specific collector involved, so see
the [Collectors] section for more details.
See [Crash Report Storage] for more details on queuing.

If a Chrome (browser) process crashes, [crash_reporter] will be called by the
kernel, but we actually ignore that invocation.
Instead, Chrome itself will take care of processing that crash report before
calling [crash_reporter] with the final crash report for queuing.

Some hardware devices can trigger errors via udev, so we have a [udev rules]
file to trigger [crash_reporter] based on those.

## Source File Conventions

Each collector has a `xxx_collector.cc` and `xxx_collector.h` module.

The standalone programs (e.g. [crash_reporter], [crash_sender], and
[anomaly_detector]) have their own modules.

All unittests are named `xxx_test.cc` and contain tests for the corresponding
`xxx.cc` files.

All init related scripts live in the [init/] directory.

The [core_collector] program is kept separate because it's otherwise completely
standalone and doesn't share any code.

That covers pretty much all the files in here.

## Init Scripts

Here is a brief summary of each init script we provide.
More details on each can be found in the sections below.

* [anomaly-detector.conf]: Background daemon that monitors logs for anomalies.
* [crash-boot-collect.conf]: One-off collection at boot time.
* [crash-reporter.conf]: One-off boot initialization (after stateful is
    mounted).
* [crash-reporter-early-init.conf]: One-off early boot initialization
  (before stateful is mounted).
* [crash-sender.conf]: Background daemon for uploading reports.
* [crash-sender-login.conf]: One-off instance of crash-sender to run on login.

## Initialization

This section is triggered via the [crash-reporter.conf] init script.

We want to initialize boot collection as early as possible so as to minimize
the time frame for crashes that we'd miss otherwise.
Currently we initialize during `boot-services` and after `syslog`.
This is because the [crash_reporter] code will use syslog for output/errors of
its own, even during early init.

For any userland crashes that occur before this point, the
[crash-reporter-early-init.conf] script helps us collect these. It runs
after pre-startup, and saves crashes into temporary directories. We then collect
these with [crash-boot-collect.conf] after the stateful partition is available.

The init step itself should be fairly quick as it only initializes internal
state paths (e.g. under `/run` and `/var`), and it configures the various
`/proc` and `/sys` paths that the kernel has setup.
Most notably, this is responsible for writing `/proc/sys/kernel/core_pattern`
which tells the kernel to execute us whenever a crash is detected.

For more details, see the [core(5)] man page.

## Crash Report Storage

We store reports in a couple of different places.

*   `/var/spool/crash/`: Non-user (i.e. system) queued reports, when not logged
    in or half of the time when logged in.
    *** promo
    When on a test build, all system crashes are written to `/var/spool/crash`
    instead of `/run/daemon-store/crash/<user_hash>`. This avoids having crashes
    become inaccessible if a test logs the user out.
    ***
*   `/home/chronos/<user_hash>/crash/`: User-specific queued reports.
    Used when invoked as the user (e.g. by Chrome as `chronos` while logged in).
    Only used half of the time -- otherwise we use daemon-store (see below).
*   `/home/chronos/crash`: Crashes from the `chronos` user when not logged in,
    for instance, if Chrome crashes while not logged in.
    *** promo
    When on a test build, all user crashes are written to `/home/chronos/crash`
    instead of `/home/chronos/<user_hash>/crash/` or
    `/run/daemon-store/crash/<user_hash>`. This avoids having crashes
    become inaccessible if a test logs the user out.
    ***
*   `/run/daemon-store/crash/<user_hash>`: Some crashes from the `chronos` user
    are sent here.  In addition, **half** of all crashes that occur when a user
    is logged in are sent here. In the long term, all crashes should go here
    when the user is logged in. (We send half of crashes now as part of an
    experiment to validate usage of daemon-store.)
*   `/mnt/stateful_partition/unencrypted/preserve/crash`: Crashes found early in
    the boot process (before `/var/spool/crash` is available) are stored here if
    we wish to preserve them across clobbers.
*   `/run/crash_reporter/crash`: Crashes found early in the boot process (before
    `/var/spool/crash` is available) are stored here.

These directories are only written to by the crash-reporter at collection time.
The [crash_sender] program will also delete reports after it uploads them.

These directories are only read by the [crash_sender] program for uploading,
and by feedback reports.
Test frameworks (e.g. autotest, tast) also offload crash reports, and the
[crash_serializer] binary helps them do so.

We enforce a limit of about 32 crashes per spool directory.
This is to avoid filling up the underlying storage, especially if a daemon
goes into a crash loop and generates a lot of crashes quickly.

## Collectors

[crash_reporter] is composed of a number of *collectors*.
Each of these are responsible for actual crash collection and processing.
Since these are a large topic by themselves, we have a [Collectors] doc.

### Supplementary Data Collection

Every collector produces a unique name of sorts which is then looked up in the
[crash_reporter_logs.conf] file.
For example, [user_collector] uses the program's base file name, while
[udev_collector] constructs a more complicated format to make it easier to
match unique events.

The value of that setting is an arbitrary shell script which is then executed.
The output is captured and automatically attached to the corresponding report.

This is most useful to collect data from device or program specific paths that
otherwise would not be collected.
For example, for kernel wifi driver warnings, we'll dump some of the low level
PCI register state for those specific pieces of hardware.

The output of this snippet should be kept small as there are size limits to
report uploads, and to minimize PII data leaking in.

*** aside
This file should be moved to `/etc/crash-reporter/logs.conf`.
***

## Metrics

*** promo
Metric collection is currently being evaluated for their usefulness.
As it stands currently, metrics are still in the codebase, but ultimately
disabled just before being collected.

See https://crbug.com/754850 for more details.

If we re-enable the metrics, then we'll fill out this section of the doc.
If we delete the code entirely, then we'll delete this section too.
***

## Uploading Crashes

The [crash_sender] program is responsible for uploading reports to the server.
It tries to be unobtrusive in a number of ways:
*   Runs at most once an hour.
*   Limits the crashes uploaded in any 24 hour window to no more than 24 MB
    (compressed) or 32 reports, whichever comes *last*.
*   Adds a random delay between [0..600] seconds before each report upload.

While there are multiple local crash queues, these are global limits.

Before we upload any report, we check to see if consent is still granted.
This way we stop uploading reports right away if things change.

We also check if the network is online before uploading a crash report and stop
uploading reports until the next run of [crash_sender] if we are offline.

If an upload fails for any reason (flaky network, system going to sleep,
etc...), then the report is left in the local queue and retried later.

We attempt to upload the oldest reports first to minimize them going stale.

Network proxies are respected; see the [Proxies] section for more details.

After a report has been successfully uploaded, we add details to the
`/var/log/chrome/Crash Reports/uploads.log` file.
This is used by Chrome itself in its internal `chrome://crashes` page to provide
crash information to the user.
The exact format of this file is controlled by Chrome.
Here are just some of the files involved:
* [chrome/browser/ui/webui/crashes_ui.cc](https://chromium.googlesource.com/chromium/src/+/HEAD/chrome/browser/ui/webui/crashes_ui.cc)
* [components/crash/core/browser/crashes_ui_util.cc](https://chromium.googlesource.com/chromium/src/+/HEAD/components/crash/core/browser/crashes_ui_util.cc)
* [chrome/browser/crash_upload_list/](https://chromium.googlesource.com/chromium/src/+/HEAD/chrome/browser/crash_upload_list/)
* [components/upload_list/](https://chromium.googlesource.com/chromium/src/+/HEAD/components/upload_list/)

*** aside
Our management of `uploads.log` lags behind other platforms.
See https://crbug.com/275910 for more details.
***

### Manually Uploading

At runtime, there are a few different ways one can trigger uploading.
Since [crash_sender] has internal locking, you don't have to worry about any of
these methods clobbering or racing with any other crash component.
* People can run [crash_sender] directly as root (when in developer mode). You
  may need to pass `--dev`. (This will upload crashes to crash-staging, rather
  than crash.)
* [crosh] has a `upload_crashes` command to trigger immediately.
* The `chrome://crashes` page has a "Start Uploading" link.

*** aside
Currently we disable crash uploading while in guest mode, but this is only to
avoid uploading any browser or user crashes saved in the guest's profile.
We should be able to improve this by still uploading system crashes.
***

### Viewing

Once these crashes are uploaded, where do they go you might wonder?
By default, they're sent to the [Google Crash Server].
For obvious privacy reasons, this server is only accessible to Google employees,
and even then not all employees have access, only ones that need it to debug.

### Proxies

Network information is managed by Chrome because they are often distributed
via [PAC] files which are written in JavaScript and executed on the device.
We'd rather not have to spin up our own JS VM to execute these snippets.

This is where the [list_proxies] tool comes in.
It's a simple front end to sending queries to Chrome via D-Bus and then printing
the results to stdout.
This info can then be exported or passed to tools like `curl`.

For Chromeless devices, this presents a bit of a challenge.

### Throttling

The crash report server has quotas on the number of crash reports it will accept
for a particular product/version combination. When this quota is exceeded, it
will return good status to the device (HTTP 200) along with a special crash
report receipt ID of "0000000000000001". This prevents the device from
re-attempting the crash report upload due to bad status (i.e., HTTP 429:
"Too Many Requests").

## Filesystem Paths

We won't cover (in depth) files covered by these topics:
* Files read/processed via [crash_reporter_logs.conf].
* Files read/processed by specific [Collectors].

Otherwise, this should be an exhaustive list of paths on the filesystem that
this project uses in any fashion.

### Persistent Paths (/var)

These paths are guaranteed to persist across boots.

*   `/var/lib/crash_reporter/`: Non-volatile state we need across reboots.
    Currently we use to cache previous OS details so we can correctly attribute
    previous kernel crashes to the previous OS version that was running.
*   `/var/lib/crash_reporter/pending_clean_shutdown`: Used by the
    [unclean_shutdown_collector].
*   `/var/lib/crash_sender/`: Non-volatile state that [crash_sender] maintains.
    Used to keep track of how many reports have been uploaded (and when) so we
    can regulate our limits. Do not add any additional files to this directory
    or it will break timestamp calculations. Add additional state information
    to the 'state' subdirectory instead. Currently we store a 'client_id' in
    the 'state' subdirectory for maintaining a persistent device identifier for
    coalescing crash reports by device. This ID should never be used for any
    other purpose.

*   `/var/log/messages`: [anomaly_detector] monitors this (read-only).
*   `/var/log/chrome/Crash Reports/uploads.log`: [crash_sender] updates this
    after every crash it uploads.  See [Uploading Crashes] for more details.

These spool dirs are covered in detail in [Crash Report Storage].

*   `/var/spool/crash/`: System crash reports.
*   `/home/chronos/<user_hash>/crash/`: User-specific queued reports.
*   `/home/root/<user_hash>/crash-reporter/`: User-specific queued reports.

### Boot Clean Paths (/run)

These paths are guaranteed to be reset at every boot, so we only store active
runtime details here.

*   `/run/crash_reporter/`: Used by all crash-reporter tools (i.e. both
    [crash_reporter] and [crash_sender]) for runtime state.
    *This should be moved to `/run/crash-reporter/` as the project name.*
*   `/run/lock/crash_sender`: Used by [crash_sender] to guarantee only one
    upload instance is active at a time.

These are used to communicate with [metrics_daemon].

*   `/run/metrics/external/crash-reporter/kernel-crash-detected`: Used by
    [crash_reporter] to signal the [metrics_daemon] that a kernel
    crash occurred.
    Also used by integration tests to verify this functionality.
*   `/run/metrics/external/crash-reporter/unclean-shutdown-detected`: Used by
    [crash_reporter] to signal the [metrics_daemon] that an unclean
    shutdown occurred.
    Also used by integration tests to verify this functionality.

This is used to communicate with [powerd].

*   `/run/crash_reporter/boot-collector-done`: Used by [crash_reporter] to
    signal the [powerd] that boot collector has successfully completed per-boot
    crash collection.
    Also used by integration tests that rely on the boot collector.

*** aside
This poor man's IPC with `/run` files was done historically because the
[crash-reporter.conf] init and [crash-boot-collect.conf] were one script that
always executed early and before [metrics_daemon] started.
However, now we can make [crash-boot-collect.conf] wait for [metrics_daemon],
we should be able to switch to its more standard existing IPC methods.
***

### VM-specific configuration

VMs may ship `/etc/vm_crash_filter.textproto` within the VM filesystem. If
present, it contains a protobuf message of type
[VmCrashFilters](./proto/crash_reporter.proto). It's used by UserCollector's
VmSupport to control which processes may have crash reports generated.

### Test-related paths
*   `/var/lib/crash_sender_paused`: Used by integration tests to pause
    [crash_sender].
    *This should be moved to `/run/crash_reporter/crash_sender_paused`.*
*   `/var/spool/crash/mock-consent`: Used by integration tests to persist mock
    consent across reboots. This file should be created with a small number
    greater than 0 (like 2). It will be deleted after that number of reboots.
*   `/var/spool/crash/crash-test-in-progress`: Used by integration tests to
    persist crash test in progress state across reboots. This file should be
    created with a small number greater than 0 (like 2). It will be deleted
    after that number of reboots.
*   `/run/crash_reporter/crash-test-in-progress`: Used by integration tests to
    tell tools they are being exercised by an integration test that tests the
    crash system itself and to adjust their behavior accordingly.
*   `/run/crash_reporter/mock-crash-sending`: Used by integration tests to tell
    [crash_sender] to mock out the actual upload for testing purposes.
*   `/run/crash_reporter/mock-consent`: Used by integration tests to tell
    the crash system to act as if the user had given consent for crashes to be
    collected and uploaded.
*   `/run/crash_reporter/filter-in`: Used by integration tests to tell the
    crash_reporter to ignore invocations unless the command line contains
    the contents of this file as a substring.
*   `/run/crash_reporter/filter-out`: Used by integration tests to tell the
    crash_reporter to ignore invocations *if* the command line contains
    the contents of this file as a substring.
*   `/mnt/stateful_partition/etc/collect_chrome_crashes`: Used by tast tests
    to let [crash_reporter] collect browser crashes directly (normally it
    ignores them and lets Chrome handle things).
    *This should be moved to `/run/crash-reporter/collect_chrome_crashes`.*

### Temporary Paths (/tmp)

The `/tmp/` usage by tools would normally be quite concerning due to the ease of
predictable file names, but [crash_reporter] and [crash_sender] both execute in
a minijail with a unique empty `/tmp/` mount (and automatically freed on exit).
That mount is visible only to the active process (and its children), so other
processes in the system won't be able to inject content.
This doesn't mean the `/tmp/` usage shouldn't be improved, but it at least
mitigates collisions (accidental or otherwise).

*   `/tmp/crash_reporter/<pid>/`: [crash_reporter] writes intermediate data
    here for the `<pid>` that just crashed.
*   `/tmp/crash_sender.XXXXXX/`: [crash_sender] holds intermediate upload report
    status here and is cleared after every run.
*   `/tmp/`: [core_collector] writes intermediate `/proc` files directly here.

### Other Paths

Here's any other random paths we handle.

*   `/root/.leave_core`: Normally [crash_reporter] will delete the large
    coredumps after converting them to minidumps.
    When this file exists, coredumps are saved in the spool dir too.
    Created on dev images automatically.
    *This should be moved to `/etc/crash-reporter/leave-core`, and duplicated
    in `/run/crash-reporter/` so people don't have to modify the rootfs.*

## Crash Report Format

Each crash report has a `.meta` file with a unique basename.
The `.meta` file is a simple key-value store read by [crash_sender].
Each collector will generate this, and any supplemental files will use that same
basename with other extensions.
e.g. The main crash image will be a minidump but with a `.dmp` extension.
Supplemental log files will have a `.log` extension.

However, [crash_sender] doesn't care about that.
The `.meta` file will have keys that point to those files directly.

## Symbol Handling

The uploaded crashes are only minidumps (and related metadata).
Actual stack walking and symbolification happens on the server.
The symbols themselves are generated by CrOS builders.

For more details, see the [Symbols] document.

## Security

Since these tools often run as root and work with untrusted data, security is
a big concern.
Check out [security.md](./docs/security.md) for more details.

## Developing & Testing

For tips for hacking on this project, check out [hacking.md](./docs/hacking.md).

## Breakpad Tools

We use a bunch of tools from [Google Breakpad].
Check out the their [docs][1] for more details (especially on minidumps).

[1]: https://chromium.googlesource.com/breakpad/breakpad/+/HEAD/docs/

[core(5)]: http://man7.org/linux/man-pages/man5/core.5.html
[crosh]: ../crosh/
[EC]: https://chromium.googlesource.com/chromiumos/platform/ec
[Google Breakpad]: https://chromium.googlesource.com/breakpad/breakpad
[Google Crash Server]: https://crash.corp.google.com/
[inotify]: https://en.wikipedia.org/wiki/Inotify
[metrics]: ../metrics/
[metrics_client]: ../metrics/
[metrics_daemon]: ../metrics/
[PAC]: https://en.wikipedia.org/wiki/Proxy_auto-config
[powerd]: ../power_manager/
[SELinux]: https://en.wikipedia.org/wiki/Security-Enhanced_Linux

[Collectors]: ./docs/collectors.md
[Crash Report Storage]: #Crash-Report-Storage
[Proxies]: #Proxies
[Symbols]: ./docs/symbols.md
[Uploading Crashes]: #Uploading-Crashes

[anomaly_detector]: ./anomaly_detector.cc
[anomaly-detector.conf]: ./init/anomaly-detector.conf
[core_collector]: ./core-collector/
[crash-boot-collect.conf]: ./init/crash-boot-collect.conf
[crash_reporter]: ./crash_reporter.cc
[crash-reporter-early-init.conf]: ./init/crash-reporter-early-init.conf
[crash_reporter_logs.conf]: ./crash_reporter_logs.conf
[crash-reporter.conf]: ./init/crash-reporter.conf
[crash_sender]: ./crash_sender.cc
[crash-sender.conf]: ./init/crash-sender.conf
[crash_serializer]: ./crash_serializer.cc
[init/]: ./init/
[kernel_warning_collector]: ../kernel_warning_collector.cc
[udev rules]: ./99-crash-reporter.rules
[udev_collector]: ./udev_collector.cc
[unclean_shutdown_collector]: ../unclean_shutdown_collector.cc
[user_collector]: ./user_collector.cc
