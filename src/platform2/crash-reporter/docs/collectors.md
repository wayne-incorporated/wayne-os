# Crash Collectors

For each major class of crash reports, we define a dedicated *collector*.
This is a simple way to encapsulate all related logic in a single module.

When we run [crash_reporter], depending on its mode, it simply iterates through
all registered collectors.

The [crash_collector.cc] code isn't a real collector, it's the base class to
hold common logic for all collectors.
Similarly, [user_collector_base.cc] isn't a real collector, it's the base class
to hold common logic for all user related collectors.

The [core_collector] program is just a utility tool and not a collector in the
sense of all these.
It probably should have used a different naming convention.

[TOC]

# Basic Operations

Each collector is designed to generate and queue crash reports.
They get uploaded periodically by [crash_sender].

# Boot Collectors

These are the collectors that run once at boot.
They are triggered via the [crash-boot-collect.conf] init service.
They do not, by design, block the boot of the system.
They are run in the background as a non-critical service.

## bert_collector

This collects Boot Error Record Table ([BERT]) failures.

The dump collected might be referred to as `bertdump`.

*   Unhandled firmware errors that occurred in the previous boot are stored in
    the boot error region.
*   The Kernel ACPI sysfs interface generates the BERT table at
    `/sys/firmware/acpi/tables/BERT` and BERT data at
    `/sys/firmware/acpi/tables/data/BERT`.
*   During boot, if a BERT report exists, read them and create a report.

## ec_collector

This collects [EC] (ChromeOS Embedded Controller) failures.

The program name is `embedded-controller` and might be referred to as `eccrash`.

*   The kernel driver [cros_ec_debugfs.c] sets up a debugfs path at
    `/sys/kernel/debug/cros_ec/`.
*   The driver probes the [EC] to see if it has any panic logs.
*   If the logs exist, the `/sys/kernel/debug/cros_ec/panicinfo` is created.
*   During boot, if that file exists, we read it and create a report.

[cros_ec_debugfs.c]: https://chromium.googlesource.com/chromiumos/third_party/kernel/+/chromeos-4.14/drivers/platform/chrome/cros_ec_debugfs.c

## ephemeral_crash_collector

This is a meta crash collector: it collects already collected ephemeral crashes
into persistent storage. This is useful for handling crash reports in
situations where we may not have access to persistent storage (eg. early boot).

## gsc_collector

This collects Google Security Chip (GSC) failures.

* Uses `gsctool` to query the GSC Flash Logs for any crashes.
* During boot, if `gsctool` Flash Log output contains a crash signature, we
create a report.

## kernel_collector

This collects kernel (and BIOS) crashes that caused the system to reboot.

It is built on top of [pstore] and doesn't support any other data source.
We currently support the `ramoops` and `efi` backend drivers.

The program name is `kernel` and might be referred to as `kcrash`.

*   The BIOS/AP firmware maintain some dedicated space to hold a snippet of the
    kernel log.
    They make sure to not clear it during reboot in case there's valid data.
    *   For `ramoops`, CrOS firmware (e.g. coreboot) dedicate a chunk of RAM.
    *   For `efi`, the EFI firmware provides data in its own NVRAM space.
*   While the kernel is running normally, a circular buffer is used to hold the
    most recent portion of the kernel log buffer (i.e. what `printk` writes to
    and what `dmesg` reads from).
*   When the kernel reboots unexpectedly (e.g. due to a panic, oops, or BUG()),
    that error message is saved by [pstore] to the persistent location.
*   If the watchdog reset the system, we won't have an explicit panic message,
    but we will have the last snippet of the kernel log buffer.
*   During the next boot, the firmware makes sure that space is not reset.
*   While the kernel boots, the [pstore] driver will check that common space to
    see if there are any valid records.
    All valid records are made available via files in `/sys/fs/pstore/`.
*   During userspace boot, those paths are checked and reports are created.
*   For panics the kernel handled, we'll read the logs from `dmesg-ramoops-*`
    & `dmesg-efi-*`, and generate a report for each one.
*   Stack traces created by the kernel are analyzed to create a stack for the
    server, as well as generate a hash/fingerprint to correlate other reports.
*   For watchdog resets, we'll first query the eventlog (from [elogtool]) to see
    if the reset was actually due to that.
    Normally we'd query the watchdog driver directly, but not all platforms are
    able to support that properly via the kernel driver.
    We'll create a simpler report using the last snippet of the kernel log from
    `console-ramoops-*` and hope the events just before the reset are enough to
    triage the problem.
*   As records are processed, they get removed from the pstore area.
*   On systems with coreboot BIOS, we also collect the BIOS log. This may be
    helpful to debug crashes when the kernel interacted with runtime firmware.
*   coreboot maintains a ring buffer (the "CBMEM console") of log messages in a
    memory area that is considered reserved by the kernel. The buffer is never
    erased unless the memory loses power (i.e. if the system fully shuts down),
    and is usually large enough to hold messages from several prior boots.
*   The collector will search the BIOS log for "banner" strings printed by
    coreboot on boot to determine where a reboot occured. It will only collect
    log lines from the boot prior to the current one (i.e. the one that the
    crash occured it).
*   On arm64 systems, we also attempt to collect runtime firmware (BIOS)
    crashes. This is done by the kernel collector since runtime firmware mostly
    does things when requested by the kernel, and errors in runtime firmware are
    usually triggered by how the kernel calls it. The BIOS generally doesn't log
    very much after boot, we need both the kernel and BIOS logs to understand
    the situation of a runtime firmware crash. Since the kernel collector
    already has the logic to collect both of these, it makes sense for it to
    handle BIOS crash collection as well.
*   On arm64, the runtime firmware is a piece of code called BL31 from the Arm
    Trusted Firmware project. BL31 logs crashes by dumping all CPU registers and
    knows how to append to the coreboot CBMEM console. Since we do not have the
    infrastructure to generate a full stack trace in firmware, we file these
    crash reports with a poor man's crash signature that just encodes the
    address of the program counter where the crash occured.

## unclean_shutdown_collector

Collects unclean shutdown events.

*   On every boot, crash_reporter is run.
    It creates a file (`/var/lib/crash_reporter/pending_clean_shutdown`) to
    indicate that the system hasn't gone through a clean shutdown.
*   Upon clean shutdown ([chromeos_shutdown]), crash_reporter is run with the
    `--clean_shutdown` flag.
    The stateful partition file is removed to indicate the system has gone
    through a clean shutdown.
*   If during boot, the file already exists before crash_reporter attempts to
    create it, this signifies that the system hadn't shut down cleanly.
    A signal is enqueued for metrics_daemon to emit user metrics about this
    unclean shutdown.
*   No crash reports are otherwise generated for unclean shutdowns since it's
    not clear how we'd triage this in the first place (i.e. what to report).

# Runtime Collectors

Here are the collectors that are triggered on demand while the OS is running.
They are invoked either by the kernel or by other program.

## arc_java_collector

Collects Java crashes from programs inside the [ARC++] container or [ARCVM].

## arcpp_cxx_collector

Collects crashes from Android NDK programs inside the [ARC++] container.
It does not handle crashes from [ARC++] support daemons that run outside of the
container as those are collected like any other userland crash via the main
[user_collector].

[arcpp_cxx_collector] shares a lot of code with [user_collector] so it can overlay
[ARC++]-specific processing details.

## arcvm_kernel_collector

Collects crashes of Linux kernel of Android in [ARCVM].

When the ARCVM Linux kernel crashes, it dumps logs to
`/sys/fs/pstore/dmesg-ramoops-0` in ARCVM.  It's a [pstore] file, so the
backend exists on ChromeOS as `/home/root/<hash>/crosvm/*.pstore`.
[arcvm_kernel_collector] receives the content of this file from
ArcCrashCollector and ARC bridge via Mojo (or possibly, directly reads the
ring buffer in pstore file) and processes it.

## arcvm_cxx_collector

Collects crashes of machine-code binaries (i.e. non-Java crashes, it's mainly
crashes of C++ programs) in [ARCVM].

When a machine-code binary crashes, Linux kernel detects the crash and invokes
`arc-native-crash-dispatcher` via `/proc/sys/kernel/core_pattern`.
`arc-native-crash-dispatcher` calls `arc-native-crash-collector32` or
`arc-native-crash-collector64`, and they dump crash file in
`/data/vendor/arc_native_crash_reports` in ARCVM. A Java daemon
`ArcCrashCollector` in ARCVM monitors this directory, and if new files
appeared, then sends them to ARC bridge of Chrome browser via Mojo. Dump files
are passed as FDs. And finally ARC bridge invokes `crash_reporter` with the FDs.

## chrome_collector

Collects Chrome browser crashes.
The browser will hand us the minidump directly, so we only attach system
metadata and queue it.

crash_reporter will be called by the kernel for Chrome crashes like any other
[user_collector] crash, but we actually ignore these invocations.
Chrome is supposed to catch the crash in its parent process and handle it
itself; it links in [Google Breakpad] or [crashpad] directly to do so.
This is because Chrome is better suited to know what memory regions to ignore
(e.g. large heaps or file memory maps or graphics buffers), as well as what
metadata to attach (e.g. the last URL visited, whether the process was a
renderer, browser, plugin, or other kind of process, `chrome://flags`, etc...).
Otherwise Chrome coredumps can easily consume 3GB+ of memory!

This does mean the system may miss crashes if Chrome's handling itself is buggy.

*** aside
In much older versions of ChromeOS (sometime before R40), Chrome would not only
handle creating its own crash reports, it would also handle uploading them.
We changed that behavior because Chrome's uploading is not as robust: it starts
uploading immediately, lacks delays/rate limiting, it tries only once, and if it
fails at all, it throws away the report entirely.
By queueing the report with crash-reporter, it avoids all those problems.
***

## mount_failure_collector

Collects information on failures to mount or unmount partitions. This is invoked
via [chromeos_startup] or [chromeos_shutdown] when the umount/mount operation
fails.

TODO(sarthakkukreti): Expand on this section

## udev_collector

This collects crash/error events triggered by [udev] events.
It is invoked via the [udev rules] and relies heavily on callbacks in the
[crash_reporter_logs.conf] file.

The program name is `udev`.

These reports are largely device specific as they try to capture whatever state
the device/firmware needs to triage.

TODO: Add devcoredump details if we ever enable them.

## user_collector

Collects all userland crashes where the kernel dumps core.
Basically any program that segfaults, aborts, violates a seccomp policy, or is
otherwise unceremoniously killed.

*   When a process crashes, the kernel invokes crash_reporter with various
    important runtime attributes (e.g. the pid, the uid, etc...).
    The kernel writes a full core dump of the process to stdin.
*   At this point, the failing process is frozen until crash_reporter exits.
    That means any parent that is monitoring the child won't be notified until
    we finish processing.
    This is often a critical path operation if a service needs to be restarted.
    *   Chrome reports are ignored normally; see the [chrome_collector] section
        for more details as to why.
*   The core2md is run to convert the full coredump to a minidump (`.dmp`).
    This process involves reading the core file contents to determine number of
    threads, register sets of all threads, and threads' stacks' contents.
    This is fundamental to our out-of-process design.
*   When a crash occurs, we consider the effective user ID of the process which
    crashed to determine where to save it.
    If the crashed process was running as `chronos`, we enqueue its crash to
    `/home/user/<user_hash>/crash/` which is on the user-specific cryptohome
    when a user is logged in since it might have user PII in it.
    If the crashed process was running as any other user, we enqueue the crash
    in `/var/spool/crash`.
*   The name of the crashing program is used to determine if we should gather
    additional diagnostic information.
    [crash_reporter_logs.conf] contains a list of executables and shell commands
    to run to gather more details.
    Any output from them will automatically be attached to the crash report as
    a `.log` file.

## vm_collector

Used to process crash reports generated inside VMs. This is mostly a wrapper
around writing the right collection of files to the right directory, as most
useful crash information has to be gathered inside the VM, but it has
responsibility for gathering any VM logs stored on the host.

This collector writes to the new `/home/root/<user_hash>/crash` spool directory,
as the daemons that interact directly with VMs to get crash information
intentionally don't have the permissions required to access either of the
existing spool directories.

# Anomaly Detectors

The [anomaly_detector] service is spawned early during boot via
[anomaly-detector.conf].  It monitors various syslog files and tries to
match a set of regexes. A match triggers a collection or a D-Bus signal,
depending on the regex.

A number of anomalies are sampled -- that is, we do not upload a report every
time the anomaly occurs, but instead only 1 in every N times, where N is a value
specific to that kind of crash. In this case, we generally also attach a
"weight" field (with value N) to the crash report to indicate to the crash
server that that report should count as N reports. This sampling is necessary in
order to minimize load on the server and keep our total daily reports under 10
million.

*   Collection:

    *   [crash_reporter] is invoked for a specific collector, and is fed
    relevant lines via stdin.

*   Signal:

    *   A D-Bus signal is emitted on a specific service.  Other processes may
        register for delivery of this signal. The service offers no
        methods.

See sections below for more details on each collector and signal.

The anomaly detector runs one collector at a time, and waits for it to
finish running fully before processing more syslog entries.

As a special case, only the first instance of each kernel warning is collected
during a session (from boot to shutdown or crash).  A count of each warning is
reported separately via a sparse UMA histogram.

## crash_reporter_failure_collector

Collects log messages indicating that crash reporter itself crashed. Anomaly
detector will invoke this collector at most once an hour, to prevent crash loops
in crash reporter from generating an infinite set of calls to crash reporter.

## generic_failure_collector

Responsible for collecting information on suspend failures and
service failures. The architecture is generic and adapatable: It allows
arbitrary weights, log names for [crash_reporter_logs.conf], etc.

You can use this with any anomaly that can be passed to crash_reporter as a
single line, optionally with additional data collected via
[crash_reporter_logs.conf].

### service failures

Collects warnings from the init (e.g. Upstart) for non-ARC services that failed
to startup or exited unexpectedly at runtime.
This catches syntax errors in the init scripts and daemons that simply exit
non-zero but didn't otherwise trigger an abort or crash.

The program name is `service-failure`.

*   Lines from `init:` are processed.
*   The standard upstart syntax is:
    `<daemon> <job phase> process (<pid>) terminated with status <status>`.
*   All non-normal exits are recorded this way.
*   The signature is constructed from the exit status and service name.

### arc service failures

Similar to the above "service failures" except that it collects ARC
services failures. ARC services are services with names started with "arc-".
Separate ARC services logic is needed because the ARC services system log
messages are kept in a separate file /var/log/arc.log.

The program name is `arc-service-failure`.

### suspend failures

When the system fails to suspend, we generate a report along with some log
information on why the suspend failure happened.

TODO(dbasehore): Expand on this section

### recovery failures

When the cryptohome recovery process fails we generate a report with
cryptohomed logs. This happens in these cases:
*   Generation of the recovery request fails.
*   Derivation of the recovery secret fails.

The program name is `cryptohome`.

### auth failures

When there are some auth failure on the previous life cycle of tcsd, we
generate a report along with failed tpm commands.

TODO(chingkang): Expand on this section

### modem failures

When the modem rejects a user request to perform an operation on the modem, we
generate a report (For e.g. Failure to connect to a network)

## kernel_warning_collector

Collects WARN() messages from anywhere in the depths of the kernel.
Could be drivers, subsystems, or core logic.

The program name is `kernel-warning` or `kernel-xxx-warning` (where `xxx` is a
common subsystem/area) and might be referred to as `kcrash`.

*   Whenever the kernel uses `WARN()` or `WARN_ON(...)` or any similar helper,
    it generates a standard log message including stack traces.
*   By default, `kernel-warning` is used everywhere, but the location of drivers
    in the backtrace are used to further refine the name.
*   The stack signature uses the same algorithm as the [kernel_collector].

## missed_crash_collector

Invoked via [crash_reporter_parser]. collects log information when the kernel
invokes [crash_reporter] for a chrome crash, but then chrome does not invoke
crash_reporter within a reasonable timeframe (currently, 60 seconds).
Includes chrome logs and syslogs.

## selinux_violation_collector

Collects [SELinux] policy violations.

The program name is `selinux-violation`.

*   Lines from the audit subsystem are processed.
*   Fields from each line are extracted (such as `name=` and `scontext=`) and
    used to create the magic signature.


## Out-Of-Memory kill signal (OOM kill)

On detection of OOM-kill attempts in the kernel, [anomaly_detector] sends a
D-Bus signal on /org/chromium/AnomalyEventService.  This is currently used by
[memd] to collect a number of memory-manager related stats and events.

[anomaly_detector] does not try to confirm that the kill is successful.

[ARC++]: ../../arc/
[ARCVM]: ../../arc/vm/
[BERT]: https://www.uefi.org/sites/default/files/resources/ACPI%206_2_A_Sept29.pdf
[EC]: https://chromium.googlesource.com/chromiumos/platform/ec
[elogtool]: https://review.coreboot.org/plugins/gitiles/coreboot/+/HEAD/util/cbfstool/
[Google Breakpad]: https://chromium.googlesource.com/breakpad/breakpad
[crashpad]: https://chromium.googlesource.com/crashpad/crashpad
[memd]: ../../metrics/memd/
[pstore]: https://chromium.googlesource.com/chromiumos/third_party/kernel/+/v4.17/Documentation/admin-guide/ramoops.rst
[SELinux]: https://en.wikipedia.org/wiki/Security-Enhanced_Linux
[udev]: https://en.wikipedia.org/wiki/Udev

[anomaly_detector]: ../anomaly_detector.cc
[anomaly-detector.conf]: ../init/anomaly-detector.conf
[arc_java_collector]: ../arc_java_collector.cc
[arcpp_cxx_collector]: ../arcpp_cxx_collector.cc
[arcvm_kernel_collector]: ../arcvm_kernel_collector.cc
[arcvm_cxx_collector]: ../arcvm_cxx_collector.cc
[bert_collector]: ../bert_collector.cc
[chrome_collector]: ../chrome_collector.cc
[chromeos_startup]: ../../init/chromeos_startup
[chromeos_shutdown]: ../../init/chromeos_shutdown
[core_collector]: ../core-collector/
[crash-boot-collect.conf]: ../init/crash-boot-collect.conf
[crash_collector.cc]: ../crash_collector.cc
[crash_reporter]: ../crash_reporter.cc
[crash_reporter_logs.conf]: ../crash_reporter_logs.conf
[crash_reporter-parser]: ../crash_reporter_parser.cc
[crash_sender]: ../crash_sender.cc
[ec_collector]: ../ec_collector.cc
[kernel_collector]: ../kernel_collector.cc
[kernel_warning_collector]: ../kernel_warning_collector.cc
[selinux_violation_collector]: ../selinux_violation_collector.cc
[service_failure_collector]: ../service_failure_collector.cc
[udev rules]: ../99-crash-reporter.rules
[udev_collector]: ../udev_collector.cc
[unclean_shutdown_collector]: ../unclean_shutdown_collector.cc
[user_collector]: ../user_collector.cc
[user_collector_base.cc]: ../user_collector_base.cc
