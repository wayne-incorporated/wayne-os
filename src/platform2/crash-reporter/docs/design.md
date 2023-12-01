# ChromiumOS Crash Reporting (original design doc)

*2011-05-15*

*** note
This is the original design doc for this project.
Some aspects are out of date or no longer accurate, but is still useful for
historical reference purposes.
We don't plan on updating or "fixing" content here as the current state of the
project is better reflected in other files.
Start with the [README](../README.md).
***

[TOC]

# Objective

We intend to design a system for generating statistics and diagnostic
information on a variety of crashes.

Our goals for devices that are opted into automatically submitting usage
feedback and crash reports to Google:

*   Detect crashes in any system process and accumulate a User Metrics counter
    of number of user space crashes, usage time between crashes, and crashes per
    day/week.
*   Detect unclean shutdowns on the system and accumulate a User Metrics counter
    of number of unclean shutdowns, usage time between unclean shutdowns, and
    unclean shutdowns per day/week.
*   Detect kernel crashes (Linux kernel panics) on the system and accumulate a
    User Metrics counter of number of kernel crashes, usage time between
    crashes, and crashes per day/week.
*   Generate diagnostic information for any user space process that crashes with
    enough information to generate stack traces server-side.
*   Generate other diagnostic information that is application specific for
    specific user space process crashes.
*   Generate diagnostic information for any kernel crash (panic) with kernel
    debug messages including the kernel-generated stack trace at the point of
    crash.
*   Upload diagnostics in spite of system failures (unusable components like
    Chrome or X), temporary network failures, and use a system-wide upload rate
    throttle.
*   Store crash diagnostics for user-specific crashes in the cryptohome which is
    encrypted so that any diagnostics with sensitive information that needs to
    be stored after the user logs out because of a failure described above
    cannot be viewed by any other user.
    This means we will need to upload the crash report once the user has
    provided their credentials later and is logged in.

Our non-goals:

*   Recognizing a wide variety of very bad user space problems such as a Chrome,
    X, or Window Manager that immediate exits and causes the machine to not be
    usable.

    *> Are you talking about processes that exit with a failed assert, or
    something else?
    If the former, it seems like we'd be able to report that.*

    *> I'm not opposed to adding this to the longer-term goals, but I'm not sure
    what interface would be appropriate here - looking through syslogs for
    errors, looking through application specific logs?*

# Background

Our goal is to provide a stable platform.
We need to be able to diagnose failures that do not occur in our labs or that
are otherwise hard to reproduce automatically.

## Existing User Space Crash Reporting

[Google Breakpad] is used by most Google applications on Mac, Windows, and Linux
for x86 and ARM architectures to send "minidump" crash reports, very small crash
reports that contain enough information to provide a stack trace of all threads
running at the time of the crash.
[Google Breakpad] does (as of Q1 2010) support ARM but is not yet used in
production.
Chrome in ChromeOS currently uses [Google Breakpad] and sends crash reports
with product ID "Chrome_ChromeOS".

The Canonical Ubuntu Linux project uses [Apport] to handle user space crashes.
This is a Python package that intercepts all core file writes, invokes gdb, and
collects stack dumps into a directory which it then sends out using an Anacron
job.
It relies on Python and debug information being present on the target.

The Linux kernel creates core files for processes that encounter unhandled
signals.
As of 2.6 kernels, the file location and naming can be customized by changing
[/proc/sys/kernel/core_pattern].
Once core files are written they can be manually inspected by a developer or
advanced user.
Additionally, this kernel parameter can be set to cause a pipe to be opened to
a user space process which then can receive the core file that would have been
written to its stdin.
We will rely on this mechanism to get diagnostic information and signaling for
all user space processes.

On Windows, Microsoft has created the [WINQUAL] service which allows developers
to retrieve crash diagnostics for their applications.
When a Windows application crashes and does not handle the crash itself, the
operating system prompts the user if they would like to send this particular
crash report, and uploads it upon receiving consent.
The [WINQUAL] service then aggregates and shows the reports.
Crash reports can be sent as full dumps or as minidumps using the same format
that [Google Breakpad] uses.

## Existing Kernel Space Crash Reporting

[Linux Kernel Crash Dump] ([LKCD]) is a set of kernel patches and a user-space
application that enables a panicked Linux kernel to write crash diagnostics to
its swap partition and then diagnose the crash and store it in a simplified
form.
It provides a command-line utility for diagnosing kernel state, but requires a
fairly large file to be uploaded to diagnose the running kernel state remotely.
This patch was last updated in 2005 and is an invasive kernel patch that's
difficult to maintain and will never go upstream.

[kexec] based dump - is a method where the kernel "exec"s a new kernel that is
stable into a reserved area of memory without performing a system reset first.
The new stable kernel writes out the state and data of the old kernel to disk,
whilst only operating from the reserved memory area.
When any relevant state is written, the rest of memory is reclaimed and
initialized and full system boot is completed.
The patches for kexec are already upstream.

http://www.kerneloops.org/ - Collects crash dumps and provides a dashboard for
all kernel developers to find crashes common across all versions, as well as
specific to vendors/distributors.
Provided they have enough server-side capacity to handle crash dumps from
ChromeOS scale numbers of machines this is an option.
kerneloops provides a user space process that runs at startup, prompts the user
if they want to upload the kernel crash, and uploads an analyzed result.

Ubuntu uses [Apport] and [LKCD] to handle kernel crashes.
It invokes lcrash to perform crash analysis on the vmcore image.

## Existing Firmware Space Crash Reporting

[Firmware event logs] can be stored in non-volatile storage.
Traditionally problems during firmware initialization as well as kernel
panic/problems can be placed here.

# Requirements and Scale

## Crash Diagnostic Information Collection

There can be different systems for recording kernel and user space crash
diagnostic information.
We ideally want stack traces at time of crash for either kind of crash.
Some kinds of kernel crashes (i.e. crashes in interrupt handlers) by their
nature will not be able to generate/persist any diagnostic information.

For user space crashes, we would need:
* Identification of executable
* The context (parameters, environment, cwd)
* Stack trace (this is nice to have but also difficult in general)

We will use rate limiting to avoid flooding our servers with crash diagnostics.
We will limit to 8 crash reports per machine per day.

We need to build executables and libraries with debug information and upload
these to crash server for those for which we would like stack traces with proper
symbolic information.

## Crash Statistics Collection

We would like to have statistics on how often crashes are occurring in the
field.
For every release of ChromeOS on every device we would like to know how
frequent unclean shutdowns, user space process, and kernel crashes are.
Ideally we can know information on occurrences per individual user, for
instance, knowing that 1% of users experience over 5 kernel panics per week.
We will generate frequency data for these kinds of events in the course of a
day and per week.

## Protecting User Privacy

We must err on the side of getting too little information if the alternative is
to potentially send sensitive information of a user who has not enabled this.
As such, we should be careful, for instance, to not send kernel core files as
the kernel core may have information for a variety of users.
We also must avoid sending log files that may capture the accumulated activities
of multiple users.
We will send a unique but anonymous identifier per device to find potentially
related crashes by those which happen on the same device and to help eliminate
crashes from buggy/broken devices.
User space processes which crash and which interact closely with the user, such
as Chrome, the window manager, entd, and others are more likely to have
sensitive data in memory at the time of crash.
For this reason we encrypt the diagnostics generated from all executables which
run as Linux user 'chronos' (which means they are started when the user logs in
and terminated upon log out) when stored to disk.
Since the encryption is based on the user's password, the only way a user's
crash diagnostics can be sent is when they are currently logged in to the
device.

# Design Ideas

We will separate kernel and user space diagnostic gathering in implementation.
Both however, need to adhere to our EULA with the user.
During the out of box experience the owner chooses if he/she would like crashes
on this device to be uploaded to Google servers.
We must never send a crash report if they do not give consent.
They may rescind their consent at any time which means that if we have enqueued
a crash report to be sent which was created at a time when the user consented,
and they rescind their consent before the crash is sent, the crash report must
be discarded.

## User space crash handling

*   Upon a crash occurring, the kernel invokes crash_reporter indicating the
    name and process ID of the crashing process and pipes in to it a full core
    dump of the process.
*   Chrome links in [Google Breakpad] directly and handles its own crashes and
    uploads them.
    It generates its own statistics for various kinds of crashes and sends
    application specific information (last URL visited, whether the process was
    a renderer, browser, plugin, or other kind of process).
    The system crash handling mechanism will ignore Chrome crashes since they
    are already handled internally.
*   crash_reporter will invoke core2md to convert the full core dump to the
    minidump format.
    This process involves reading the core file contents to determine number of
    threads, register sets of all threads, and threads' stacks' contents.
    We created core2md by modifying [Google Breakpad] specifically for Chrome
    OS's uses.
    [Google Breakpad] is normally linked directly into individual executables
    whose crashes we want to generate diagnostics for.
    Since ChromeOS has hundreds of these executables, catching signals can
    interfere with executables' own code, and some executables are only
    delivered to Google in binary form, we found the conversion of full core
    files from the kernel to minidump files to be a superior way to generate
    crash diagnostics for the entire system.
*   When a crash occurs, we consider the effective user ID of the process which
    crashed to indicate if the crash report should be encrypted due to having
    higher risk of containing sensitive information.
    If the crashed process was running as `chronos` we enqueue its crash to
    `/home/chronos/user/crash` which is on the cryptohome when a user is logged
    in and so it will be encrypted.
    If the crashed process was running as any other user, we enqueue the crash
    in `/var/spool/crash`.
*   In the future, encrypted crash reports will go to
    `/home/root/<user_hash>/crash/`. This directory is still part of the
    cryptohome, but can be accessed without running as chronos. This will allow
    both creating and uploading crash reports with lower privileges.
*   The name of the crash is used to determine if we should gather additional
    diagnostic information.
    The file `/etc/crash_reporter.conf` contains a list of executables and shell
    commands for them.
    If an executable crashes which is listed in this file, the shell commands
    listed will be executed as root and their output will be sent in the crash
    report.
    For instance when the update_engine (auto updater) daemon crashes, this
    allows us to send the daemon's logs (listing attempts and application-level
    logs) in the crash report.
*   To enqueue a crash, we generate a .dmp file which is the minidump of the
    crash.
    We store the logs above in a .log file.
    We store other information in a .meta file such as the name of the
    executable that crashed and its crash timestamp.
    These three files have the same basename to form one report.
    The basename includes the crashing executable's name and time of the crash
    to help developers diagnose crashes on non-production devices.
*   Crash statistics are generated by `crash_reporter` emitting a dbus signal
    that `metrics_daemon` receives.
    That daemon generates and emits user metrics to Chrome.
*   These crash reports are sent by a crash sending agent also used by kernel
    crash collector.

## Termina virtual machine crashes

*   ChromeOS has over time grown a number of virtual machines, including
    Termina, a VM for running Linux applications the ChromeOS won't support
    natively. The user space crash handling described above won't catch any
    crashes here.
*   Inside Termina we gather information about crashes using the normal
    user space crash flow described above.
*   Once the crash information is gathered inside Termina, instead of writing it
    to a spool directory for the crash sender, it gets sent out of Termina to a
    daemon (cicerone) running on the host.
*   This daemon then invokes a VM collector on the host and passes it the
    information from Termina, which writes out the crash report.
*   Cicerone has intentionally limited privileges due to its interaction with
    untrusted VMs, which means it (and any process it invokes) can't write
    directly to the regular spool directories. Instead we write the crash report
    to `/home/root/<user_hash>/crash/` which only requires being a member of the
    group `crash-user-access`.

## Kernel crashes

*   Upon a kernel panic occurring (which can happen when the kernel crashes with
    unexpected memory accesses and also with oops or BUG stat, a procedure is
    called which copies the current contents of the kernel debug buffer into a
    region of memory called "kcrash" memory.
*   This memory can be accessed from user space by reading the
    `/sys/kernel/debug/preserved/kcrash` file.
*   This kcrash memory is handled specially by the ChromeOS firmware when
    reboots occur.
*   Upon writing to this memory area, the kernel panic handler causes the system
    to reboot.
*   Upon restarting, crash_reporter checks the kcrash memory area, copies out
    its data to a crash report, analyzes the crash report for stack traces that
    signify the cause of the error, generates a hash/fingerprint of the stack,
    and enqueues that information in the kernel crash report.
    It then clears the kcrash area.

## Unclean shutdowns

*   Upon start up, crash_reporter is run.
    It creates a file on stateful partition to indicate that the current state
    is startup without clean shutdown.
*   Upon clean shutdown, crash_reporter is run.
    The stateful partition file is removed to indicate the current state is
    clean shutdown last occurred.
*   If upon start, the file already exists before crash_reporter attempts to
    create it, this signifies that the system was in the state of startup
    without clean shutdown.
    This signals an unclean shutdown.
    A signal is enqueued for metrics_daemon to emit user metrics about this
    unclean shutdown.
*   No diagnostics are currently collected for unclean shutdowns.

## Crash sending agent

*   Runs hourly and checks `/var/spool/crash`, `/home/chronos/user/crash`, and
    `/home/root/<user_hash>/crash` for reports, sends those, and removes them if
    successfully sent.
*   Rate limits to 32 crash diagnostics uploads in 24 hours across entire
    system.
*   We rely upon Google crash server to collect user space crash diagnostics for
    further analysis.
    We already know that it scales well to large numbers of Google Toolbar and
    Chrome desktop users.

# Alternatives Considered

One/some of these alternatives may indeed be what we implement in the longer
run.

## User space diagnostics

We considered linking [Google Breakpad] into every process with extra logic that
determines where and how to store crash dumps.
This was our first implementation.
Unfortunately we cannot affect the linking of every process (since some come to
Google as binary format).
Also the act of installing a signal handler in every process can be disruptive.
This could also be done at the libc level, such as how Android added to Bionic
(their libc replacement) the ability to catch unhandled segfaults in process and
signal a debugger process in the system.
While possible, it seems tricky to be installing this into every process.
The timing of when the library is initialized would be tricky, as well as
watching for infinite loops (what if the crash sending process crashes).

[Apport]: https://wiki.ubuntu.com/Apport
[Firmware event logs]: https://github.com/dhendrix/firmware-event-log/blob/wiki/FirmwareEventLogDesign.md
[Google Breakpad]: https://chromium.googlesource.com/breakpad/breakpad
[kexec]: https://en.wikipedia.org/wiki/Kexec
[Linux Kernel Crash Dump]: http://lkcd.sourceforge.net/
[LKCD]: http://lkcd.sourceforge.net/
[WINQUAL]: https://en.wikipedia.org/wiki/Winqual
[/proc/sys/kernel/core_pattern]: http://man7.org/linux/man-pages/man5/core.5.html
