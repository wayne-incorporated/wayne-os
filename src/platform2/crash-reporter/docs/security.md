# Crash Reporter Security

As a tool that usually runs as root in order to access the data in various
log and proc and sys files, we have to be extra careful while also processing
untrusted data -- the coredumps and process state are entirely under the
control of the untrusted processes.
This doesn't mean we can't take steps to reduce privilege and access to
runtime state we don't need, but we do have to be careful as we reduce
access to not also break our ability to collect data.

[TOC]

## Status

With that out of the way, the current state of the world:
all processes run as root all the time.  Oops.
That doesn't mean we want to stay here -- this section includes various ideas,
suggestions, and brainstorms for how we can reduce even further.

Our ultimate goals at all times are to run with minimal access to resources
and capabilities.
Further splitting up these tools into discrete helpers/components will probably
help with keeping clear lines for which tools need which privileges.

[anomaly_detector] needs read access to `/var/log/messages` and write access
to `/var/spool/crash/`.
[crash_reporter_logs.conf] needs read access to `dmesg` and some sysfs PCI
registers for the [kernel_warning_collector].
At the very least, we should be able to have this minijail itself.

[crash_sender] runs in a limited minijail, but still as root, and accesses
servers over the network.
It needs write access to all the crash spool directories, as well as its own
internal `/var/lib/crash_sender/` state, and `/run/lock/crash_sender`.
It only needs read access to `/run/crash_reporter/` for testing state.
Otherwise, the only mutable paths it needs are entirely self contained in the
spool paths, so dropping access to everything else should be doable.
Another idea is to fork a child for parsing the crash reports and communicating
with the network -- it would be able to drop privs and run under a restrictive
seccomp filter.
The only content it would need access to is the specific set of crash reports.

[crash_reporter] is a bit of a beast.
Not only does it need write access to `/var/lib/crash_reporter/` and the crash
spool directories, but it also needs read access to many `/proc/` files
(especially the `/proc/<pid>/` of the crashing process which usually have read
restrictions in place based on the crashing process's uid/gid), as well as all
the random supplemental log sources in [crash_reporter_logs.conf].
Perhaps during early startup, we setuid to an account for most work, and we only
setuid(0) again when we need to read a restricted path, and then we setuid back.
Or we drop all caps except `CAP_DAC_OVERRIDE` assuming the kernel still allows
us to access all the paths we need to.
For helper programs we run (most notably core2md), we should be able to run them
in a more restrictive environment as they are data-in/data-out tools.

Access to the spool dirs is needed by only these tools and feedback reports
(which are gathered as root by debugd).
So we should be able to change all of these from `root:root` to a new dedicated
account like `crash:crash`, as well as using that account for dropping privs.
This is tracked in https://crbug.com/441427.

## Cryptohome Protected Crash Reports

Some crash report are considered to be especially likely to contain sensitive
user information and are stored in the cryptohome. Right now these are stored in
`/home/user/<user_hash>/crash`, but `/home/user/<user_hash>` is only traversable
by user `chronos` and group `chronos-access`. This means that anything writing
into that spool directory currently must also acquire permission to read large
parts of the user data stored in the cryptohome, which limits our ability to
have lower privilege processes record crashes here.

Worse, it creates a potential privilege escalation vector because `crash_sender`
may end up processing reports with a higher privilege level then is required to
write to the directory. This means a lower privileged process could set up the
spool directory in an unexpected way to trick `crash_sender` by e.g. creating
symlinks, or modifying it at the same time as `crash_sender` is accessing
it. This has been a source of many historical vulnerabilities.

Fortunately, we now have another set of paths that form part of the cryptohome,
mounted under `/home/root/<user_hash>`. Directories under this path are created
there by `cryptohomed` and bind mounted to `/var/daemon-store/*/<user_hash>`,
which can be traversed to by any process. Therefore, we can create a new `crash`
sub-directory owned by `crash:crash-user-access` and processes that need to
produce encrypted crash reports can be given access to only this path by making
them members of `crash-user-access`. `crash_sender` will also be able to access
this directory while having strictly less privilege then any process that
creates crash reports. The new `/home/root/<user_hash>/crash` directory should
eventually replace the `/home/user/<user_hash>/crash` directory entirely.

This leaves some residual risk that one crash reporting process will compromise
another via this shared directory. Crash reporters interact with it in two
ways. Once by reading the filenames to determine if the directory is full, which
is unlikely to be exploitable by writing things to the directory, and later by
writing out files into the directory. This could be exploited by tricking the
process into writing to a symlink, but most (possibly all) writes to spool
directories open files using O_CREAT|O_EXCL to ensure they only write to newly
created ordinary files.

## Historical Vulnerabilities

Here we cover some vulnerabilities that were found in crash-reporter.
Hopefully by understanding the types of bugs that hit us in the past, we can
design a system that disables entire classes of bugs rather than simply fixing
each of these in a one-off fashion.

### crbug.com/678365 (info leak)

https://crbug.com/678365

This bug allowed the `chronos` user to read any file as root (including memory
of processes via `/proc/` symlinks).

The scenario is as follows:
*   chronos user has full read/write access to the path
    `/home/chronos/Consent To Send Stats`.
*   chronos user deletes the consent file and symlinks it to desired file.
*   chronos user creates a valid crash (such as visiting `chrome://crash`).
*   chronos user triggers crash uploading (a valid & authorized request).
*   crash_sender (as root) reads that path to get the UID.
*   crash_sender passes the value read as a command line option to curl.
*   chronos user is able to observe the commandline of all processes.
*   chronos user simply polls and watches `/proc/*/cmdline` files.

The fix for this was a directed one:
*   https://chromium-review.googlesource.com/422851:
    (1) metrics_client no longer follows symlinks, (2) metrics_client now
    validates the input file, and (3) all other projects replaced their own
    ad-hoc logic with a single robust implementation (calling metrics code).

There are a few alternative ways this could have been addressed, albeit with a
lot more disruption to the overall system.
*   https://crbug.com/359207:
    Lock down `/proc` so users can only see their own processes.
*   https://crbug.com/655606:
    Disallow following symlinks in the kernel on writable partitions (stateful).

### crbug.com/766275 (priv escalation)

https://crbug.com/766275

This bug allowed any user on the system to get root execution.

The scenario is as follows:
*   crash_reporter uses `/tmp/crash_reporter/<pid>/` with hardcoded filenames
    (e.g. `environ`) to hold intermediate state.
*   User starts a process that does:
    *   Creates `/home/chronos/drop/`.
    *   Symlinks `/home/chronos/drop/environ` to
        `/proc/sys/kernel/core_pattern`.
    *   Symlinks `/tmp/crash_reporter/getpid()` to `/home/chronos/drop`.
    *   Modifies own environment with content to be written to `core_pattern`
        (e.g. `|/bin/bash /home/...`).
    *   Forces self to crash.
*   crash_reporter is run by kernel as root to handle the crash.
*   crash_reporter sees `/tmp/crash_reporter/<pid>/` already exists.
*   crash_reporter copies `/proc/<pid>/environ` to
    `/tmp/crash_reporter/<pid>/environ`.
*   This dereferences the symlink and writes the content to `core_pattern`.
*   crash_reporter finishes its execution.
*   User triggers another crash.
*   Kernel executes user's custom code and they now have root.

A few directed fixes went in first:
*   https://chromium-review.googlesource.com/673485:
    `/tmp/crash_reporter/` is created and owned as root during early boot so
    no one else could hijack it.
*   https://chromium-review.googlesource.com/716878 &
    https://chromium-review.googlesource.com/721564:
    Move some `/tmp` state to `/run` which is only accessible by root and the
    daemon that initialized the specific subdir (e.g. crash-reporter).

After that, some class fixes went in:
*   https://chromium-review.googlesource.com/672943 &
    https://chromium-review.googlesource.com/678294 &
    https://chromium-review.googlesource.com/723869:
    Have crash_reporter & crash_sender always run in unique mount namespaces
    and create unique & empty `/tmp` mounts.
    Now any attacks via shared `/tmp` are impossible.

    We also mount `/proc` read-only so any write attacks to sysctl paths are
    impossible.
*   https://chromium-review.googlesource.com/753406:
    Make /proc/self/mem read-only for all processes (a noexec bypass).

There are a few class fixes that would help with this:
*   https://crbug.com/655606:
    Disallow following symlinks in the kernel on writable partitions (stateful).
*   https://crbug.com/873733:
    Following symlinks from sticky dirs are disallowed, but only when the last
    component of the path is a symlink.
    If an intermediate path is a symlink, it is still traversed.

### crbug.com/817993 (priv escalation)

https://crbug.com/817993

This bug allowed the chronos user to get root execution.

The scenario is as follows:
*   User creates a valid crash report (e.g. visit `chrome://crash`).
*   User edits the `.meta` file created under their chronos-owned
    `/home/chronos/<user_hash>/crash/` spool directory.
*   Add a line starting with `upload_` and followed by a sed script.
    e.g. `/p;s^.*^setsid${IFS}bash${IFS}<a-shell-script>${IFS}\&^ep;/=1`.
*   crash_sender (as root) parses that `.meta` file.
*   The `upload_...` key is extracted and passed to `sed` verbatim.
*   The `e` sed command executes an arbitrary command via `system()`.

The quick directed fix was to validate all input `.meta` reports:
*   https://chromium-review.googlesource.com/944788:
    If the `.meta` file contains any bad content, we just delete the report.

After that, some class fixes went in:
*   https://chromium-review.googlesource.com/949523:
    Hard enable sed's existing "sandbox" mode all the time for boards.
    This makes the `r/w/e` commands (read file/write file/execute) always
    unavailable and prevents arbitrary code exec ever again.
*   https://crbug.com/767182:
    Add a sandbox mode to awk and always enable it for all boards.
    This disables `system()`, file redirects, and pipelines.

There are a few class fixes that would help with this:
*   If the code parsing the report wasn't run as root (and it doesn't really
    have to), then that'd limit the damage of arbitrary code exec.
*   https://crbug.com/391887:
    Rewrite crash_sender in C++ to avoid all usage of external programs like
    `sed` or `awk` and thus any arbitrary code execution they introduce.

### crbug.com/866895 (priv escalation)

https://crbug.com/866895

This bug allowed people to chown arbitrary paths to `chronos` as root.

The scenario is as follows:
*   User deletes their `crash` spool directory in their profile.
*   User symlinks `crash` to an arbitrary path.
*   User triggers a crash.
*   `crash_reporter` is invoked by the kernel as root.
    It derefs the symlink and then chowns the target to `chronos`.

The fix was to improve the spool directory walking code to avoid any TOCTOU
races, and to have all filesystem operations avoid derefing any symlinks.
*   https://crrev.com/c/1156064:
    All paths are processed relative to the spool directory instead of absolute
    paths.  This allows us to guarantee the directory we open isn't a symlink,
    and that it never changes on us while we're processing it.
*   https://crrev.com/c/1152078:
    We use filesystem funcs that reject symlinks to initialize all spool
    directories.

The larger class fix involved blocking symlinks entirely.
*   https://crbug.com/655606:
    Disallow following symlinks in the kernel on writable partitions (stateful).


[anomaly_detector]: ../anomaly_detector.cc
[crash_reporter]: ../crash_reporter.cc
[crash_reporter_logs.conf]: ../crash_reporter_logs.conf
[crash_sender]: ../crash_sender.cc
[kernel_warning_collector]: ../kernel_warning_collector.cc
