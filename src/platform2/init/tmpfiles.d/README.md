# tmpfiles.d Configuration Files

These `.conf` files define filesystem operations that are needed to set up
paths. This is commonly creating specific files and directories with specific
permissions and ownership before running a system daemon. For example an
upstart job with:

```bash
pre-start script
  mkdir -p /run/dbus
  chown messagebus:messagebus /run/dbus
  mkdir -p /var/lib/dbus
end script
```

Can be replaced with a `tmpfiles.d` file with:

```bash
d= /run/dbus 0755 messagebus messagebus
d= /var/lib/dbus 0755 root root
```
See the [upstream documentation] for the configuration file format. On Chrome OS
the `=` is used to remove a path if it has the wrong type (FIFO vs.
directory vs. file vs. etc.) instead of failing with an error.

This configuration will take care of creating the listed paths with the correct
type, ownership, permissions, and SELinux labels. If the path already exists
with the wrong ownership or permissions they will be changed to match the
configuration with some caveats (see the note below). Remember the root-fs is
read-only and uses verity for integrity checking so you cannot create or change
paths on it without building a new image. Also, tmpfiles.d checks to make sure
symlinks in the parent directories paths do not cross from lower privilege to
higher privilege.

***note
**Note:**
If the parent directory is not owned by root and a sub path is owned
by a different user, it is treated as an unsafe transition. Currently, an unsafe
transition in a configured path will cause tmpfiles.d to fail with an error and
chromeos_startup will trigger a cleanup of the stateful partition.
***

The preferred location of these config files in the source tree is a
subdirectory of the parent project named `tmpfiles.d`.

## When not to use tmpfiles.d

Not all paths should be used with the tmpfiles.d mechanism.

For device-related paths under `/dev` and `/sys`, use udev rules instead to
set ownership & permissions.  These react well according to when the kernel
finishes initialization and avoid race conditions with userland.

## Configuration application timing

There are three primary ways to apply a tmpfiles.d configuration on Chrome OS.
1. As part of the early system start-up.
2. By using a tmpfiles stanza in an upstart job.
3. By calling systemd-tmpfiles directly on a configuration.

Note that these are not mutually exclusive, so different combinations can be
used if appropriate.

### Early startup

Configurations intended to be applied from startup should have the `.conf`
extension and be installed to `/usr/lib/tmpfiles.d` using `dotmpfiles` or
`newtmpfiles` from [tmpfiles.eclass]. The `--boot` flag is supplied here so
configuration entries with the `!` action will be applied.

[pre-startup.conf] applies configurations for the following path prefixes:

* `/dev`
* `/proc`
* `/run`

`/sys` can be added, but care needs to be taken because some subpaths are
mounted at a later time like cgroups.

After [pre-startup.conf] finishes, [chromeos_startup] is executed, which covers
the following path prefixes:

* `/home`
* `/media`
* `/mnt/stateful_partition`
* `/var`

Additional path prefixes can be added as needed, but care needs to be taking to
make sure the parent paths are mounted before applying the configuration.

### Upstart job pre-start

Adding a tmpfiles stanza to an upstart config applies the config before running
the pre-start stanza. This does not prevent the config from also being applied
at early boot.

Some reasons you might want a tmpfiles stanza are for paths created dynamically,
or to reduce the risk of a compromise persisting between user-sessions (without
a reboot).

Here is an excerpt from [vm_concierge.conf] with an example:

```
start on start-user-session
stop on stopping ui
respawn
expect daemon

tmpfiles /usr/lib/tmpfiles.d/arcvm.conf /usr/lib/tmpfiles.d/vm_tools.conf
```

The Chrome OS upstart patch that adds the tmpfiles stanza does not set the
`--boot` flag so configuration entries with the `!` action will not be applied.

### On demand

Configurations that can not be applied in early boot should be installed to
`/usr/lib/tmpfiles.d/on-demand` using `doins` or `newins`. These need either:
* A tmpfiles stanza to the appropriate upstart config as shown in the previous
section
* A direct call to systemd-tmpfiles. Here is an example:

```
systemd-tmpfiles --create --remove --clean <absolute path to your-tmpfiles-d.conf>
```

***note
**Note:**
You may not need all the options `--create`, `--remove`, or `--clean` depending
on the actions being applied. See the [upstream documentation] for more details.
***

One reason why this might be necessary is the cases a tmpfiles.d configuration
has a path inside a mount that is created on demand.

## Testing

Currently, an error in a tmpfiles.d config installed to /usr/lib/tmpfiles.d will
result in a stateful repair boot-loop. To avoid this when testing, copy your
config file to a different path and invoke it manually (or from an upstart job)
with:

```sh
/usr/bin/systemd-tmpfiles --boot --create --remove --clean <absolute path to your-tmpfiles-d.conf>
```

Generally, no errors are printed on success. If extra verbosity is desired, use:

```sh
export SYSTEMD_LOG_LEVEL=debug
```

## Troubleshooting and Common Obstacles

For tmpfiles.d configurations applied at startup, errors cause a clobber of
the stateful partition. Warnings and errors are logged to `/run/tmpfiles.log`
because the system log is set up after [chromeos_startup] executes and writes to
the stateful partition which may be clobbered. The [clobber_state_collector]
crash collector preserves this log across stateful_partition clobbers and writes
it to `/var/spool/crash` which can be checked when troubleshooting.

Warnings do not result in the stateful_partition being clobbered and the
[collect-early-logs] upstart job applies the contents of `/run/tmpfiles.log` to
the system log once it is available. These entries are prefixed with
"tmpfiles.d".

Here are some common errors with known resolutions.

### Paths Missing SELinux File Context Entries

If you see errors that resemble something like:

```
Failed to determine SELinux security context for /run/rsyslogd: Resource temporarily unavailable
Failed to create directory or subvolume "/run/rsyslogd": Resource temporarily unavailable
Failed to determine SELinux security context for /var/log/bluetooth.log: Resource temporarily unavailable
Unable to fix SELinux security context of /var/log/bluetooth.log (/var/log/bluetooth.log): Resource temporarily unavailable
```

The problem is usually missing SELinux file context entries. This occurs because
tmpfiles.d tries to restore the SELinux labels of the path. The restore
operation depends on having a file context entry. In some cases the path may
already have an existing label applied through a context transition policy rule,
but without the file context entry tmpfiles.d will still fail.

Here are example entries to resolve the above errors from
[chromeos_file_contexts]:

```
/run/rsyslogd             u:object_r:cros_run_rsyslogd:s0
/var/log/bluetooth.log    u:object_r:cros_var_log_bluetooth:s0
```

*** note
**Note:** the context label (e.g. `cros_var_log_bluetooth`) needs to be defined.
Most are located in [file.te].
***

More information about defining the SELinux policy can be found in the
[SELinux documentation].

[chromeos_file_contexts]: /sepolicy/file_contexts/chromeos_file_contexts
[chromeos_startup]: /init/chromeos_startup
[clobber_state_collector]:  /crash-reporter/clobber_state_collector.cc
[collect-early-logs]: /init/upstart/collect-early-logs.conf
[file.te]: /sepolicy/policy/base/file.te
[pre-startup.conf]: /init/upstart/pre-startup.conf
[SELinux documentation]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/security/selinux.md
[tmpfiles.eclass]: https://chromium.googlesource.com/chromiumos/overlays/portage-stable/+/HEAD/eclass/tmpfiles.eclass
[upstream documentation]: https://www.freedesktop.org/software/systemd/man/tmpfiles.d.html
[vm_concierge.conf]: /vm_tools/init/vm_concierge.conf
