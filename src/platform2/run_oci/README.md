# `run_oci`

## Overview

`run_oci` is a minimalistic container runtime that is (mostly) compatible with
the [OCI runtime spec](https://github.com/opencontainers/runtime-spec).

## Chrome OS extensions

The OCI runtime spec allows implementations to add additional properties for
[extensibility](https://github.com/opencontainers/runtime-spec/blob/HEAD/config.md#extensibility).

Chrome OS adds the following extensions:

### Pre-chroot hooks

There are some bind-mounts that cannot be specified in the config file, since
the source paths for them are not fixed (e.g. the user's cryptohome path), or
can be enabled dynamically at runtime depending on [Chrome
Variations](https://www.google.com/chrome/browser/privacy/whitepaper.html#variations).

During the container setup in Chrome OS, there is a small window of time when
the container's mount namespace is completely set up, but
[chroot(2)](http://man7.org/linux/man-pages/man2/chroot.2.html) has not been yet
called, so bind mounts that cross the chroot boundary can still be performed.

The
[**`hooks`**](https://github.com/opencontainers/runtime-spec/blob/HEAD/config.md#posix-platform-hooks)
object has been extended to also contain the following:

* **`precreate`**: *(array of objects, OPTIONAL)* - is an array of pre-create
  hooks. Entries in the array have the same schema as pre-start entries, and are
  run in the outer namespace before the container process is created.

* **`prechroot`**: *(array of objects, OPTIONAL)* - is an array of pre-chroot
  hooks. Entries in the array have the same schema as pre-start entries, and are
  run in the outer namespace after all the entries in [**`mounts`**](https://github.com/opencontainers/runtime-spec/blob/HEAD/config.md#mounts)
  have been mounted, but before chroot(2) has been invoked.

#### Example (Chrome OS)

    {
        "hooks": {
            "precreate": [
                {
                    "path": "/usr/sbin/arc-setup",
                    "args": ["arc-setup", "--setup"]
                }
            ],
            "prechroot": [
                {
                    "path": "/usr/sbin/arc-setup",
                    "args": ["arc-setup", "--pre-chroot"]
                }
            ]
        }
    }

### Linux device node dynamic major/minor numbers

Device nodes that have well-known major/minor numbers are normally added to the
[**`devices`**](https://github.com/opencontainers/runtime-spec/blob/HEAD/config-linux.md#devices)
array, whereas device nodes that have dynamic major/minor numbers are typically
bind-mounted. Android running in Chrome OS needs to have device node files
created in the container rather than bind-mounted, since Android expects the
files to have different permissions and/or SELinux attributes.

The objects in the **`devices`** array has been extended to also contain the
following:

* **`dynamicMajor`** *(boolean, OPTIONAL)* - copies the [major
  number](https://www.kernel.org/doc/Documentation/admin-guide/devices.txt) from
  the device node that is present in `path` outside the container. If
  `dynamicMajor` is set to `true`, the value of `major` is ignored.

* **`dynamicMinor`** *(boolean, OPTIONAL)* - copies the [minor
  number](https://www.kernel.org/doc/Documentation/admin-guide/devices.txt) from
  the device node that is present in `path` outside the container. If
  `dynamicMinor` is set to `true`, the value of `minor` is ignored.

#### Example (Chrome OS)

    {
        "linux": {
            "devices": [
                {
                    "path": "/dev/binder",
                    "type": "c",
                    "major": 10,
                    "dynamicMinor": true,
                    "fileMode": 438,
                    "uid": 0,
                    "gid": 0
                }
            ]
        }
    }

### Support for mounts in an intermediate mount namespace

Most mounts can be done in the container's mount namespace, especially if a user
namespace is also used, since that gives the caller the `CAP_SYS_ADMIN`
capability inside the container. However, the interaction between the mount and
user namespaces carry other restrictions. For instance, changing most mount
flags does not work at all: any mount that is created in the container's
namespace is completely invisible from the init namespace (so real root in the
init mount+user namespace cannot modify it), and entering the mount namespace
with [setns(2)](http://man7.org/linux/man-pages/man2/setns.2.html) still does
not allow root to perform a remount since the user namespace associated with the
namespace to be entered does not match the outer namespace.

In order to overcome the above restriction, a new flag is added to objects in
[**`mounts`**](https://github.com/opencontainers/runtime-spec/blob/HEAD/config.md#mounts),
that will cause `run_oci` to create an intermediate mount namespace that has the
init user namespace associated with it. This way, privileged operations that
require being in the init user namespace can still be carried out, and the
mounts don't leak to the init mount namespace.

The objects in the **`mounts`** array has been extended to also contain the
following:

* **`performInIntermediateNamespace`** *(boolean, OPTIONAL)* - creates an
  intermediate [mount
  namespace](http://man7.org/linux/man-pages/man7/mount_namespaces.7.html) in
  which the mounts are performed. This namespace is associated with the init
  user namespace, so privileged mounts that require having the `CAP_SYS_ADMIN`
  capability in the init user namespace (such as non-bind remounts) can still be
  performed. Upon entering this namespace, the mount propagation flags specified
  by `rootfsPropagation` (which default to `"rslave"`) are honored. Defaults to
  `false`.

#### Example (Chrome OS)

    {
        "rootfsPropagation": "rprivate",
        "mounts": [
            {
                "destination": "/",
                "type": "bind",
                "source": "",
                "options": [
                    "remount",
                    "ro",
                    "nodev"
                ],
                "performInIntermediateNamespace": true
            }
        ]
    }

### Alternate Syscall Table

The Chromium OS kernel has infrastructure for changing syscall tables using the
[alt-syscall](https://chromium.googlesource.com/chromiumos/third_party/kernel/+/4ee2ed4d5903c2354c3ded9ee8eef663c403e457/security/chromiumos/Kconfig#28)
infrastructure.  This allows containers to further reduce the kernel attack
surface area by not even exposing some system calls, and is also faster than
using [seccomp(2)](http://man7.org/linux/man-pages/man2/seccomp.2.html) BPF
filters.

The
[**`linux`**](https://github.com/opencontainers/runtime-spec/blob/HEAD/config-linux.md)
object has been extended to also contain the following:

* **`altSyscall`**: *(string, OPTIONAL)* - changes the system call table for the
  container to the one specified.  Support for the chosen alt-syscall must be
  built into the kernel.  Please refer to the `whitelists` table in
  [alt-syscall.c](https://chromium.git.corp.google.com/chromiumos/third_party/kernel/+/chromeos-4.4/security/chromiumos/alt-syscall.c)
  for the full list of supported values.

#### Example (Chrome OS)

    {
        "linux": [
            {
                "altSyscall": "android"
            }
        ]
    }

### Securebits

`run_oci` by default sets all [securebits](https://lwn.net/Articles/280279/)
(except `NO_CAP_AMBIENT_RAISE` and `NO_CAP_AMBIENT_RAISE_LOCKED`) when starting
the container.  Some containers might want to leave more securebits not set
(e.g. so that processes can retain their capabilities after transitioning to a
non-root user).

The
[**`linux`**](https://github.com/opencontainers/runtime-spec/blob/HEAD/config-linux.md)
object has been extended to also contain the following:

* **`skipSecurebits`**: *(array of strings, OPTIONAL)* - adds additional securebits
  to not be set in the container process.  Please refer to the
  `linux/securebits.h` header for an updated list of supported securebits.

#### Example (Chrome OS)

    {
        "linux": [
            {
                "skipSecurebits": [
                    "KEEP_CAPS",
                    "KEEP_CAPS_LOCKED"
                ]
            }
        ]
    }

### Initial file mode creation mask

The file mode creation mask (`umask`) is inherited from its parent process.  The
default value for this is `18` (or `0022` in octal), but some containers need it
to be `0`.

The
[**`process`**](https://github.com/opencontainers/runtime-spec/blob/HEAD/config.md#posix-process)
object has been extended to also contain the following:

* **`umask`**: *(uint32, OPTIONAL)* - sets the initial file mode creation mask
  ([`umask`](http://man7.org/linux/man-pages/man2/umask.2.html)) for the
  container process. Defaults to `18`, which corresponds to `0022` in numeric
  notation (octal) and `----w--w-` in symbolic notation.

#### Example (Chrome OS)

    {
        "process": {
            "umask": 0
        ]
    }
