# vsh - Vsock SHell

vsh is a remote shell that operates over [vsock]. Think of ssh, but replace
the first 's' with a 'v'.

[TOC]

## Why vsh?

SSH is the de-facto standard for getting a shell on a remote machine over a
network. This makes a lot of sense for a machine under your desk or a VM in the
cloud.

The most critical features SSH provides are:
*  Host authentication ensures you're talking to the right machine.
*  User authentication ensures only authorized users can sign in, and only as
   themselves.
*  Encryption prevents parties between the two machines snooping on your
   traffic.

vsh is focused on one use case only: connect to a VM on the same machine. This
lets us simplify the requirements substantially.

*  Host authentication is provided by [vsock]. Unlike IP, a VM cannot spoof its
   [vsock] context id. [vsock] is machine-local, so there is no concern with
   MitM attacks.

*  User authentication is not required. vsh is used exclusively from host to
   guest, and the host is always considered more privileged.

*  Encryption isn't necessary since [vsock] cannot be routed, and the traffic
   will transit directly between host and guest memory. Without a host kernel
   exploit, a VM cannot observe traffic intended for another VM.

Without the need for any encryption, vsh is simple to set up, and easily
integrated into a VM project. There's no need to have the guest OS configure
a network, since [vsock] does not require guest-side configuration.

>**NOTE:** Although the guest-side `vshd` does not authenticate users, it does
limit which user a shell can be launched with. For example, Crostini's `termina`
VM will only allow logging in as `chronos`. Developers must build a `test` image
of `termina` to allow logging in as `root`.

## Features

vsh can:

*  Run both interactive shells (like `bash`), as well as one-shot commands.

*  Detect interactive vs non-interactive usage. This allows piping binary data
   through vsh without triggering terminal escape codes, as well as using vsh to
   pipe `stdout` and `stderr` output separately.

*  Forward exit status from the guest-side process.

*  Forward certain signals. Sending `SIGHUP`, `SIGINT`, `SIGQUIT`, or `SIGTERM`
   will forward the signal to the remote process. This is useful in
   non-interactive environments such as [Tast] to force the guest-side process
   to exit cleanly.

## Usage examples

Launches a shell on the VM with [vsock] cid 3. This will work even with a
manually launched `crosvm` instance, as long as the guest is running `vshd`.
Check [here](#setup-a-crosvm-instance-for-vsh) for an example.

```bash
(device) # vsh --cid=3
```

Launches a shell on the VM named `foo`. Names are managed by [`vm_concierge`],
so this VM must have been started through the [`vm_concierge`] API. The
`$CROS_USER_ID_HASH` variable is only set for crosh-spawned shells. The
included one-liner can set it for you.

```bash
(device) # export CROS_USER_ID_HASH="$(cryptohome --action=status | \
                                       python3 -c 'import sys, json; \
                                                   print(json.load(sys.stdin)["mounts"][0]["owner"])')"

(device) # vsh --vm_name=foo --owner_id="${CROS_USER_ID_HASH}"
```

Launches a root shell on the VM named `foo`. This may require that the VM is
running a developer-built `test` image.

```bash
(device) # vsh --vm_name=foo --owner_id="${CROS_USER_ID_HASH}" --user=root
```

Runs `lxc list` in the `termina` VM with required environment variables set.

```bash
(device) # vsh --vm_name=termina \
               --owner_id="${CROS_USER_ID_HASH}" \
               -- \
               LXD_DIR=/mnt/stateful/lxd \
               LXD_CONF=/mnt/stateful/lxd_conf \
               lxc list
```

Writes a host file `foo` to `/bar` in the crostini container `penguin`.

```bash
(device) # cat foo | vsh --vm_name=termina \
                         --owner_id="${CROS_USER_ID_HASH}" \
                         --target_container=penguin \
                         -- \
                         sh -c "cat - > /bar"
```

Writes a file `/foo` from crostini container `penguin` to `bar` on the host.

```bash
(device) # vsh --vm_name=termina \
               --owner_id="${CROS_USER_ID_HASH}" \
               --target_container=penguin \
               -- \
               cat /foo > bar
```

### Setup a crosvm instance for vsh

First, the guest needs the `vshd` executable. [termina] [dlc] is one way to get
it. `vshd` is contained in `vm_tools.img`

```bash
(device) # dlcservice_util --install --id=termina-dlc
# Prints the root mount of termina-dlc, which should be `/run/imageloader/termina-dlc/package/root`
(device) # dlcservice_util --list
```

Launch `crosvm` with `--cid=3` and `vm_tools.img`.

```bash
(device) # crosvm run --cid=3 --disk /run/imageloader/termina-dlc/package/root/vm_tools.img ...
```

Then, run the following commands in guest to launch `vshd`.
```bash
(guest) # mount -t proc proc /proc
(guest) # mount -t sysfs sys /sys
(guest) # mount -t tmpfs tmp /tmp
(guest) # mount -t tmpfs run /run
(guest) # mkdir /dev/pts
(guest) # mount -t devpts devpts /dev/pts -o mode=0620,ptmxmode=666
(guest) # mkdir /tmp/vm_tools
(guest) # mount /dev/vda /tmp/vm_tools # or vdx depending on disks available
(guest) # /tmp/vm_tools/bin/vshd
```

[Tast]: https://chromium.googlesource.com/chromiumos/platform/tast/+/HEAD/README.md
[`vm_concierge`]: /vm_tools/concierge
[vsock]: https://www.man7.org/linux/man-pages/man7/vsock.7.html
[termina]: https://chromium.googlesource.com/chromiumos/overlays/board-overlays/+/main/project-termina/
[dlc]: /dlcservice/README.md
