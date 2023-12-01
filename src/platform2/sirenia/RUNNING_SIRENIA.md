# Running Sirenia

Instructions for running Sirenia both on ManaTEE and non-ManaTEE environments.

[TOC]

## Local Workflows

### Building using cargo

```bash
cd ~/trunk/src/platform2/sirenia
cargo build --workspace
```

The binaries are statically compiled so they can be copied to the target device
using scp:

```bash
cd ~/trunk/src/platform2/sirenia
ssh test-device-hostname mount -o remount,rw /
scp ./target/debug/dugong ./target/debug/manatee ./target/debug/trichechus test-device-hostname:/usr/bin/
```

### Unit testing using cargo

Unit testing using cargo

```bash
cd ~/trunk/src/platform2/sirenia
cargo test --workspace
```

## Sirenia workflows for non-manatee boards

`USE=sirenia` instructs [target-chromium-os] to install sirenia and its
dependencies as well as enables the [security.Manatee.fake tast test]. It is set
by default for the amd64-generic and arm64-generic boards, but can be set to
enable the same features when building an image of your choice. In this mode the
`trichechus` and TEE app binaries are installed to `/usr/bin/` alongside
`dugong`, and `manatee` but the upstart init scripts are not installed for
`dugong` or `cronista`.

### Building using portage

```bash
USE=sirenia ./build_packages --board=${BOARD}
```

or

```bash
emerge-${BOARD} manatee-runtime manatee-client cronista sirenia
cros deploy --deep <target> cronista manatee-client sirenia manatee-runtime
```

The trichechus, cronista, dugong, and tee binaries can be found in `/usr/bin`

### Manual testing

Each command starts a part of the sirenia system and outputs the address and
port to connect the next step in the setup process to. E.g. when you run
cronista, it will output something like `[INFO:src/main.rs:50] waiting for
connection at: ip://127.0.0.1:32881` which is the address and port to connect
trichechus to:

```bash
/sbin/minijail0 -u cronista -- /usr/bin/cronista -U ip://127.0.0.1:0
/usr/bin/trichechus -U ip://127.0.0.1:0 -C ip://127.0.0.1:<port>
/sbin/minijail0 -u dugong -- /usr/bin/dugong -U ip://127.0.0.1:<port>
```

There are 2 options for telling dugong to start up a new TEE app. The preferred
method is by calling `manatee_runtime` like so:

```bash
manatee -a demo_app
```

The other option is to send a dbus command to dugong to start up a tee app

```bash
dbus-send --system --type=method_call --print-reply --dest=org.chromium.ManaTEE /org/chromium/ManaTEE1 org.chromium.ManaTEEInterface.StartTEEApplication string:demo_app
```

#### Troubleshooting

The binaries have usage messages when run with the `-h` flag that say the build
timestamp as well as the usage of the binary.

### Integration testing

```bash
tast run test-device-hostname security.Manatee.fake
```

Note: Board must have been built with USE=sirenia set or you must add sirenia to
/usr/local/etc/tast_use_flags.txt

## Sirenia workflows for manatee boards

Manatee boards set the `manatee` USE flag which does the following:

*   The manatee kernel is installed with the CrOS kernel added to the initramfs.
*   Trichechus (and TEE apps) are installed to the initramfs
*   Dugong and cronista are started by upstart as system services.

Note: The only manatee board options at the moment are
`{hatch,volteer-brya}-manatee`.

### Building using portage

```bash
emerge-${BOARD} manatee-runtime cronista sirenia
```

### Integration testing

`tast run test-device-hostname security.Manatee.real`

[target-chromium-os]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/virtual/target-chromium-os/target-chromium-os-9999.ebuild
[security.Manatee.fake tast test]: https://chromium.googlesource.com/chromiumos/platform/tast-tests/+/HEAD/src/chromiumos/tast/local/bundles/cros/security/manatee.go
