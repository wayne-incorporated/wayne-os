# Overview

Runtime Probe is essentially a command line tool that consumes the
[probe syntax](https://chromium.googlesource.com/chromiumos/platform/factory/+/HEAD/py/probe/README.md#detail-usage-the-syntax-of-a-probe-config-file)
and outputs the
[probe result](https://chromium.googlesource.com/chromiumos/platform/factory/+/HEAD/py/probe/README.md#output-format).

This command line tool will gradually replace fields in HWID (i.e. less fields
will be encoded into HWID) as it reflects the status of a device in a more
timely approach. **We are not aiming to be a daemon service**, instead, we pose
ourselves as a one-shot call tool, just like the `ping` command, the D-Bus
method introduced later is also on-demand and expected to exit immediately after
one call.

Currently, the reported data is purely hardware information. For example, the
model of storage, the remaining capacity of battery, the screen resolution..etc.

To serve clients that are not able to call the command line directly, we offer a
simple, restricted D-Bus interface with only one method
`org.chromium.RuntimeProbe.ProbeCategories`. This D-Bus method follows the
[Chrome OS D-Bus Best Practices](https://chromium.googlesource.com/chromiumos/docs/+/HEAD/dbus_best_practices.md#limit-use-of-d_bus-to-start-services-on_demand),
proper `minijail0`, `secomp policy` are applied inside
`dbus/org.chromium.RuntimeProbe.conf`.

# Motivation

To better reflect hardware configuration on users’ system, we need a tool in
release image that is able to reflect the truth of the moment in the field.
Traditionally, this need has been satisfied by
[factory's probe framework](https://chromium.googlesource.com/chromiumos/platform/factory/+/HEAD/py/probe/README.md),
because we assume rare components replacement after mass production. However, we
have seen more and more requests from partners to switch components after
devices left the factory process.

This work is also related to the evolution of HWID. Instead of going into
details on the complicated plan, we would like to use an example to let the
reader get a high level concept on how this work helps cases in HWID.

Let's look into a typical scenario here: After years' love into the Chromebook,
a user has one of the DRAM broken in slots, and would like to replace it.
However, the original part is already EOL (End Of Life), ODM has no choice but
to pick another part from the
[AVL (Approved Vendor List)](https://www.google.com/chromeos/partner/fe/#avl),
while this new DRAM is installed, the original probe result (HWID) in factory is
violated. Hence, even after the factory process, we would like to get the probe
result to reflect the truth of the moment under release image. Runtime is used
to convey the concept of dynamic.

# Contribute to Runtime Probe

## Environment

Runtime Probe has a significant different logic when working with
`cros_debug=0`, in order to test the behavior under so, you might try to setup a
device like the following:

*   CCD Unlock
*   Build locally a test image for your device and flash it to ensure your USE
    flags are aligned. Image is suggested to build with rootfs verification
    disabled in `build_image` step.

*   Flash the latest dev-signed firmware, for Googler, it might be easier to get
    it from
    [GoldenEye](https://cros-goldeneye.corp.google.com/chromeos/console/listFFBuild?type=firmware#).
    Suggest to use the following for flashing while keeping the VPD: `futility
    update --force -i $FILE`

*   Switch on/off developer mode

    Besides the
    [developer
    doc](https://chromium.googlesource.com/chromiumos/docs/+/HEAD/developer_mode.md)
    describing how to enter/leave developer mode, following is another useful
    hack to prevent some long running check while switching mode for the first
    time.
    *   Before switching on developer mode
        * `touch /mnt/stateful_partition/.developer_mode`
        * `sync`
    *   Before switching off developer mode
        * `rm /mnt/stateful_partition/.developer_mode`
        * `sync`

*   Hack[^1] to keep developer tools (For example: python, emerge for `cros
    deploy`) while mocking `cros_debug=0`

    *   Switch off developer mode
    *   `sed -i 's/CROS_DEBUG=/CROS_DEBUG=1 #/g' /sbin/chromeos_startup`
    *   Reboot

*   Toggle the `cros_debug` to 0

    *   `cd /usr/share/vboot/bin/`
    *   `./make_dev_ssd.sh --save_config /tmp/foo --partitions 2`
    *   `sed -i 's/cros_debug//g' /tmp/foo.2`
    *   `./make_dev_ssd.sh --set_config /tmp/foo --partitions 2`

*   Toggle the `cros_debug` to 1

    *   `cd /usr/share/vboot/bin/`
    *   `./make_dev_ssd.sh --save_config /tmp/foo --partitions 2`
    *   `sed -i 's/cros_secure/cros_secure cros_debug/g' /tmp/foo.2`
    *   `./make_dev_ssd.sh --set_config /tmp/foo --partitions 2`


## Development

*   `cros_workon-$BOARD start runtime_probe`
*   `emerge-$BOARD runtime_probe`
*   `cros deploy $ACTIVE_DUT runtime_probe`
*   On the device:
    *   `runtime_probe --vebosity_level=3`

## Testing

Runtime Probe provides CLI and a D-Bus interface, and our goal is to **make sure
using Runtime Probe by both interface works correctly**. The main runtime\_probe
binary executed via CLI is free of minijail and hence is useful for testing the
correctness of probe function. D-Bus call to Runtime Probe is the main entry
point we expect in most use cases.  It is guarded by minijail, and the main goal
is to ensure the integrity of this entry point.

### Via CLI

Simply run the following:
```shell
localhost ~ # runtime_probe [--verbosity_level=<level>]
```
This command will produce the probe result in json format, also it verifies the
correctness of probe results and tests the sandbox args of each probe function
(if `cros_debug` is set to 1).

### Via D-Bus call

The following script tests the D-Bus entry of runtime\_probe remotely. Besides
the output of the following script, the protocol buffer would also be shown in
`/var/log/messages` by changing the `verbosity_level` in
`runtime_probe/init/runtime_probe.conf` to 3. (And deploy to DUT by
`emerge-${BOARD} runtime_probe && cros deploy "$ACTIVE_DUT" runtime_probe`)

```shell
#!/bin/sh

PROTO_DIR_PATH="$HOME/trunk/src/platform2/system_api/dbus/runtime_probe/"
PROTO_PATH="$PROTO_DIR_PATH/runtime_probe.proto"

# Executing the following commands in cros_sdk or change the proto paths above

CATEGORIES="categories:battery\ncategories:vpd_cached\ncategories:storage"
PROTO_BYTES=$(echo -e "$CATEGORIES" | \
  protoc --encode runtime_probe.ProbeRequest --proto_path="$PROTO_DIR_PATH" "$PROTO_PATH" | \
  hexdump -v -e '/1 "%d,"')

RAW_HEX_PROBE_RESULT=$(ssh root@$ACTIVE_DUT sudo -u chronos \
  dbus-send --system --print-reply=literal \
  --type=method_call --dest=org.chromium.RuntimeProbe \
  /org/chromium/RuntimeProbe org.chromium.RuntimeProbe.ProbeCategories \
  array:byte:"$PROTO_BYTES")

echo "$RAW_HEX_PROBE_RESULT" | sed -e '1d;$d' | \
  xxd -r -p | \
  protoc --decode runtime_probe.ProbeResult --proto_path="$PROTO_DIR_PATH" "$PROTO_PATH"
```
Sample output:
```
storage {
  name: "generic"
  values {
    path: "/sys/class/block/nvme0n1"
    sectors: 1234567890
    size: 123456789012
    type: "NVMe"
    pci_vendor: 9876
    pci_device: 5432
    pci_class: 67890
  }
}
...
probe_config_checksum: "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
```

### Per probe function

The probe statement of Runtime Probe could be customized for any supported probe
function.  The following script tests each function via debugd and use the
corresponding sandbox environment for each probe function.

```shell
#!/bin/sh
# on DUT with cros_debug = 1
# "generic_battery" could be replace with any supported probe function.
cat << EOF > per_function.json
{"CUSTOM_CATEGORY": {"CUSTOM_COMPONENT_NAME": {"eval": {"some_new_probe_function": {}}}}}
EOF
runtime_probe --config_file_path=./per_function.json
```

On DUT with `cros_debug` = 0 we cannot use `--config_file_path` option. However,
we could leverage `/etc/runtime_probe/$MODEL/probe_config.json` like the
following:
```shell
#!/bin/sh
# backup probe_config.json
cat << EOF > /etc/runtime_probe/$MODEL/probe_config.json
{"CUSTOM_CATEGORY": {"CUSTOM_COMPONENT_NAME": {"eval": {"some_new_probe_function": {}}}}}
EOF
runtime_probe  # or via D-Bus as described earlier
```

### On Recovery image

* Get the following from the [image folder](http://go/goldeneye) of a Live,
  where xxx is the channel [beta, dev, stable] and yyy is the board name and
  zzz is the version info.
  * xxx-channel\_yyy\_zzz\_ChromeOS-firmware-...tar.bz2
    * image-yyy.bin
  * xxx-channel\_yyy\_zzz\_ChromeOS-recovery-...tar.xz
    * recovery\_image.bin
* Flash the dev-signed firmware, image-yyy.bin by using futility.
* Flash to the USB and trigger a recovery install [ Ctrl + Alt + D ]
* Switch to developer mode and login into console [ Ctrl + Alt + F2 ]
* Disable rootfs verification
  * `cd /usr/share/vboot/bin/`
  * `./make_dev_ssd.sh --remove_rootfs_verification --partitions 2`
* Reboot the system
* Enable Developer Console login in normal mode
  * Delete the following lines in `/etc/init/boot-splash.conf`
    * `if is_developer_end_user; then`
    * `fi`
* Login as root and change the password to non-empty (might just use `test0000`)
* Reboot the system and disable developer switch
* You should be able to login as root with the password set before
* Clear the `/var/log/message` for better check
  * `echo 0 > /var/log/messages`
* Acts as chronos
  * `su chronos`
* Either execute a script or type manually on DUT

```shell
#!/bin/sh
PROTO_BYTES="10,2,1,2"
PROBO_BYTES="10,1,3"  # for devices report vpd_cached only
dbus-send --system --print-reply \
--type=method_call --dest=org.chromium.RuntimeProbe \
/org/chromium/RuntimeProbe org.chromium.RuntimeProbe.ProbeCategories \
array:byte:"$PROTO_BYTES"
```

* `10,2,1,2` is the generated ProbeRequest, which should depend on the version
  of image. For example `10,1,3` for devices only reporting vpd\_cached.  These
  value could be encoded by `protoc --encode` command mentioned in [via D-Bus
  call](#via-d_bus-call).
* Check the `/var/log/message` if the ProbeResult dumps every field in the
  protocol buffer.
* Again this ProbeResult could be decoded from local machine in a way similar to
  the test script described in [via D-Bus call](#via-d_bus-call)

### Via Tast

[Tast](https://chromium.googlesource.com/chromiumos/platform/tast/+/HEAD/README.md)
is a golang-based test framework.  Currently tast-tests for Runtime Probe check
if the probe result matches the cros labels we decoded from the HWID of DUT.
Please refer to `cros_runtime_probe_*.go` under [platform
tests](https://chromium.googlesource.com/chromiumos/platform/tast-tests/+/HEAD/src/chromiumos/tast/local/bundles/cros/platform/).

Note that Runtime Probe uses the probe statements at
`/etc/runtime_probe/$MODEL/probe_config.json` on DUT.  The names of probed
components are directly under the probe categories (e.g. component
"MODEL\_COMPONENT1" under category "battery").  This is an
[example](http://go/runtime-probe-component-example-probe-statement) for such
component name.

On the other hand, we will compare the above probed component name with one
described in HWID DB file which is used to generate HWID string.  This is an
[example](http://go/runtime-probe-component-example-hwid) for the same component
name described in HWID DB. These component names will be cros labels and be
passed from `-varsfiles` option of tast.  We can manually create one and run
tast tests with it in cros\_sdk.

```bash
#!/bin/sh
# in cros_sdk
cat << EOF > labels.yaml
autotest_host_info_labels: '["model:MODEL", "hwid_component:battery/MODEL_COMPONENT1", "hwid_component:storage/MODEL_COMPONENT2"]'
EOF
tast -verbose=true -logtime=false run -build=true -logtime=false -varsfile=labels.yaml "$ACTIVE_DUT" '(!disabled && "group:runtime_probe")'
```
In the output there will be the probed component names and expected component
names for clarification.

Example output:
```
Using SSH key ...
Using SSH dir ...
Writing results to /tmp/tast/results/20200220-172233
Connecting to $ACTIVE_DUT
Getting architecture from target
Building local_test_runner, cros, remote_test_runner, cros
Built in 2.778s
Pushing executables to target
Pushed executables in 4.104s (sent 9.4 MB)
Getting data file list from target
Got data file list with 0 file(s)
Getting DUT info
Software features supported by DUT: ...
Getting initial system state
[01:22:42.048] Devserver status: [[http://127.0.0.1:28082 UP]]
[01:22:42.048] Found 0 external linked data file(s), need to download 0
Started test platform.CrosRuntimeProbeBattery
[01:22:42.173] Probed battery:MODEL_COMPONENT1
[01:22:42.173] Skip known generic probe result
Completed test platform.CrosRuntimeProbeBattery in 89ms with 0 error(s)
Ran 1 local test(s) in 481ms
Starting /tmp/tast/build/host/remote_test_runner locally
Ran 0 remote test(s) in 26ms
Collecting system information
--------------------------------------------------------------------------------
platform.CrosRuntimeProbeBattery  [ PASS ]
--------------------------------------------------------------------------------
Results saved to /tmp/tast/results/20200220-172233
```
# Documents

* Design doc: [go/cros-probe](http://go/cros-probe)
* Consolidated summary for all supported component types and probing fields:
  [go/cros-runtime-probe-fields](http://go/cros-runtime-probe-fields)

# Useful Reference

* minijail0 manpage (`man 1 minijail0` in cros\_sdk)
* [docs/sandboxing.md](https://chromium.googlesource.com/chromiumos/docs/+/HEAD/sandboxing.md)
* [debugd/src/](https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/debugd/src/)

<!-- Footnotes themselves at the bottom. -->

# Notes

[^1]: Subject to change based on the other program, after this quick hack, you
    will not able to switch to developer mode easily.
