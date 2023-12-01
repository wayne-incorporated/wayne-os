# Testing a Probe Function
If a ProbeFunction subtype interacts with the hardware, you probably need to run
the function in a separated minijail sandbox.  For example, the
`generic_battery` function has the following files:

- functions/generic_battery.h
- functions/generic_battery.cc
- sandbox/generic_battery.args
- sandbox/amd64/generic_battery-seccomp.policy

Files `sandbox/generic_battery.args` and
`sandbox/${ARCH}/generic_battery-secomp.policy` will be installed under
`/etc/runtime_probe/sandbox/` in the rootfs.

When evaluating a probe config, the probe config might want to probe battery by
using `generic_battery` probe function.  In this case, `GenericBattery::Eval()`
will be called.  The `GenericBattery::Eval()` function calls
`GenericBattery::InvokeHelper()` (which is inherited from `ProbeFunction` base
class).  The helper function invokes a DBus call, calling method
`EvaluateProbeFunction` of `debugd`.  The function will start a sandboxed
process (using minijail), which should be equivalent to:

```
# Check platform2/debugd/src/probe_tool.cc for the up-to-date version.

# sandbox/generic_battery.args is a JSON serialized list.
ARGS="$(jq -r .[] <"/etc/runtime_probe/sandbox/generic_battery.args")"
POLICY="/etc/runtime_probe/sandbox/generic_battery-seccomp.policy"

minijail0 \
    -v \
    -u runtime_probe -g runtime_probe \
    -S "${POLICY}" \
    -n \
    -G \
    -P /mnt/empty \
    -b / \
    -b /proc \
    -b /dev/log \
    -t \
    -r \
    -d \
    ${ARGS} \
    -- \
    /usr/bin/runtime_probe \
    --helper \
    -- \
    '{"generic_battery": {}}'
```

You can use the commands above to test it on your device.  If there are
permission / policy errors, you can add `-L` to get more details about the
violation (the blocked system call will be printed to syslog).

Checkout [Sandboxing Chrome OS system services](https://chromium.googlesource.com/chromiumos/docs/+/HEAD/sandboxing.md)
to learn more about minijail options.

The helper process starts in the created sandbox, and the
`GenericBattery::EvalInHelper()` will be called, which should be the real
implementation of the probe function.
