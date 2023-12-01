# vm_concierge

`vm_concierge` is a daemon that exposes a D-Bus interface to control lifetime of
crosvm. See [`/vm_tools/README.md`](/vm_tools/README.md) for details.

[TOC]

## Hacking

For quick iteration on related projects, work on `vm_protos` for grpc and
`chromeos-base/system_api` for dbus.

```
cros_workon --board ${BOARD} start chromeos-base/system_api chromeos-base/vm_host_tools chromeos-base/vm_protos
```

Then it is possible to iterate on `vm_concierge`.

```
cros_workon_make --test --board=brya \
  chromeos-base/system_api \
  --install  # If system_api changed.
cros_workon_make --test --board=brya \
  chromeos-base/vm_protos \
  --install  # If vm_protos changed.
cros_workon_make --test --board=brya chromeos-base/vm_host_tools
```

### Obtaining backtrace on crash

Observe the logs on the device. Trigger what you are trying to debug. For
inspiration, the following are examples of triggering crash and observing logs.

```
tail -f /var/log/messages & start vm_concierge; fg
tail -f /var/log/messages & stop vm_concierge; fg
tail -f /var/log/messages & vmc stop termina; fg
```

Observe the dump log file on your workstation to get a backtrace. Using
[tast symbolize](https://chromium.googlesource.com/chromiumos/docs/+/HEAD/stack_traces.md#Symbolizing-minidumps-with-tast-symbolize)

```
scp dut:/var/spool/crash/vm_concierge.20230413.101819.53856.31734.dmp .
tast symbolize vm_concierge.20230413.101819.53856.31734.dmp
```

### When concierge fails to start up

concierge is started via upstart on /etc/init/vm_concierge.conf. Failure is
silent. Adding logging may help. Example:

https://chromium-review.googlesource.com/c/chromiumos/platform2/+/3600040

### When crosvm fails to start up

Adding strace to crosvm may help sometimes. Example:

https://chromium-review.googlesource.com/c/chromiumos/platform2/+/3205434
