# cecservice

## About

cecservice is a system service allowing its clients to put [CEC] enabled TVs in
and out of standby mode.

## D-Bus API

The service exposes a D-Bus API consisting of following functions:
*   `SendWakeUpToAllDevices` - wakes up all TVs, putting them out of standby and
    announces the device running this service as an active source.
*   `SendStandByToAllDevices` - puts all TVs on standby.
*   `GetTvsPowerStatus` - returns power status of TVs (devices with logical
    address 0) on all connected CEC adapters.

## Implementation

cecservice uses the [Linux CEC API] to interact with CEC adapters present on
the device. It assumes exclusive ownership of `/dev/cecX` device nodes and
keeps all of them open at all times. The service uses libudev to keep track
of CEC devices as they come and go.

When the client invokes the `SendWakeUpToAllDevices` method on the service,
the service sends a `Image View On` request to devices with logical address 0
on all present `/dev/cecX` adapters. Following that, an `Active Source`
message is sent, announcing the device to be an active source.

Similarly, when `SendWakeUpToAllDevices` is called, the service sends
a `StandBy` request to devices with logical address 0 on all CEC adapters.

After the `SendWakeUpToAllDevices` is called the service will assume an active
source role. While being an active source it will respond to
`Request Active Source` requests and will continue doing so until either
another CEC device announces itself as an active source or
the `SendStandByToAllDevice` is called.

`GetTvsPowerStatus` sends `give device power status` request on all adapters.
This method returns array of integers, each integer describing power state of
a TV connected to an adapter. The meaning of the values is explained in
the service [system API] definition.

## Supported adapters / limitations

The service only works with CEC adapters which drivers handle physical address
configuration on their own and which allow userland to configure logical
addresses.

[CEC]: https://en.wikipedia.org/wiki/Consumer_Electronics_Control
[Linux CEC API]: https://www.kernel.org/doc/html/latest/media/uapi/cec/cec-api.html
[system API]: https://chromium.googlesource.com/chromiumos/platform/system_api/+/HEAD/dbus/cecservice/dbus-constants.h
