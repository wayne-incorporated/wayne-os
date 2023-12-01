# Chrome OS Iio Service

The repository hosts the core Chrome OS platform iioservice components,
including:

- [Mojo IPC library](libiioservice_ipc) for sensors mojo interfaces
- [Daemon iioservice](daemon) for CrOS Daemon Iio Service's implementation
- [Iioservice test executables](iioservice_simpleclient) for Iio Service IPC

## Mojo IPC library

This library provides mojo interfaces. Developers should use
[CrOS Mojo Service Manager](../mojo_service_manager) to connect to Iio Service via
`IioSensor` service. The first mojo pipe created is
`cros::mojom::SensorService`.

## Daemon iioservice

- `/usr/sbin/iioservice`

This daemon provides mojo channels that let processes connect to it. iioservice
will dispatch devices' event data to the processes that need them. Each process
can set the desired frequencies and IIO channels of devices without conflicts,
as it owns all IIO devices.


## Iioservice test executables

Several test executables are contained under this directory. Developers can
also take these as examples when adding sensor clients in platform2.

- `/usr/local/sbin/iioservice_simpleclient`
- `/usr/sbin/iioservice_simpleclient`

Reads iio samples with a device id, a frequency, channels, and a timeout. Ex:
```
(device) iioservice_simpleclient --device_id=0 --frequency=100 --timeout=1000 \
(device) --channels="accel_x accel_y accel_z timestamp"
```

- `/usr/local/sbin/iioservice_event`
- `/usr/sbin/iioservice_event`

Reads iio events with a device id and event channel indices. Ex:
```
(device) iioservice_event --device_id=0 --indices="0"
```

- `/usr/local/sbin/iioservice_query`
- `/usr/sbin/iioservice_query`

Reads device attributes on all devices. Ex:
```
(device) iioservice_query --attributes="location scale"
```
