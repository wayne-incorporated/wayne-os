# wilco_dtc_supportd daemon

Please see ../README.md for general information.

## IPC mechanisms

This daemon uses three IPC mechanisms:

* gRPC - for talking to the `wilco_dtc` daemon.
* Mojo - for talking to the browser.
* D-Bus - for receiving Mojo bootstrap requests from the browser.

## Class structure

    `Daemon`
     ^
     |
     v
    `Core`
     ^
     |
     |   // gRPC-related members:
     +-> `GrpcService`
     |       (handles incoming gRPC requests)
     +-> `AsyncGrpcServer<grpc_api::WilcoDtcSupportd>`
     |       (connects `GrpcService` with the actual gRPC
     |        pipe)
     +-> `AsyncGrpcClient<grpc_api::WilcoDtc>`
     |       (sends outgoing gRPC requests through the actual gRPC pipe)
     |
     |   // Mojo-related members:
     +-> `MojoService`
     |       (handles incoming Mojo requests and sends outgoing ones)
     +-> `mojo::Binding<mojom::WilcoDtcSupportdService>`
     |       (connects `MojoService` with the actual Mojo pipe)
     +-> `RoutineService`
     |       (handles diagnostics routines requests to cros_healthd)
     +-> `ProbeService`
     |       (handles probe requests to cros_healthd)
     |
     |   // D-Bus-related members:
     +-> `DBusService`
     |       (handles incoming D-Bus requests)
     +-> `brillo::dbus_utils::DBusObject`
             (connects `DBusService` with the actual D-Bus pipe)

Classes are generally organized such that they don't know about their owners or
siblings in this graph. Instead, these classes are parameterized with
delegate(s), which implement these cross-class calls.
This allows to test each individual piece of logic separately.
