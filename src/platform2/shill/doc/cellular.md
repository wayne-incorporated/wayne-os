# Shill Cellular
*Updated June 2021*

## ModemInfo

*   The [ModemInfo class](../cellular/modem_info.h) is a singleton owned by
    [Manager]. It creates a [DBusObjectManagerProxy] for
    [org.freedesktop.ModemManager1] to observe the appearance of
    [org.freedesktop.ModemManager1.Modem] objects.
*   When a `ModemManager1.Modem` object appears, a [Modem](#Modem) class
    instance is constructed.


## Modem

*   [Modem class](../cellular/modem.h) instances are owned by
    [ModemInfo](#ModemInfo). There is usually only one `Modem` instance.
*   The `Modem` class is a helper class for parsing `ModemManager1.Modem`
    `CurrentCapabilities` and `Ports` properties.
*   When a Modem appears, a [Cellular](#Cellular) class instance is requested
    from the [DeviceInfo](architecture.md#Device-Info) singleton.
    *   If no `Cellular` Device exists, a new instance is created.
    *   The `Cellular` Device is updated with the new `Modem` properties.
    *   *Note:* The `Cellular` instance may outlive the `Modem` instance
         and is only destroyed when Cellular is disabled or on Shutdown.
         This ensures a consistent user experience during a SIM swap or slot
         switch operation (which creates a new `ModemManager`.Modem` object).


## Cellular

*   The [Cellular class](../cellular/cellular.h) is a `base::RefCounted`
    [Device] class instance.  Its lifetime is managed by the [DeviceInfo] class.
*   When a `Cellular` instance is created, it is registered with the [Manager]
    class which handles startup, shutdown, policy, power events, and global
    properties.
*   `Cellular` maintains a state machine tracking the state of the
    `ModemManager1.Modem` object.
*   Communication with the `ModemManager1.Modem` object is done through the
    [CellularCapability](#CellularCapability) helper class, owned by `Cellular`.
*   Once Modem registration completes and SIM properties are received (see
    [CellularCapability](#CellularCapability)), a
    [CellularService](#CellularService) instance is created for each available
    SIM through the [CellularServiceProvider](#CellularServiceProvider) helper
    class.
*   Connect requests are forwarded from the [CellularService](#CellularService)
    class to the [CellularCapability](#CellularCapability) class. See
    [Connect state machine](#Connect-State-Machine) for details.


## CellularCapability

*   The [CellularCapability3gpp](../cellular/cellular_capability_3gpp.h)is owned
    by the [Cellular](#Cellular) class.
*   `CellularCapability3gpp` owns a number of proxies for communicating with
    `ModemManager1` interfaces (`3gpp`, `Signal`, `Simple`, `Location`) and the
    `ModemManager1.Modem` object.
*   When Cellular is enabled, `CellularCapability3gpp::Start` is called,
    invoking the `ModemManager1.Modem.Enable` routine. On success this sets
    `Cellular::State` to *Enabled* and starts the Modem registration process.
*   Once enabled, `ModemManager` provides a list of paths for available SIMs
    (on devices that support multi-sim), and the path of the currently active
    SIM. All available SIM properties are requested and provided to
    [Cellular](#Cellular) as a vector of `SimProperties`.
*   Once the Modem registration process successfully completes,
    `Cellular::State` becomes *Registered*, allowing the connect requests to be
    handled. (See [Connect state machine](#Connect-State-Machine) for details).


## CellularServiceProvider

*   The [CellularServiceProvider class](../cellular/cellular_service_provider.h)
    is a [ServiceProvider] singleton owned by [Manager].
*   `CellularServiceProvider` determines which
    [CellularService](#CellularService) instances to load based on the available
    `SimProperties`.
*   `Cellular` Service properties are always stored in the **Device** [Profile].
*   The [Cellular](#Cellular) class provides a vector of `SimProperties`, one
    entry for each active SIM slot, when they become available. At this point
    `CellularServiceProvider` ensures that correct service instances are
    loaded as follows:
    1.  Matching services in the Device [Profile] are identified for each
        `SimProperties` entry:
        1.  If a `CellularService` instance matching the SIM *ICCID* exists, it
            is updated with the current `Cellular Device` state.
        2.  Otherwise if a Service matching the ICCID exists in the `Profile`,
            it is loaded and a new `CellularService` instance is created.
        3.  If the entry has an EID, all other Service entries with a matching
            *EID* in the `Profile` are loaded and `CellularService` instances
            are created if necessary.
    2.  If any `CellularService` entries remain that do not match any
        `SimProperties` entries, they are destroyed.


## CellularService

*   The [CellularService class](../cellular/cellular_service.h) is a
    `base::RefCounted` [Service] class instance.  Its lifetime is managed by
    the [CellularServiceProvider](#CellularServiceProvider) class.
*   When a `CellularService` instance is created, it is registered with the
    [Manager] class.
*   `CellularService` uses the *Cellular.ICCID* property to uniquely identify
    service instances.
*   `CellularService` registers Cellular specific [Service] properties.
*   `CellularService` forwards *Connect* and *Disconnect* requests to the
    [Cellular](#Cellular) class.


## Connect State Machine

Connect requests come from a [CellularService](#CellularService) with an
identifying *ICCID*.

1.  If the Modem object is not available, an immediate Error is returned.
2.  If the Modem is *Enabling* or *Registering* the *Pending ICCID* is set.
    *   If the Modem becomes *Registered*, the Connect will be re-attempted.
    *   If the Modem fails to register, the Connect request
        [Fails](#Connect-Failure).
3.  If the Modem is not in a *Registered* state, an immediate Error is returned.
4.  If the ICCID of the Connect request does not match the ICCID of the
    active SIM in the active slot:
    *   If the ICCID matches the active SIM in a different slot, the
        *Pending ICCID* is set and a slot change is initiated.
        *   If the slot change succeeds and the Modem becomes *Registered*,
            a Connect is initiated for the *Pending ICCID*.
        *   If the slot switch fails, the connect attempt
            [Fails](#Connect-Failure).
    *   If the ICCID does not match any slot, an immediate Error is returned.
5.  When the Modem is *Registered* and the *ICCID* matches,
    `CellularCapability3gpp::Connect` is called which sets [Roaming](#Roaming)
    properties and builds and a list of [APN](#APN) properties to try.
6.  The [CellularCapability](#CellularCapability) then calls
    `ModemManager1.ModemSimple.Connect` with the first APN in the try list.
    *   If the Connect fails, `ModemManager1.ModemSimple.Connect` is called
        with subsequent APN entries in the try list.
    *   If all APN entries fail, `ModemManager1.ModemSimple.Connect` is
        called once with an empty APN.
7.  If all Connect attempts fail, the Connect request [Fails](#Connect-Failure),
    otherwise the Connect request [Succeeds](#Connect-Success).


### Connect Success

When a Connect request succeeds:

*   The [ConnectState] property of the associated
    [CellularService](#CellularService) is set to
    `Service::ConnectState::kStateConnected`.
*   Connectivity tests will be initiated.
    *   If they succeed, the [ConnectState] will be set to `kStateOnline`.
    *   Otherwise the [ConnectState] will be set to a `Portal` state.
*   **TODO(stevenjb):** Document connectivity tests / portal detection.


### Connect Failure

When a Connect request fails:

*   The [ConnectState] property of the associated
    [CellularService](#CellularService) is set to
    `Service::ConnectState::kStateFailure`.
*   The *Error* property of the associated [CellularService](#CellularService)
    is set to a `Service::ConnectFailure` string.
*   Any *Pending ICCID* is cleared.


### Entitlement Check
[cellular_carrier_entitlement.md](cellular_carrier_entitlement.md)

### Connection State Details

*   **TODO(stevenjb):** Provide details for Cellular state variables.


## Roaming

*   **TODO(pholla):** Document Cellular Roaming


## APN

*   **TODO(andrewlassalle):** Document Cellular APN

[Manager]: architecture.md#Manager
[DeviceInfo]: architecture.md#DeviceInfo
[Device]: architecture.md#Device
[ServiceProvider]: architecture.md#ServiceProvider
[Service]: architecture.md#Service
[Profile]: architecture.md#Profile
[DBusObjectManagerProxy]: ../../modemfwd/dbus_bindings/org.freedesktop.DBus.ObjectManager.xml
[org.freedesktop.ModemManager1]: ../../../third_party/modemmanager-next/introspection/org.freedesktop.ModemManager1.xml
[org.freedesktop.ModemManager1.Modem]: ../../../third_party/modemmanager-next/introspection/org.freedesktop.ModemManager1.Modem.xml
[ConnectState]: ../service.h#152
