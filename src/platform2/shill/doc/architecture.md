# Shill Architecture
*Updated June 2021*

## Shill

*   [shill.conf.in](../init/shill.conf.in) sets up the shill upstart environment
*   [shill-pre-start.sh](../init/shill-pre-start.sh) ensures that
    directories required by shill are set up correctly.
*   [shill.sh](../init/shill.sh) converts environment variables to command
    line arguments and runs the shill binary.
*   [`shill_main.cc`](../shill_main.cc) parses command line options and creates
    and runs a [ShillDaemon class](../shill_daemon.h) instance which wraps a
    singleton [DaemonTask](#DaemonTask) instance.


## DaemonTask

The [DaemonTask class](../daemon_task.h) is a singleton owned by the
[ShillDaemon class](../shill_daemon.h) singleton.

It creates the following singleton classes (along with a few support/utility
classes).

*   [Manager](#Manager) This is the primary / top-level shill class.
    `DaemonTask::Start` calls `Manager::Start`.
*   [RTNLHandler class](../net/rtnl_handler.h) Available globally using
    RTNLHandler::GetInstance(). See also [RTNL](#RTNL).
*   [RoutingTable class](../routing_table.h) Available globally using
    RoutingTable::GetInstance(). See also [routing](routing.md).
*   [NetlinkManager class](../net/netlink_manager.h) Available globally using
    NetlinkManager::GetInstance().
*   [DHCPProvider class](../network/dhcp_provider.h) Available globally using
    DHCPProvider::GetInstance().


## Manager

The [Manager class](../manager.h) is the "top-level" singleton class in Shill,
created and owned by [DaemonTask](#DaemonTask).

*   `Manager` is associated with the [org.chromium.flimflam.Manager] DBus API
    documented in [manager-api.txt](manager-api.txt).
*   `Manager` includes a number of global properties, some of which are
    included in the DBus API, and some of which come from command-line switches.
*   `Manager` owns a [DeviceInfo](#DeviceInfo) singleton which tracks
    network instances and creates corresponding [Device](#Device) instances.
    *   `Manager` also owns a [ModemInfo](cellular.md#ModemInfo) singleton for
        observing `ModemManager1.Modem` DBus objects.
    *   `Manager` keeps its own list of `Device` instances and handles
        Registration, [power management](#Power-Management), and
        enabling/disabling network technologies (e.g. WiFi, Cellular).
    *   The paths of available `Device` objects are available in the
        `Manager.Devices` DBus property.
*   `Manager` owns [ServiceProvider](#ServiceProvider) instances for managing
    the creation and lifetime of [Service](#Service) instances.
    *   `Manager` also keeps its own list of `Service` instances and handles
        Registration, [power management](#Power-Management), and
        [AutoConnect](#AutoConnect).
    *   The paths of visible `Service` objects are available in the
        `Manager.Services` DBus property, sorted by *State* and priority
        as described in [manager-api.txt](manager-api.txt).
    *   The paths of all `Service` objects, including saved (favorite) service
        configurations that are not visible, are available in the
        `Manager.ServiceCompleteList` DBus property, sorted as per *Services*.
*   `Manager` maintains the stack of [Profile](#Profile) instances.


## DeviceInfo

The [DeviceInfo class](../device_info.h) is a singleton owned by
[Manager](#Manager).

*   `DeviceInfo` listens to network interface and address-configuration events
    using [RTNL](#RTNL).
*   On startup, `DeviceInfo` requests a dump of existing network interface and
    address-configuration information in order to be in sync with the current
    kernel state.
*   When `DeviceInfo` has enough information about a network interface
    for a technology backed by a [Device](#Device), it creates an instance of
    the proper type. See `CreateDevice` in [device_info.cc](../device_info.cc).
    *    Some network interfaces are explicitly ignored by shill and managed by
         other entities: `TAP` devices and virtual ethernet interfaces are
         managed by patchpanel, some `TUN` devices may be created and managed by
         third-party VPN clients directly.
*   `DeviceInfo` also updates existing [Device](#Device) instances with new
    information that it receives about the corresponding network interface.
*   `DeviceInfo` is used by some VPN drivers for creating the virtual interface
    (`TUN` device, `WG` device) used by third party VPN clients.

## Device

The [Device class](../device.h) is a `base::RefCounted` class representing a
network interface.

*   `Device` is associated with the [org.chromium.flimflam.Device] DBus API
    documented in [device-api.txt](device-api.txt).
*   `Device` provides basic functionality to configure its interface through
    `/proc/sys/net` parameters, to acquire and use
    [IP configuration](#IP-Configuration) parameters, and to drive
    [Service](#Service) connection state.
*   `Device` sets up a [Connection](#Connection) and shares it with the
    associated active [Service](#Service).
*   `Device` is the base class for a hierarchy of subclasses that perform
    technology-specific behavior:
    *   [Cellular](cellular.md#Cellular)
    *   [Ethernet class](../ethernet/ethernet.h)
    *   [VirtualDevice class](../virtual_device.h)
        *   See also [vpn.md](vpn.md)
    *   [WiFi class](../wifi/wifi.h)

![Device Inheritance](https://storage.googleapis.com/chromium-website-lob-storage/16d9864a22c27acc9058dab23d8afa7c1ef711d6)

*   `Device` instances are managed by [DeviceInfo](#DeviceInfo).
    *   Exception: `VirtualDevice` instances corresponding to virtual interfaces
        (for use-cases like VPN, and cellular dongles).


## ServiceProvider

The [ProviderInterface class](../provider_interface.h) is a common interface for
singleton instances owned by [Manager](#Manager).

*   Each `ServiceProvider` is responsible for creating [Service](#Service)
    instances on startup and as required by the associated [Device](#Device).
*   A separate `ServiceProvider` singleton exists for each primary Technology:
    *   [CellularServiceProvider](cellular.md#CellularServiceProvider)
    *   [EthernetEapProvider class](../ethernet/ethernet_eap_provider.h)
    *   [EthernetProvider class](../ethernet/ethernet_provider.h)
    *   [VpnProvider class](../vpn/vpn_provider.h)
    *   [WiFiProvider class](../wifi/wifi_provider.h)
[![Provider Inheritance](https://storage.googleapis.com/chromium-website-lob-storage/1ca5af01448a1f4580b5dacb22bed8d7cffa0f16)][ProviderInheritance]
*   `ServiceProvider` instances create new `Services` from the persisted state
    in the [Profile](#Profile) and/or properties from the D-Bus interface.
    *   See [CellularServiceProvider](cellular.md#CellularServiceProvider)
        for [CellularService](cellular.md#CellularService) provisioning.
    *   The `EthernetProvider` by default has a single `EthernetService`, which
        the first `Ethernet` instance will use. Additional `Ethernet` instances
        will cause the `EthernetProvider` to create additional `EthernetService`
        instances.
    *   For `WiFiProvider`, `Services` are also created based on network scans
        performed by `wpa_supplicant`, which leads to the reception of BSSAdded
        D-Bus signals that trigger `WiFiProvider` to create a corresponding
        `WiFiService`.

## Service

The [Service class](../service.h) is a `base::RefCounted` class representing a
network configuration and a connection through an associated
[Device](#Device).

*   `Service` is associated with the [org.chromium.flimflam.Service] DBus API
    documented in [service-api.txt](service-api.txt).
*   A network interface on its own does not provide network connectivity, the
    interface must be configured and the link layer connection must be
    established by the relevant technology specific software (`WPA` for `WiFi`
    interfaces, `ModemManager` for `Cellular`, `kernel` for `Ethernet`).
*   A `Service` provides configuration properties to the associated
    [Device](#Device) and helps setup the [Connection](#Connection) and drive
    the connection state machine.
*   `Service` is the base class for a hierarchy of subclasses that perform
    technology-specific behavior:
    *   [CellularService](cellular.md#CellularService)
    *   [EthernetService class](../ethernet/ethernet_service.h)
    *   [EthernetEapService class](../ethernet/ethernet_eap_service.h)
    *   [VPNService class](../vpn/vpn_service.h)
        *   See also [vpn.md](vpn.md)
    *   [WiFiService class](../wifi/wifi_service.h)

![Service Inheritance](https://storage.googleapis.com/chromium-website-lob-storage/44c323a47d23b956035c9dd714bb2a1d494a2dd5)

*   A `Service` has an associated `Device` instance, stored as a type specific
    `RefPtr` in the subclass.
*   `Service` lifetime is managed by the associated
    [ServiceProvider](#ServiceProvider) singleton.


## Profile

The [Profile class](../profile.h) represents a set of persisted data and is
used for both `Device` and `Service` properties, as well as a handful of global
properties. Shill keeps a `Profile` instance for shared/default properties,
and a per-user Profile when a user is logged in.

*   [Device](#Device) and [Service](#Service) classes and their subclasses
    handle loading from and saving to the underlying storage used by the current
    `Profile`.
*   Shill allows for a stack of `Profile` instances. The `Profile` stack is
    owned by [Manager](#Manager).
    *   On startup, the `Profile` stack contains a single `DefaultProfile`,
        which provides pre-login (shared) configuration data.
        *   In addition to the regular `Profile` behavior of persisting
            `Service` properties, a `DefaultProfile` will also persist `Device`
            properties and a subset of `Manager` properties.
    *   On user login, specifically when Chrome instructs session_manager to
        emit the load-shill-profile upstart event, the
        [`shill_login_user`](../bin/shill_login_user) script is run.
        *   This creates a `Profile` for the user  and pushes that `Profile`
            onto the `Profile` stack.
    *   On user logout, [`shill_logout_user`](../bin/shill_logout_user) removes
        the user's `Profile` from the `Profile` stack.
    *   When a guest user logs in, a `Profile` is created and pushed onto the
        stack as usual, but the persisted data is deleted on logout.
        *   An `EphemeralProfile` (see below), is *not* used for guest users.
            This allows persistence of properties after a shill crash within
            a guest user session.
*   Every `Service` has exactly one `Profile` associated with it, which is
    the`Profile` most recently pushed onto the `Profile` stack. The `Profile`
    contains persisted data for the `Service`.
*   An `EphemeralProfile` is used exclusively for `Service` instances that are
    created but that have no `Profile` in the `Profile` stack, e.g., a
    `WiFiService` that was created from a WiFi scan but that the user has never
    attempted to configure or connect to.

![Profile Inheritance](https://storage.googleapis.com/chromium-website-lob-storage/5dba6837e02797273e55a0311bcf9ea99f1a1a53){inl}

*   A `Service` can be "linked" to a different `Profile` through the use of the
    `Service` kProfileProperty D-Bus property, which is how `Service` instances
    currently using the `EphemeralProfile` can be moved over to a `Profile` that
    allows its configuration parameters to be persisted.
*   *Note* Shill's D-Bus clients (aside from Autotest/Tast) do not create
    additional `Profiles`, so the `Profile` stack in non-test cases contains
    only the `DefaultProfile` and potentially a user `Profile`. The
    `EphemeralProfile` is not part of the `Profile` stack.


## IP Configuration

*TODO:* Document the [IPConfig class](../ipconfig.h) and IP configuration.


## Connection

*   The [Connection class](../connection.h) is owned by the
    [Device](#Device) that sets it up and is shared by the active
    [Service](#Service) for the `Device`.
*   [Manager](#Manager) uses the `Connection` of the default [Service](#Service) to
    configure /etc/resolv.conf (DNS).
*   *TODO:* Properly document the [Connection class](../connection.h).


## AutoConnect

*TODO*


## Power Management

*TODO*


## DBus

*   DBus permissions are configured in
    [org.chromium.flimflam.conf](../shims/org.chromium.flimflam.conf)
*   Shill implements the following DBus APIs:
    *   [org.chromium.flimflam.Device]
    *   [org.chromium.flimflam.Manager]
    *   [org.chromium.flimflam.Service]
    *   [org.chromium.flimflam.IPConfig]
    *   [org.chromium.flimflam.Profile]
    *   [org.chromium.flimflam.ThirdPartyVpn]


# Glossary

## RTNL

**RTNL** is short for [rtnetlink].

*   [Netlink] is a protocol that can be used for kernel <-> user-space and
    user-space <-> user-space communication.
    *   See also [rtnetlink.h].
*   *TODO:* Document the [RTNLHandler class](../net/rtnl_handler.h) and the
    [RTNLListener class](../net/rtnl_listener.h).

[ProviderInheritance]: https://docs.google.com/drawings/d/13bSfym4MoC3qxQS1c7aiJktyJkzs8qmF6-ulh57mbuE
[org.chromium.flimflam.Device]: ../dbus_bindings/org.chromium.flimflam.Device.dbus-xml
[org.chromium.flimflam.Manager]: ../dbus_bindings/org.chromium.flimflam.Manager.dbus-xml
[org.chromium.flimflam.Service]: ../dbus_bindings/org.chromium.flimflam.Service.dbus-xml
[org.chromium.flimflam.IPConfig]: ../dbus_bindings/org.chromium.flimflam.IPConfig.dbus-xml
[org.chromium.flimflam.Profile]: ../dbus_bindings/org.chromium.flimflam.Profile.dbus-xml
[org.chromium.flimflam.ThirdPartyVpn]: ../dbus_bindings/org.chromium.flimflam.ThirdPartyVpn.dbus-xml
[rtnetlink]: http://man7.org/linux/man-pages/man7/rtnetlink.7.html
[Netlink]: http://man7.org/linux/man-pages/man7/netlink.7.html
[rtnetlink.h]: https://elixir.bootlin.com/linux/v5.0/source/include/uapi/linux/rtnetlink.h
