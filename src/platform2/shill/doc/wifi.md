# Shill WiFi
*Updated January 2023*

This doc describes how Shill manages WiFi, the different classes used, and how
they interact with `wpa_supplicant`, the daemon used to handle authentication,
and the kernel. It's split into the following sections:

*   [Station Mode Operation](#Station-Mode-Operation)
*   [AP Mode Operation](#AP-Mode-Operation)
*   [Interface-Mode-Agnostic Classes](#Interface_Mode_Agnostic-Classes)
*   [Connection Flow](#Connection-Flow)
*   [Disconnect Flow](#Disconnect-Flow)
*   [Connection "Maintenance" Operation](#Connection-Maintenance-Operations)
*   [Scanning](#Scanning)

## Station Mode Operation

This section documents classes used in station mode, or "normal" WiFi
connections.

### WiFi

*   [WiFi](../wifi/wifi.h) corresponds to one station mode virtual interface
    (represented as `wlan0` in most devices).
*   It implements the [Device] class and its lifetime is managed by the
    [DeviceInfo] class.
*   `WiFi` is visible as a Device D-Bus object and supports the generic [Device]
    properties and functions as well as WiFi specific ones.
*   It also implements the
    [SupplicantEventDelegateInterface](../supplicant/supplicant_event_delegate_interface.h).
*   `WiFi` contains a [SupplicantInterfaceProxyInterface](../supplicant/supplicant_interface_proxy_interface.h)
    which is used to communicate to `wpa_supplicant`'s interface struct, `struct
    wpa_supplicant`, in order to connect to and disconnect from networks, track
    the interface connection state, scan, etc.
*   Connect requests are forwarded from the [WiFiService](#WiFiService) to the
    `WiFi` class, which asynchronously asks wpa_supplicant for a connection and
    tracks the interface connection state thereafter.

### WiFiService

*   [WiFiService](../wifi/wifi_service.h) is a [Service] class instance whose
    lifetime is managed by the [WiFiProvider](#WiFiProvider) class.
*   When a `WiFiService` instance is created, it is registered with the
    [Manager] class.
*   `WiFiService` is visible as a Service D-Bus object and supports the generic
    [Service] properties and functions as well as WiFi specific ones.
*   `WiFiService` represents a "WiFi network", and is identified by its
    (security class, SSID (more commonly known as network name), mode) triplet.
    For example, two networks with the same SSID, or network name, and
    different security classes will be two unique `WiFiService`s. Note that CrOS
    only supports one network mode (infrastructure mode) at the time of writing.
*   `WiFiService` registers WiFi specific [Service] properties.
*   `WiFiService` forwards *Connect* and *Disconnect* requests to `WiFi`.
*   `WiFiService` maintains a list of endpoints that match its "connection
    triplet".

### WiFiEndpoint

*   [WiFiEndpoint](../wifi/wifi_endpoint.h) corresponds to a physical BSS (basic
    service set), or AP (access point). Its lifetime is managed by `WiFi`, which
    creates a new `WiFiEndpoint` when it discovers a new BSS in a scan and
    destroys it once it's no longer in view.
*   `WiFiEndpoint` parses the information elements present in the beacons and
    probe responses.
*   `WiFiEndpoint` contains a
    [SupplicantBSSProxyInterface](../supplicant/supplicant_bss_proxy_interface.h)
    which is used to communicate property changes to the corresponding
    `WiFiEndpoint`.

### WiFiLinkStatistics

*   [WiFiLinkStatistics](../wifi/wifi_link_statistics.h) are used to log both
    RTNL (general netlink communication with kernel) and nl80211 (wifi-specific
    netlink communication with kernel) link statistics on L3+ failures.
*   On DHCP lease acquisition or portal detection failures, `WiFiLinkStatistics`
    print out the diff of these stats to help developers diagnose whether or not
    the failure was due to a bad underlying link.
*   It is created and owned by `WiFi`.

### WiFiCQM

*   [WiFiCQM](../wifi/wifi_cqm.h) listens to CQM (Connection Quality Monitor)
    events from the kernel and reacts to these by:
    *	logging
    *	recording metrics
    *	triggering firmware dumps
*   It is created and owned by `WiFi`.

### WakeOnWiFi

*   [WakeOnWiFi](../wifi/wake_on_wifi.h) implements WoW, a feature that wakes
    the device up based on certain predefined wake triggers.
*   This is created by [DeviceInfo] and owned by `WiFi`.
*   Currently not supported. To be filled in when WoW is re-enabled.

### PasspointCredentials

*   [PasspointCredentials](../wifi/passpoint_credentials.h) store credentials to
    be used to authenticate to passpoint networks.
*   `PasspointCredentials` are added by [Manager] D-Bus calls and stored by the
    [WiFiProvider](#WiFiProvider).
*   They are passed to `wpa_supplicant` through [WiFi](#WiFi) and used to match
    networks when *InterworkingSelect* is called.

## AP Mode Operation

This section documents classes used in AP mode, or as a WiFi "hotspot".

### LocalDevice and HotspotDevice

*   [LocalDevice](../wifi/local_device.h) is the base class for
    [HotspotDevice](../wifi/hotspot_device.h). They represent a network
    interface used to share connectivity (e.g. a WiFi hotspot).
*   A `HotspotDevice` is created and owned by
    [TetheringManager](../tethering_manager.h).
*   Similarly to [WiFi](#WiFi), it implements
    [SupplicantEventDelegateInterface](../supplicant/supplicant_event_delegate_interface.h)
    and owns a
    [SupplicantInterfaceProxyInterface](../supplicant/supplicant_interface_proxy_interface.h)
    which it uses to communicate with and configure the network interface.

### LocalService and HotspotService

*   [LocalService](../wifi/local_service.h) is the base class for
    [HotspotService](../wifi/hotspot_service.h). They represent a downstream
    network created on its corresponding [LocalDevice or
    HotspotDevice](#LocalDevice-and-HotspotDevice) to share connectivity.
*   A `HotspotService` is created and owned by a `HotspotDevice`.
*   They are responsible for providing the configuration parameters for the
    `wpa_supplicant`, if necessary, and configuring the downstream L3 network.

## Interface-Mode-Agnostic Classes

This section documents classes that are used in all WiFi-related operations.

### WiFiPhy

*   [WiFiPhy](../wifi/wifi_phy.h) corresponds to a WiPhy, which is a single
    physical wireless device.
*   It owns different WiPhy properties, such as device capabilities, interface
    combinations, supported frequencies, etc.
*   They are created and owned by [WiFiProvider](#WiFiProvider) when shill is
    notified via netlink about a phy.
*   There can be multiple virtual interfaces on a single phy, represented by
    either a [WiFi](#WiFi) object for station mode operation or
    [LocalDevice](#LocalDevice-and-HotspotDevice) for AP mode operation.
*   There can be multiple WiPhys on a single wireless card. `iw list` will list
    all the available phys on the system. Most ChromeOS devices have only one
    phy.

### WiFiProvider

*   [WiFiProvider](../wifi/wifi_provider.h) is a singleton that both implements
    the [ProviderInterface class](../provider_interface.h), and also handles
    more general WiFi operations, such as maintaining the interface to phy
    mappings, creating AP mode interfaces, matching passpoint credentials,
    maintaining `Endpoint` to `Service mappings`, etc.
*   Like other technology providers, its lifetime is managed by [Manager].
*   Since the `WiFiProvider` needs to be responsible for much more than other
    technologies (which mostly just handle `Service` creation and matching),
    this may eventually break out into a separate type.

## Connection Flow

Connect requests are forwarded from [WiFiService](#WiFiService) to
[WiFi](#WiFi).

1.   [WiFi](#WiFi) fetches `wpa_supplicant` network configuration parameters,
     which are stored in [WiFiService](#WiFiService), uses them to create a
     `wpa_supplicant` network block, and asks `wpa_supplicant` to connect.
2.   At this point, `pending_service_` is set to indicate that the user has
     asked for a connection, but that `wpa_supplicant` has not yet associated.
3.   Shill monitors the *CurrentBSS* `wpa_supplicant` interface property to
     determine when to set `current_service_` to `pending_service_`.
     `wpa_supplicant` will update this property after it has completed L2
     association if there's no existing connection, and before it has completed
     L2 association if there is an existing connection.
4.   Shill also monitors the *State* interface property to track the 802.11
     authentication, association, and handshake states. When the interface has
     reached the *Completed* state, `WiFi` transitions the `Service` state to
     *kStateConfiguring* and starts L3 configuration using the
     [Network](../network.h) class.

## Disconnect Flow

A disconnect can either be user-initiated or non-user-initiated.

### User-Initiated Disconnect

Disconnect requests are similarly forwarded from [WiFiService](#WiFiService) to
[WiFi](#WiFi).

1.   [WiFi](#WiFi) resets all connection state.
2.   It then asks `wpa_supplicant` to disconnect.

### Non-User-Initiated Disconnect

This can happen as a result of bad link, walking away from an AP, AP-side
issues, etc.

1.   `wpa_supplicant` notices that the device is no longer connected. This can
     happen primarily in one of three ways:
     *   shill gets a *DisconnectReason* property change event, along with a
	 *CurrentBSS* property change to a `null` BSS.
     *   shill notices that the interface is down and get notified from the
         kernel via RTNL before wpa_supplicant tells us (suspend/resume race
	 case, as well as others).
     *   the current BSS the device is associating/associated to no longer
         appears in scan results.
2.   In the first situation above, shill calls `WiFi::HandleDisconnect`. This
     may or may not be expected, and shill records it as such in our telemetry
     depending on what state it was in prior to getting the disconnect event.
3.   In the second and third situation above, shill calls
     `WiFi::DisconnectFrom`, to actively send the *Disconnect* command to
     `wpa_supplicant`. Note that this call usually results in a benign error
     because `wpa_supplicant` will inevitably also notice that the link is down,
     but have raced with other means of communicating link failure.

## Connection "Maintenance" Operations

This refers to rekeying and roaming, which both happen beneath the shill layer,
but surface *State* property changes that shill sees.

### Rekeying

*   This operation happens on a regular basis depending on the AP configuration
    and is used to periodically refresh the PTK (pairwise transient key) or GTK
    (group temporal key) for security purposes.
*   This causes the *State* interface property to transition from *Completed*
    back to *4way_handshake* or *group_handshake*.
*   There's no reason to expect that the handshake would fail given that it
    already completed successfully the first time, so this should also be kept
    opaque to the user. [WiFi](#WiFi) will note "backwards" state transitions
    and set a flag `is_rekey_in_progress_` to indicate that it is rekeying and
    that the `Service` state should not be changed then (or after the rekeying
    has finished).

### Roaming

*   This happens when `wpa_supplicant` detects that another AP is strong enough
    to warrant another association.
*   Similar to [Rekeying](#Rekeying), this causes a backwards state transition
    that should not be surfaced to the user.
*   A similar flag, `is_roaming_in_progress_` is set to indicate that the device
    is roaming.
*   After a roam completes, it's possible that the device may end up on a
    different subnet, so [WiFi](#WiFi) renews the DHCP lease through the
    [Network class]('../network.h) to refresh L3 without tearing down the
    connection.

## Scanning

*   Scanning is the process of AP discovery. This is primarily handled by
    `wpa_supplicant`, but shill plays a few important roles in scanning:
    *   It configures `wpa_supplicant`'s background scan with parameters such
        as:
        1.   the RSSI (signal strength) scan threshold: the threshold below
	     which the scan interval will increase in search of a better AP,
        2.   the short scan interval: the scan interval used when the device
	     sees the AP at an RSSI below the scan threshold,
        3.   and the long scan interval: the scan interfval used when the
	     device sees the AP at an RSSI above the scan threshold.
    *   It explicitly asks `wpa_supplicant` for scans periodically.
    *   It explicitly asks `wpa_supplicant` for scans when *RequestScan* or
        *ScanAndConnectToBestServices* [Manager] D-Bus functions are called.
*   When `wpa_supplicant` finishes a scan, it reports its scan results to Shill
    through *BSSAdded* and *BSSRemoved* D-Bus signals.
*   Shill constructs [WiFiEndpoint](#WiFiEndpoint) objects and matches them to
    [WiFiService](#WiFiService) objects, creating new ones if applicable.
*   Since [Service]s are exposed via D-Bus, these will be picked up by Chrome
    and visible to the user in the WiFi settings menu.

[Manager]: architecture.md#Manager
[DeviceInfo]: architecture.md#DeviceInfo
[Device]: architecture.md#Device
[Service]: architecture.md#Service
