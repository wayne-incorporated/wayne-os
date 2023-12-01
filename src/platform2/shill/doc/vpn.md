# VPN

## Overview

From the perspective of Shill's architecture, VPN is inherently different from
physical connections because the corresponding `Device` (in this case
representing a virtual interface) may not exist when a Connect is
requested. Therefore the standard means of a `Service` passing Connect requests
over to its corresponding `Device` does not work. Also since the `VirtualDevice`
type is not unique to a particular VPN solution (`PPPDevices`, for example, are
used for cellular dongles, and L2TP/IPsec VPNs), the VPN-specific logic cannot
be contained within the `VirtualDevice` instance.

For VPN, this is solved through the use of `VPNDrivers`. A `VPNDriver` takes
care of attaining a proper `VirtualDevice`, communicating with processes outside
of Shill which implement some part of the VPN functionality, and setting up
routes and routing rules for the corresponding `VirtualDevice`. Thus a
`VPNService` passes Connect and Disconnect requests to its corresponding
`VPNDriver`. Note that `VPNDriver` D-Bus properties are exposed through the
owning `VPNService`; `VPNDrivers` are an implementation detail that is not
exposed to D-Bus clients.

ChromeOS supports 4 types of VPN solutions:
*   Android 3rd-party VPN apps in ARC
*   Built-in L2TP/IPsec VPN
*   Built-in OpenVPN
*   Chrome Extension VPN App

Each of these types has a corresponding `VPNDriver` child which contains the
functionality needed on the Shill-side to support that VPN solution (note that
Shill's involvement varies between different types of VPNs):

![VPNDriver Inheritance](https://storage.googleapis.com/chromium-website-lob-storage/3c5afd9bada7cc8f1d3bfe735d28824aed309d5c)

When a `VPNService` is created by `VPNProvider` (whether from a `Manager`
ConfigureService D-Bus call or from a `Profile` containing an already-configured
`VPNService`), the "Provider.Type" `Service` property is used specify what type
of `VPNDriver` that `VPNService` should use. Note that "Provider.Type" is only
valid for `Services` whose "Type" property is of value "vpn". See
`VPNProvider::CreateServiceInner` for more details.

## VPN Types

### Android 3rd-party VPN in ARC

Android 3rd-party VPNs (implemented using the [Android `VpnService` API] in ARC
are the VPN type requiring the least amount of functionality within Shill, where
the majority of the `ArcVpnDriver` functionality is just setting up routing
properly. patchpanel creates an ARC bridge, which serves as a host-side (v4
NAT-ed) proxy for the arc0 interface on the Android-side. In addition,
patchpanel creates a corresponding arc_${IFNAME} interface for each interface
named ${IFNAME} exposed by the Shill `Manager` (see patchpanel
`Manager::OnShillDevicesChanged` for more detail). This allows traffic from the
Android-side to have a specific host-side interface that will carry it.

Traffic that needs to pass through the VPN gets sent to the ARC bridge rather
than out of a physical interface. VPN-tunnelled traffic will then be sent out of
Android to arc_${IFNAME} interfaces to actually send the traffic out of the
system.

Internally, Chrome's [`ArcNetHostImpl`] and the ARC [`ArcNetworkBridge`]
communicate between each other to create the appropriate behavior as specified
by the [ARC net.mojom interface]. For example, the ARC [`VpnTracker`] will
trigger `ArcNetworkBridge.androidVpnConnected` when an Android VPN
connects. This triggers `ArcNetHostImpl::AndroidVpnConnected` on the
Chrome-side, which will Connect the appropriate `VpnService` in Shill, first
configuring a new `VpnService` in Shill if needed.

### Built-in L2TP/IPsec VPN

The built-in L2TP/IPsec VPN is implemented with multiple projects, the two Chrome
OS components being the Shill `L2TPIPsecDriver` and the
[vpn-manager](../../vpn-manager) project. The vpn-manager project (in particular
the l2tpipsec_vpn binary) serves to create the L2TP/IPsec nested tunnels that
define the L2TP/IPsec VPN. l2tpipsec_vpn creates the outer IPsec tunnel using
[strongSwan](https://www.strongswan.org), while the inner L2TP tunnel is created
by [xl2tpd](https://linux.die.net/man/8/xl2tpd) (which itself uses pppd).

>   Note: There are actually two distinct L2TP standards (distinguished as
>   L2TPv2 and L2TPv3). [RFC 2661] defines L2TPv2, which is a protocol
>   specifically designed for the tunnelling of PPP traffic. [RFC 3931]
>   generalizes L2TPv2 such that the assumption of the L2 protocol being PPP is
>   removed. L2TP/IPsec is described in [RFC 3193], which--as the RFC numbers
>   might suggest--is based on L2TPv2. In particular, xl2tpd is an
>   implementation of RFC 2661, and all references to L2TP in Shill and
>   vpn-manager are specifically referencing L2TPv2.

Upon a Connect request, `L2TPIPsecDriver` spawns an l2tpipsec_vpn process,
passing the proper configuration flags and options given the configuration of
relevant Service properties. One important configuration option set is the
"--pppd_plugin" option, which is used so that `L2TPIPsecDriver` can get updates
from the pppd process created by xl2tpd, which passes messages to
`L2TPIPsecDriver::Notify`. One use of the `Notify` method is to get information
of the PPP interface created by pppd when the PPP connection is established,
which is used to create the corresponding `PPPDevice` instance. The `Notify`
method is also used to get information about a disconnection, although
`L2TPIPsecDriver::OnL2TPIPsecVPNDied` also serves that purpose but receives the
exit status from l2tpipsec_vpn rather than pppd.

### Built-in OpenVPN

The built-in OpenVPN implementation consists primarily of the open-source
[OpenVPN](https://openvpn.net) project, and of Shill's `OpenVPNDriver` and
`OpenVPNManagementServer`. Upon a Connect request, `OpenVPNDriver` creates a TUN
interface and spawns an `openvpn` process, passing a set of command-line options
including the interface name of the created TUN interface (using the OpenVPN
"dev" option). Shill interacts with the spawned `openvpn` process in two
distinct ways.

One interaction is between `openvpn` and `OpenVPNDriver::Notify`. The OpenVPN
"up" and "up-restart" options are set so that the [shill
openvpn_script](../shims/openvpn_script.cc) is called when `openvpn` first opens
the TUN interface *and* whenever `openvpn` restarts. This script leads to
`OpenVPNDriver::Notify` being invoked (through OpenVPNDriver::rpc_task_), which
will process environment variables passed by `openvpn` in order to populate an
`IPConfig::Properties` instance appropriately.

>   Note: From the OpenVPN documentation:
>   >   On restart, OpenVPN will not pass the full set of environment variables
>   >   to the script. Namely, everything related to routing and gateways will
>   >   not be passed, as nothing needs to be done anyway – all the routing
>   >   setup is already in place.

The other interaction is between `openvpn` and `OpenVPNManagementServer`.
OpenVPN provides the concept of a management server, which is an entity external
to the `openvpn` process which provides administrative control. Communication
between the `openvpn` and management server processes occurs either over TCP or
unix domain sockets. In this case, `OpenVPNManagementServer` uses a TCP socket
over 127.0.0.1 to communicate with the OpenVPN client. This allows for Shill to
control `openvpn` behavior like holds (keeping `openvpn` hibernated until the
hold is released) and restarts (triggered by sending "signal SIGUSR1" over the
socket), but also allows for `openvpn` to send information like state changes
and failure events back over to Shill (see
`OpenVPNManagementServer::OnInput`). To clarify, the communication between
`OpenVPNManagementServer` and `openvpn` is an out-of-band control channel; since
`openvpn` already has the TUN interface opened, the Shill-side is not involved
with processing data packets themselves.

### Chrome Extension VPN App

`ThirdPartyVpnDriver` exposes the [Shill ThirdPartyVpn API] through
`ThirdPartyVpnDBusAdaptor`, which [Chrome `VpnService`] instances use, such that
Chrome VPN App information can be passed between Shill and Chrome. Chrome's
`VpnService` is wrapped by `VpnThreadExtensionFunction` children to create the
[Chrome vpnProvider API] for Chrome Apps.

When the Shill `VpnService` receives a Connect call, the `ThirdPartyVpnDriver`
will create a TUN interface where packets received on the interface reach
`ThirdPartyVpnDriver::OnInput` as a vector of bytes. Within `OnInput`, IPv4
packets are sent using the OnPacketReceived D-Bus signal, which Chrome's
`VpnService` will forward to the Chrome VPN App. In the other direction, Chrome
VPN Apps use the SendPacket vpnProvider function to cause its Chrome
`VpnService` to call the SendPacket D-Bus method on the corresponding
`ThirdPartyVpnDriver` in Shill, which causes the driver to send that packet to
the TUN interface. Understandably, the performance of Chrome App VPNs is not
optimal, but the performance drawbacks of this design are embedded in the
ThirdPartyVpn and Chrome vpnProvider APIs, as opposed to being hidden
implementation details. One can contrast this with how built-in OpenVPN above
works, where the TUN interface is passed to `openvpn` so that the Shill <->
external VPN entity communication is exclusively a control channel rather than
both a control and data channel.

[Android `VpnService` API]: https://developer.android.com/reference/android/net/VpnService
[ARC net.mojom interface]: https://cs.chromium.org/chromium/src/components/arc/mojom/net.mojom
[`ArcNetHostImpl`]: https://cs.chromium.org/chromium/src/components/arc/net/arc_net_host_impl.h
[`ArcNetworkBridge`]: https://source.corp.google.com/rvc-arc/vendor/google_arc/libs/arc-net-services/src/com/android/server/arc/net/ArcNetworkBridge.java
[Chrome `VpnService`]: https://cs.chromium.org/chromium/src/extensions/browser/api/vpn_provider/vpn_service.h
[Chrome vpnProvider API]: https://developer.chrome.com/apps/vpnProvider
[RFC 2661]: https://tools.ietf.org/html/rfc2661
[RFC 3193]: https://tools.ietf.org/html/rfc3193
[RFC 3931]: https://tools.ietf.org/html/rfc3931
[Shill ThirdPartyVpn API]: thirdpartyvpn-api.txt
[`VpnTracker`]: https://cs.corp.google.com/pi-arcvm-dev/vendor/google_arc/libs/arc-services/src/com/android/server/arc/net/VpnTracker.java
