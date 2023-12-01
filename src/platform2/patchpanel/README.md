# Patchpanel

This directory contains the Patchpanel platform networking service daemon
(formerly arc-networkd).

Patchpanel is the network control plane manager for all guest application
platforms running inside virtual machines (ARCVM, Termina VM, Parallels VM) or
containers (ARC++). Patchpanel configures and controls the network datapath for
these guest platforms and provides additional services and features:
*   Creation and configuration of virtual ethernet interface pairs for ARC++.
*   Creation and configuration of TAP devices for CrosVM (ARCVM, Termina VM,
    and Parallels VM).
*   Configuration of source NAT and IP forwarding for all guest platforms, and
    configuration of inbound firewall destination NAT rules for ARC.
*   IPv6 NDProxy forwarder implementing [RFC 4389] and proxying ICMPv6 traffic
    between physical networks and guest platforms.
*   mDNS forwarder proxying mDNS traffic between physical networks and guest
    platforms in both directions, with additional facilities for transparent
    traversal over IPv4 SNAT.
*   SSDP forwarder proxying SSDP traffic between physical networks and guest
    platforms.
*   ADB-over-TCP proxy relaying ADB inbound connections and Crostini
    ADB-sideloading connections to ARC.
*   Broadcast forwarder proxying broadcast packets between physical networks and
    ARC.

Patchpanel's IPv6 NDProxy and mDNS/SSDP forwarders also run as standalone
binaries inside Termina for providing these features to user lxd containers.

In addition Patchpanel implements other general networking services and
features not associated with virtualization:
*   A ConnectNamespace D-Bus API for creating a virtual datapath and configuring
    routing for a network namespace. This API is currently used by:
    *    The [authenticated web proxy relay](../system-proxy) that transparently
         supports web proxy authentication for proxy aware web clients on the
         host platform or in guest application platforms.
    *    The [DNS proxy service](../dns-proxy) that manages DNS functionality
         including providing Chrome OS with DNS-over-HTTPS.
    *    Various Tast test packages including those for VPN and [system-proxy](../system-proxy).
*   A ModifyPortRule D-Bus API for opening destination ports in the inbound
    firewall rules and for forwarding destination ports to guest application
    platforms.
*   Traffic counters for measuring network usage for a variety of sources
    (Chrome, system, guest application platforms, ...). Counters are polled
    by [shill](../shill) with the GetTrafficCounters D-Bus API for implementing
    Service network usage metering.

[RFC 4389]: https://tools.ietf.org/html/rfc4389
