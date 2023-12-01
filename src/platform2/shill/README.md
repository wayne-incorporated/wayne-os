# Shill
*Updated Jan 2022*

## Packages

The shill directory contains 2 primary packages:

*   `shill`
*   `shill-net`

Shill depends on shill-net which is built as a separate package. Building or
deploying `shill` will not also build or deploy `shill-net` (and vice versa).

e.g. when making changes to code in `shill/net` it is important to use
`cros_workon --board=${BOARD} start shill-net` and to build and deploy
`shill-net` (in addition to any dependent binaries, e.g. `shill` or
`patchpanel`).


There are also additional support / utility packages:

*   `shill-client`
*   `shill-dbus-client`
*   `shill-test-scripts`

## Architecture

The [Architecture document](doc/architecture.md) provides an overview of Shill's
architecture.

## Subsystem Documentation

*   [Cellular](doc/cellular.md)
*   [Routing subsystem](doc/routing.md)
*   [VPN subsystem](doc/vpn.md)

## Overview

Shill is the connection manager for Chrome OS. It is responsible for such
functionality as:

*   Setting up network interfaces to behave as desired, which involves:
    *   Acquiring link information from the kernel.
    *   Handling different logic for different network interface technologies
        like WiFi, Ethernet, or cellular.
        *   For wireless interfaces, there may be many different "connectivity
            services" that can be connected to (e.g., different 802.11 ESSs
            within range of the WiFi adapter).
    *   Potentially interacting with separate daemons, like `wpa_supplicant` for
        WiFi or 802.1X on Ethernet, or ModemManager for cellular, for
        technology-specific behavior.
    *   Acquiring suitable IP configuration parameters, which may involve using
        DHCP.
*   Persisting relevant user information, such as previously connected networks
    and associated credentials.
*   Configuring DNS appropriately on the system.
*   Properly handling multiple connected interfaces, including:
    *    Prioritizing connected interfaces in a predictable and intuitive
         manner.
    *    Routing traffic to comply with the interface prioritization and
         ensuring that traffic always goes out of the right interface(s)
         (traffic may go through multiple interfaces when virtual interfaces are
         involved).
*   Providing VPN support for:
    *    Third-party Chrome extensions that support the [third-party VPN
         interface](doc/thirdpartyvpn-api.txt)
    *    Android VPN apps (which is primarily taken care of by `patchpanel`;
         Shill's main responsibility is to ensure that traffic which doesn't
         originate in Android and should go through the VPN is sent to ARC
         rather than directly out of a physical interface).
    *    Built-in OpenVPN (a very limited subset; it is recommended that OpenVPN
         users use an Android VPN app for this) and L2TP/IPsec VPNs.
*   Detecting connectivity issues and trying to determine potential causes.
*   Collecting non-privacy-invasive metrics to allow for a better understanding
    of user network experience (e.g., which WiFi disconnect reasons are most
    common? What is the usage of WiFi vs. Ethernet vs. cellular?).

In addition, Shill provides a D-Bus service for use by D-Bus clients. One of the
largest clients is Chrome, which provides an actual UI for the underlying
network functionality provided by Shill. Chrome both drives some part of Shill
state (e.g., a user pressing a Connect button for a WiFi network, which causes
Chrome to call the Connect D-Bus method) and reads Shill state (e.g., to
display the proper network icon and provide accurate and up-to-date network
information). Policy-derived network configuration is also applied to Shill
through Chrome.

## Brief History

Shill is not the first connection manager that was used on Chrome OS. The first
consideration was to use Intel's [ConnMan] connection manager. Following issues
with upstream responsiveness, Chrome OS forked ConnMan into the [Flimflam]
connection manager. A number of remaining issues with the legacy of ConnMan,
including a GPL license and a supposedly poor separation of concerns within the
project, led to the decision to create a new connection manager and hence Shill
was born.

Initially, the intention was for Shill to be D-Bus compatible with Flimflam,
allowing for the two to be interchangeable. D-Bus API compatibility with
Flimflam is no longer of any interest. Future changes to both the architecture
and D-Bus interface of Shill should be made on the basis of suitability to our
needs and the maintainability of the project. Ultimately the legacy of ConnMan
still lives within Shill to some degree based on that initial decision to design
Shill around Flimflam's D-Bus API, and future design decisions must be evaluated
with the understanding that the goals and requirements for Shill are not what
they were in 2012.

## D-Bus Interface Specification

*   [`Manager` D-Bus Specification](doc/manager-api.txt)
*   [`Device` D-Bus Specification](doc/device-api.txt)
*   [`Service` D-Bus Specification](doc/service-api.txt)
*   [`Profile` D-Bus Specification](doc/profile-api.txt)
*   [`IPConfig` D-Bus Specification](doc/ipconfig-api.txt)

## Command Line Interface

Shill is controlled exclusively via D-Bus, and currently (see also
[b/172222930](https://issuetracker.google.com/172222930)), there is no proper
Command Line Interface for it. Instead, there are a patchwork of scripts and
utilities that can be useful in a pinch.

*   ["flimflam" test scripts](test-scripts/): these provide many small scripts
    wrapping parts of the D-Bus API; they are [inconsistently
    maintained](https://issuetracker.google.com/172228096) and may not all
    work. Written in Python, and only available on test images.
*   [`/usr/local/autotest/cros/scripts/wifi`](https://chromium.googlesource.com/chromiumos/third_party/autotest/+/HEAD/client/cros/scripts/wifi):
    useful for connecting to WiFi networks. Written in Python, and only available on test images.
*   [`connectivity`](../modem-utilities/connectivity): shell script that dumps
    Device or Service information. Available on all images.
*   [`ff_debug`](bin/ff_debug): configures "flimflam" debugging level. See also
    [TESTING docs](TESTING.md#verbose-messages). Available on all images.
*   [network_diag](../crosh/network_diag): dump general networking and
    connectivity diagnostics.

There are a variety of other connectivity-related CLI tools which are useful,
even if not directly tied to Shill:

*   [iw](https://wireless.wiki.kernel.org/en/users/documentation/iw): tool for
    interacting with WiFi devices.
*   [iproute2](https://wiki.linuxfoundation.org/networking/iproute2): link and
    routing management tools (such as `ip`, `tc`, `ss`, ...).
*   [tcpdump](https://www.tcpdump.org/): packet capturing and analysis.
*   `iptables`, `ip6tables`: packet filtering utility.
*   `ping`: generate ICMP traffic.
*   `traceroute`, `traceroute6`: tool to track the route taken by IP packets from source to destination.
*   `dig`: DNS lookup utility.

Some of these CLI utilities (or wrapper helpers) are also available in
[crosh](../crosh). See its `help_advanced` output for info.


[ConnMan]: https://git.kernel.org/pub/scm/network/connman/connman.git/
[Flimflam]: https://chromium.googlesource.com/chromiumos/platform/flimflam
