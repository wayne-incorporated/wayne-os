# dns-proxy

This directory contains the DNS proxy service that is used to support DNS
proxying for VPNs and provide DNS-over-HTTPS functionality for Chrome OS
and virtualized guest OSes.

The dns-proxy controller is responsible for managing the lifecycles of
the child proxy processes. On start, it launches the system and default
network proxies and, as needed, for ARC.

Each child process provides both standard plain-text as well as
DNS-over-HTTPS name resolution functionality and relies on Chrome's
Secure DNS settings to configure its behavior. The system proxy
relays DNS traffic for system processes. It always tracks the default
(highest priority) physical network; and will ignore any VPN running
on the host or inside ARC, if applicable. The default network proxy will
always track the highest priority network, including VPNs. Each ARC proxy
is bound to a single ARC bridge interface (excluding the control bridge),
which allows interface-aware Android applications to use DoH via the
proxy. Chrome's DNS traffic is ignored and never proxied.
