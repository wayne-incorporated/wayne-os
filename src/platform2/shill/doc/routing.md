# Routing

## Overview

The purpose of the `RoutingTable` singleton is to allow clients to examine and
modify routing tables and policy routing rules. Its primary client is the
`Connection` class, whose instances modify routes/rules in order for network
traffic to comply with configuration rules such as priority of connected
`Service`s and tunnelling of traffic through a VPN.

## Background

Routing is the means by which network packets are sent from source nodes to
destination nodes. With the IP protocol, a routing decision is made locally at
every node that a packet reaches, until the packet either reaches its
destination or expires (as determined by a packet's TTL field). Since routing
decisions are made locally, the questions to answer at each node are "should
this packet be dropped instead of sent forward?" and "if this packet should be
sent forward, which interface should it be sent out of and to what node on that
LAN?". Note that sometimes the source and destination nodes are the same, in
which case a loopback interface is used to send packets directly to the
receiving local process rather than sent out of the machine and back. While
different devices may use different methods for making these decisions, the most
common way this is done, particularly for the second question, is through the
use of **routing tables**.

A routing table is simply a set of rules matching destination address to egress
interface. Since IP addresses are organized hierarchically, broad sets of
destination addresses can be represented with a small set of addresses within a
routing table through the use of the [longest prefix match
algorithm](https://en.wikipedia.org/wiki/Longest_prefix_match) at routing
time. Entries in a routing table can also have priorities--sometimes called a
metric in utilities like `ip route`--that allow for disambiguation between
routes that match equally well. The routes in a routing table can come from a
number of sources. There exist a number of routing protocols that allow for
routers to populate their own routing tables dynamically. In the case of Chrome
OS hosts, however, routing tables are populated by the kernel itself and by
Shill.

A single routing table, however, cannot be used to represent all of the routing
decisions one could reasonably want their machine to employ. Properties of a
packet such as source destination, quality of service, or packet markings left
by a firewall are not considered by a standard routing table. While routing
tables could be modified to consider all of these cases, an alternative that
helps to contain complexity is to use **policies** (also known as **rules**) as
a means of selecting a routing table based on properties of the packet to send,
in a process known as **policy-based routing**. Policies have their own
priorities, and a packet will be compared with policies in order of priority
(lowest to highest) until a match is found. If the matched routing table does
not have a suitable routing entry or the packet matches with a *throw* entry in
the routing table, the routing process returns to the list of policies in order
to find the next matching routing table. On Linux, the list of policies
generally ends with a rule sending all packets to the main routing table.

>   As an aside, note that policy-based routing allows for sophisticated answers
>   to the first of the two questions asked in the beginning of this section:
>   "should the packet be dropped instead of sent forward?". For example, one
>   could create a routing table that only contains a *blackhole* route, which
>   simply drops the packet. Policies can then be set to send particular traffic
>   to that routing table to prevent it from being sent. For such
>   firewall-related behavior on Linux, however, tools such as iptables that
>   utilize the kernel's netfilter architecture are generally more
>   popular. Aside from network administrator familiarity with iptables, using
>   the netfilter architecture also allows for packet filtering of ingress and
>   forwarded traffic, applying filtering logic at many stages in the lifetime
>   of a packet, and taking advantages of performance improvements applied to
>   the netfilter architecture. With that said, there is no consistent netfilter
>   API between kernel versions, making it inconvenient to programmatically deal
>   with netfilter. Dynamically modifying routing tables and rules is sufficient
>   for our needs in Shill.

On the kernel side, a routing table is represented as a [`fib_table`], while a
policy routing rule is represented as a [`fib_rule`].
>   Note the use of "FIB" rather than "routing table" in kernel code. A FIB, or
>   Forwarding Information Base, refers specifically to the set of information
>   used to forward a packet (i.e. to send it to another node), which does
>   indeed correspond to our original definition of a routing table. This is in
>   contrast to a RIB, or Routing Information Base, which refers to the set of
>   information a node has about the routes around itself. The distinction,
>   while seemingly unimportant for normal end nodes, is significant for routers
>   or other nodes that use routing protocols to dynamically determine route
>   information. Each routing protocol used by the node (e.g. OSPF, BGP, RIP,
>   etc) maintains its own view of the available routes with a protocol-specific
>   data structure. The information in these data structures are then selected
>   and used to update the RIB, which then serves as the central,
>   protocol-independent representation of routes. Finally, the FIB can be
>   updated to reflect the information in the RIB. Since both RIB and FIB can be
>   called "routing table" in various contexts, the kernel's use of "FIB" helps
>   eliminate any potential ambiguity.

## Design

The `RoutingTable` class is a singleton whose two primary responsibilities are:
*   to send client requests to add or remove routes/rules to the kernel through
    the [rtnetlink interface]
*   to maintain an internal representation of routes and policy rules organized
    on a per-interface basis for use both in internal routing logic and in
    servicing client requests for information about available routes/rules

When the `RoutingTable` is `Start()`ed, it will request all of the routes and
rules on the system. After that point, it will keep track of newly-added
routes/rules by listening to the RTNL interface (for routes/rules added directly
by the kernel) and by updating the internal representation whenever a client
request successfully adds or removes a route or rule.

Each `Device` instance has at most one `Connection`. When a `Device` is
connecting, an `IPConfig` instance representing configuration information such
as local address, gateway address, DNS servers, etc will be populated and passed
to the `Connection` instance. The relevant information from that `IPConfig`,
along with `Service` priority information provided by the `Manager` class, is
then used to set up routes and rules appropriately.

[`fib_rule`]: https://elixir.bootlin.com/linux/v4.20/source/include/net/fib_rules.h#L19
[`fib_table`]: https://elixir.bootlin.com/linux/v4.20/source/include/net/ip_fib.h#L216
[rtnetlink interface]: https://elixir.bootlin.com/linux/v4.20/source/include/uapi/linux/rtnetlink.h
