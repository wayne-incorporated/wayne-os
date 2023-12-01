// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/ndproxy.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <linux/in6.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <fstream>
#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>

#include "patchpanel/ipc.h"
#include "patchpanel/minijailed_process_runner.h"
#include "patchpanel/net_util.h"

namespace patchpanel {
namespace {
// Currently when we are unable to resolve the destination MAC for a proxied
// packet (note this can only happen for unicast NA and NS), we send the packet
// using all-nodes multicast MAC. Change this flag to true to drop those packets
// on uplinks instead.
// TODO(b/244271776): Investigate if it is safe to drop such packets, or if
// there is a legitimate case that these packets are actually required.
constexpr bool kDropUnresolvableUnicastToUpstream = false;

const unsigned char kZeroMacAddress[] = {0, 0, 0, 0, 0, 0};
const unsigned char kAllNodesMulticastMacAddress[] = {0x33, 0x33, 0,
                                                      0,    0,    0x01};
const unsigned char kAllRoutersMulticastMacAddress[] = {0x33, 0x33, 0,
                                                        0,    0,    0x02};
const unsigned char kSolicitedNodeMulticastMacAddressPrefix[] = {
    0x33, 0x33, 0xff, 0, 0, 0};
constexpr net_base::IPv6Address kAllNodesMulticastAddress(
    0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01);
constexpr net_base::IPv6Address kAllRoutersMulticastAddress(
    0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02);
constexpr int kSolicitedGroupSuffixLength = 3;
const net_base::IPv6CIDR kSolicitedNodeMulticastCIDR =
    *net_base::IPv6CIDR::CreateFromCIDRString("ff02::1:ff00:0/104");

// These filter instructions assume that the input is an IPv6 packet and check
// that the packet is an ICMPv6 packet of whose ICMPv6 type is one of: neighbor
// solicitation, neighbor advertisement, router solicitation, or router
// advertisement.
sock_filter kNDPacketBpfInstructions[] = {
    // Load IPv6 next header.
    BPF_STMT(BPF_LD | BPF_B | BPF_IND, offsetof(ip6_hdr, ip6_nxt)),
    // Check if equals ICMPv6, if not, then goto return 0.
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_ICMPV6, 0, 6),
    // Move index to start of ICMPv6 header.
    BPF_STMT(BPF_LDX | BPF_IMM, sizeof(ip6_hdr)),
    // Load ICMPv6 type.
    BPF_STMT(BPF_LD | BPF_B | BPF_IND, offsetof(icmp6_hdr, icmp6_type)),
    // Check if is ND ICMPv6 message.
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ND_ROUTER_SOLICIT, 4, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ND_ROUTER_ADVERT, 3, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ND_NEIGHBOR_SOLICIT, 2, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ND_NEIGHBOR_ADVERT, 1, 0),
    // Return 0.
    BPF_STMT(BPF_RET | BPF_K, 0),
    // Return MAX.
    BPF_STMT(BPF_RET | BPF_K, IP_MAXPACKET),
};
const sock_fprog kNDPacketBpfProgram = {
    .len = sizeof(kNDPacketBpfInstructions) / sizeof(sock_filter),
    .filter = kNDPacketBpfInstructions};

std::string Icmp6TypeName(uint32_t type) {
  switch (type) {
    case ND_ROUTER_SOLICIT:
      return "ND_ROUTER_SOLICIT";
    case ND_ROUTER_ADVERT:
      return "ND_ROUTER_ADVERT";
    case ND_NEIGHBOR_SOLICIT:
      return "ND_NEIGHBOR_SOLICIT";
    case ND_NEIGHBOR_ADVERT:
      return "ND_NEIGHBOR_ADVERT";
    default:
      return "UNKNOWN";
  }
}

std::optional<net_base::IPv6CIDR> NDOptPrefixInfoToCIDR(
    const nd_opt_prefix_info* info) {
  if (info == nullptr) {
    return std::nullopt;
  }

  return net_base::IPv6CIDR::CreateFromAddressAndPrefix(
      net_base::IPv6Address(info->nd_opt_pi_prefix),
      info->nd_opt_pi_prefix_len);
}

[[maybe_unused]] std::string Icmp6ToString(const uint8_t* packet, size_t len) {
  const ip6_hdr* ip6 = reinterpret_cast<const ip6_hdr*>(packet);
  const icmp6_hdr* icmp6 =
      reinterpret_cast<const icmp6_hdr*>(packet + sizeof(ip6_hdr));

  if (len < sizeof(ip6_hdr) + sizeof(icmp6_hdr))
    return "<packet too small>";

  if (ip6->ip6_nxt != IPPROTO_ICMPV6)
    return "<not ICMP6 packet>";

  if (icmp6->icmp6_type < ND_ROUTER_SOLICIT ||
      icmp6->icmp6_type > ND_NEIGHBOR_ADVERT)
    return "<not ND ICMP6 packet>";

  std::stringstream ss;
  ss << Icmp6TypeName(icmp6->icmp6_type) << " "
     << net_base::IPv6Address(ip6->ip6_src) << " -> "
     << net_base::IPv6Address(ip6->ip6_dst);
  switch (icmp6->icmp6_type) {
    case ND_NEIGHBOR_SOLICIT:
    case ND_NEIGHBOR_ADVERT: {
      // NS and NA has same packet format for Target Address
      ss << ", target "
         << net_base::IPv6Address(
                reinterpret_cast<const nd_neighbor_solicit*>(icmp6)
                    ->nd_ns_target);
      break;
    }
    case ND_ROUTER_SOLICIT:
      // Nothing extra to print here
      break;
    case ND_ROUTER_ADVERT: {
      const nd_opt_prefix_info* prefix_info = NDProxy::GetPrefixInfoOption(
          reinterpret_cast<const uint8_t*>(icmp6), len - sizeof(ip6_hdr));
      const auto prefix_cidr = NDOptPrefixInfoToCIDR(prefix_info);
      if (prefix_cidr) {
        ss << ", prefix " << *prefix_cidr;
      }
      break;
    }
    default: {
      NOTREACHED();
    }
  }
  return ss.str();
}

}  // namespace

NDProxy::NDProxy() {}

// static
base::ScopedFD NDProxy::PreparePacketSocket() {
  base::ScopedFD fd(
      socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons(ETH_P_IPV6)));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "socket() failed";
    return base::ScopedFD();
  }
  if (setsockopt(fd.get(), SOL_SOCKET, SO_ATTACH_FILTER, &kNDPacketBpfProgram,
                 sizeof(kNDPacketBpfProgram))) {
    PLOG(ERROR) << "setsockopt(SO_ATTACH_FILTER) failed";
    return base::ScopedFD();
  }
  return fd;
}

bool NDProxy::Init() {
  rtnl_client_ = RTNLClient::Create();
  if (!rtnl_client_) {
    PLOG(ERROR) << "Failed to create rtnetlink client";
    return false;
  }

  dummy_fd_ = base::ScopedFD(socket(AF_INET6, SOCK_DGRAM, 0));
  if (!dummy_fd_.is_valid()) {
    PLOG(ERROR) << "socket() failed for dummy socket";
    return false;
  }
  return true;
}

// static
void NDProxy::ReplaceMacInIcmpOption(uint8_t* icmp6,
                                     size_t icmp6_len,
                                     size_t nd_hdr_len,
                                     uint8_t opt_type,
                                     const MacAddress& target_mac) {
  size_t opt_offset = nd_hdr_len;
  while (opt_offset + sizeof(nd_opt_hdr) <= icmp6_len) {
    nd_opt_hdr* opt = reinterpret_cast<nd_opt_hdr*>(icmp6 + opt_offset);
    // nd_opt_len is in 8 bytes unit.
    size_t opt_len = 8 * (opt->nd_opt_len);
    if (opt_len == 0 || icmp6_len < opt_offset + opt_len) {
      // Invalid packet.
      return;
    }
    if (opt->nd_opt_type == opt_type) {
      if (opt_len < sizeof(nd_opt_hdr) + ETHER_ADDR_LEN) {
        // Option length was inconsistent with the size of a MAC address.
        return;
      }
      memcpy(icmp6 + opt_offset + sizeof(nd_opt_hdr), target_mac.data(),
             ETHER_ADDR_LEN);
    }
    opt_offset += opt_len;
  }
}

// static
ssize_t NDProxy::TranslateNDPacket(
    const uint8_t* in_packet,
    size_t packet_len,
    const MacAddress& local_mac_addr,
    const std::optional<net_base::IPv6Address>& new_src_ip,
    const std::optional<net_base::IPv6Address>& new_dst_ip,
    uint8_t* out_packet) {
  if (packet_len < sizeof(ip6_hdr) + sizeof(icmp6_hdr)) {
    return kTranslateErrorInsufficientLength;
  }
  if (reinterpret_cast<const ip6_hdr*>(in_packet)->ip6_nxt != IPPROTO_ICMPV6) {
    return kTranslateErrorNotICMPv6Packet;
  }
  if (ntohs(reinterpret_cast<const ip6_hdr*>(in_packet)->ip6_plen) !=
      (packet_len - sizeof(struct ip6_hdr))) {
    return kTranslateErrorMismatchedIp6Length;
  }

  memcpy(out_packet, in_packet, packet_len);
  ip6_hdr* ip6 = reinterpret_cast<ip6_hdr*>(out_packet);
  icmp6_hdr* icmp6 = reinterpret_cast<icmp6_hdr*>(out_packet + sizeof(ip6_hdr));
  const size_t icmp6_len = packet_len - sizeof(ip6_hdr);

  switch (icmp6->icmp6_type) {
    case ND_ROUTER_SOLICIT:
      ReplaceMacInIcmpOption(reinterpret_cast<uint8_t*>(icmp6), icmp6_len,
                             sizeof(nd_router_solicit), ND_OPT_SOURCE_LINKADDR,
                             local_mac_addr);
      break;
    case ND_ROUTER_ADVERT: {
      // RFC 4389 Section 4.1.3.3 - Set Proxy bit
      nd_router_advert* ra = reinterpret_cast<nd_router_advert*>(icmp6);
      if (ra->nd_ra_flags_reserved & 0x04) {
        // According to RFC 4389, an RA packet with 'Proxy' bit set already
        // should not be proxied again, in order to avoid loop. However, we'll
        // need this form of proxy cascading in Crostini (Host->VM->Container)
        // so we are ignoring the check here. Note that we know we are doing RA
        // proxy in only one direction so there should be no loop.
      }
      ra->nd_ra_flags_reserved |= 0x04;

      ReplaceMacInIcmpOption(reinterpret_cast<uint8_t*>(icmp6), icmp6_len,
                             sizeof(nd_router_advert), ND_OPT_SOURCE_LINKADDR,
                             local_mac_addr);
      break;
    }
    case ND_NEIGHBOR_SOLICIT:
      ReplaceMacInIcmpOption(reinterpret_cast<uint8_t*>(icmp6), icmp6_len,
                             sizeof(nd_neighbor_solicit),
                             ND_OPT_SOURCE_LINKADDR, local_mac_addr);
      break;
    case ND_NEIGHBOR_ADVERT:
      ReplaceMacInIcmpOption(reinterpret_cast<uint8_t*>(icmp6), icmp6_len,
                             sizeof(nd_neighbor_advert), ND_OPT_TARGET_LINKADDR,
                             local_mac_addr);
      break;
    default:
      return kTranslateErrorNotNDPacket;
  }

  if (new_src_ip) {
    ip6->ip6_src = new_src_ip->ToIn6Addr();

    // Turn off onlink flag if we are pretending to be the router.
    nd_opt_prefix_info* prefix_info =
        GetPrefixInfoOption(reinterpret_cast<uint8_t*>(icmp6), icmp6_len);
    if (prefix_info) {
      prefix_info->nd_opt_pi_flags_reserved &= ~ND_OPT_PI_FLAG_ONLINK;
    }
  }
  if (new_dst_ip) {
    ip6->ip6_dst = new_dst_ip->ToIn6Addr();
  }

  // Recalculate the checksum. We need to clear the old checksum first so
  // checksum calculation does not wrongly take old checksum into account.
  icmp6->icmp6_cksum = 0;
  icmp6->icmp6_cksum =
      Icmpv6Checksum(reinterpret_cast<const uint8_t*>(ip6), packet_len);

  return static_cast<ssize_t>(packet_len);
}

void NDProxy::ReadAndProcessOnePacket(int fd) {
  uint8_t* in_packet = reinterpret_cast<uint8_t*>(in_packet_buffer_);
  uint8_t* out_packet = reinterpret_cast<uint8_t*>(out_packet_buffer_);

  sockaddr_ll recv_ll_addr;
  struct iovec iov_in = {
      .iov_base = in_packet,
      .iov_len = IP_MAXPACKET,
  };
  msghdr hdr = {
      .msg_name = &recv_ll_addr,
      .msg_namelen = sizeof(recv_ll_addr),
      .msg_iov = &iov_in,
      .msg_iovlen = 1,
      .msg_control = nullptr,
      .msg_controllen = 0,
      .msg_flags = 0,
  };

  ssize_t slen;
  if ((slen = recvmsg(fd, &hdr, 0)) < 0) {
    // Ignore ENETDOWN: this can happen if the interface is not yet configured
    if (errno != ENETDOWN) {
      PLOG(WARNING) << "recvmsg() failed";
    }
    return;
  }
  size_t len = static_cast<size_t>(slen);

  ip6_hdr* ip6 = reinterpret_cast<ip6_hdr*>(in_packet);
  icmp6_hdr* icmp6 = reinterpret_cast<icmp6_hdr*>(in_packet + sizeof(ip6_hdr));

  if (ip6->ip6_nxt != IPPROTO_ICMPV6 || icmp6->icmp6_type < ND_ROUTER_SOLICIT ||
      icmp6->icmp6_type > ND_NEIGHBOR_ADVERT)
    return;

  VLOG_IF(2, (icmp6->icmp6_type == ND_ROUTER_SOLICIT ||
              icmp6->icmp6_type == ND_ROUTER_ADVERT))
      << "Received on interface " << recv_ll_addr.sll_ifindex << ": "
      << Icmp6ToString(in_packet, len);
  VLOG_IF(6, (icmp6->icmp6_type == ND_NEIGHBOR_SOLICIT ||
              icmp6->icmp6_type == ND_NEIGHBOR_ADVERT))
      << "Received on interface " << recv_ll_addr.sll_ifindex << ": "
      << Icmp6ToString(in_packet, len);

  NotifyPacketCallbacks(recv_ll_addr.sll_ifindex, in_packet, len);

  if (downlink_link_local_.find(recv_ll_addr.sll_ifindex) !=
          downlink_link_local_.end() &&
      downlink_link_local_[recv_ll_addr.sll_ifindex] ==
          net_base::IPv6Address(ip6->ip6_dst)) {
    // If destination IP is our link local unicast, no need to proxy the packet.
    return;
  }

  // Translate the NDP frame and send it through proxy interface
  auto map_entry =
      MapForType(icmp6->icmp6_type)->find(recv_ll_addr.sll_ifindex);
  if (map_entry == MapForType(icmp6->icmp6_type)->end())
    return;

  const auto& target_ifs = map_entry->second;
  for (int target_if : target_ifs) {
    MacAddress local_mac;
    if (!GetLocalMac(target_if, &local_mac))
      continue;

    // b/246444885: Overwrite source IP address with host address and set
    // prefix offlink, to prevent internal traffic causing ICMP messaged being
    // sent to upstream caused by internal traffic.
    // b/187918638: On L850 only this is a must instead of an optimization.
    // With those modems we are observing irregular RAs coming from a src IP
    // that either cannot map to a hardware address in the neighbor table, or
    // is mapped to the local MAC address on the cellular interface. Directly
    // proxying these RAs will cause the guest OS to set up a default route to
    // a next hop that is not reachable for them.
    std::optional<net_base::IPv6Address> new_src_ip = std::nullopt;
    if (modify_ra_uplinks_.find(recv_ll_addr.sll_ifindex) !=
            modify_ra_uplinks_.end() &&
        icmp6->icmp6_type == ND_ROUTER_ADVERT) {
      if (downlink_link_local_.find(target_if) == downlink_link_local_.end()) {
        continue;
      }
      new_src_ip = downlink_link_local_[target_if];
    }

    // Always proxy RA to multicast address, so that every guest will accept it
    // therefore saving the total amount of RSs we sent to the network.
    // b/228574659: On L850 only this is a must instead of an optimization.
    std::optional<net_base::IPv6Address> new_dst_ip = std::nullopt;
    if (icmp6->icmp6_type == ND_ROUTER_ADVERT) {
      new_dst_ip = kAllNodesMulticastAddress;
    }

    const ssize_t result = TranslateNDPacket(
        in_packet, len, local_mac, new_src_ip, new_dst_ip, out_packet);
    if (result < 0) {
      switch (result) {
        case kTranslateErrorNotICMPv6Packet:
          LOG(DFATAL) << "Attempt to TranslateNDPacket on a non-ICMPv6 packet";
          return;
        case kTranslateErrorNotNDPacket:
          LOG(DFATAL) << "Attempt to TranslateNDPacket on a non-NDP packet, "
                         "icmpv6 type = "
                      << static_cast<int>(icmp6->icmp6_type);
          return;
        case kTranslateErrorInsufficientLength:
          LOG(DFATAL) << "TranslateNDPacket failed: packet length = " << len
                      << " is too small";
          return;
        case kTranslateErrorMismatchedIp6Length:
          LOG(DFATAL) << "TranslateNDPacket failed: expected ip6_plen = "
                      << ntohs(ip6->ip6_plen) << ", received length = "
                      << (len - sizeof(struct ip6_hdr));
          return;
        default:
          LOG(DFATAL) << "Unknown error in TranslateNDPacket";
          return;
      }
    }

    sockaddr_ll send_ll_addr = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_IPV6),
        .sll_ifindex = target_if,
        .sll_halen = ETHER_ADDR_LEN,
    };

    ip6_hdr* new_ip6 = reinterpret_cast<ip6_hdr*>(out_packet);
    const net_base::IPv6Address dst_addr(new_ip6->ip6_dst);
    ResolveDestinationMac(dst_addr, send_ll_addr.sll_addr);
    if (memcmp(send_ll_addr.sll_addr, &kZeroMacAddress, ETHER_ADDR_LEN) == 0) {
      VLOG(1) << "Cannot resolve " << Icmp6TypeName(icmp6->icmp6_type)
              << " packet dest IP " << dst_addr
              << " into MAC address. In: " << recv_ll_addr.sll_ifindex
              << ", out: " << target_if;
      if (IsGuestInterface(target_if) || !kDropUnresolvableUnicastToUpstream) {
        // If we can't resolve the destination IP into MAC from kernel neighbor
        // table, fill destination MAC with all-nodes multicast MAC instead.
        memcpy(send_ll_addr.sll_addr, &kAllNodesMulticastMacAddress,
               ETHER_ADDR_LEN);
      } else {
        // Drop the packet.
        return;
      }
    }

    VLOG_IF(3, (icmp6->icmp6_type == ND_ROUTER_SOLICIT ||
                icmp6->icmp6_type == ND_ROUTER_ADVERT))
        << "Sending to interface " << target_if << ": "
        << Icmp6ToString(out_packet, len);
    VLOG_IF(7, (icmp6->icmp6_type == ND_NEIGHBOR_SOLICIT ||
                icmp6->icmp6_type == ND_NEIGHBOR_ADVERT))
        << "Sending to interface " << target_if << ": "
        << Icmp6ToString(out_packet, len);

    struct iovec iov_out = {
        .iov_base = out_packet,
        .iov_len = static_cast<size_t>(len),
    };
    msghdr hdr = {
        .msg_name = &send_ll_addr,
        .msg_namelen = sizeof(send_ll_addr),
        .msg_iov = &iov_out,
        .msg_iovlen = 1,
        .msg_control = nullptr,
        .msg_controllen = 0,
    };
    if (sendmsg(fd, &hdr, 0) < 0) {
      // Ignore ENETDOWN: this can happen if the interface is not yet configured
      if (if_map_ra_.find(target_if) != if_map_ra_.end() && errno != ENETDOWN) {
        PLOG(WARNING) << "sendmsg() failed on interface " << target_if;
      }
    }
  }
}

// static
nd_opt_prefix_info* NDProxy::GetPrefixInfoOption(uint8_t* icmp6,
                                                 size_t icmp6_len) {
  uint8_t* start = reinterpret_cast<uint8_t*>(icmp6);
  uint8_t* end = start + icmp6_len;
  uint8_t* ptr = start + sizeof(nd_router_advert);
  while (ptr + offsetof(nd_opt_hdr, nd_opt_len) < end) {
    nd_opt_hdr* opt = reinterpret_cast<nd_opt_hdr*>(ptr);
    if (opt->nd_opt_len == 0)
      return nullptr;
    ptr += opt->nd_opt_len << 3;  // nd_opt_len is in 8 bytes
    if (ptr > end)
      return nullptr;
    if (opt->nd_opt_type == ND_OPT_PREFIX_INFORMATION &&
        opt->nd_opt_len << 3 == sizeof(nd_opt_prefix_info)) {
      return reinterpret_cast<nd_opt_prefix_info*>(opt);
    }
  }
  return nullptr;
}

// static
const nd_opt_prefix_info* NDProxy::GetPrefixInfoOption(const uint8_t* icmp6,
                                                       size_t icmp6_len) {
  return NDProxy::GetPrefixInfoOption(const_cast<uint8_t*>(icmp6), icmp6_len);
}

void NDProxy::NotifyPacketCallbacks(int recv_ifindex,
                                    const uint8_t* packet,
                                    size_t len) {
  const ip6_hdr* ip6 = reinterpret_cast<const ip6_hdr*>(packet);
  const icmp6_hdr* icmp6 =
      reinterpret_cast<const icmp6_hdr*>(packet + sizeof(ip6_hdr));

  // GuestDiscovery event is triggered whenever an NA advertising global
  // address or an NS with a global source address is received on a downlink.
  const in6_addr* guest_address = nullptr;
  if ((IsGuestInterface(recv_ifindex) ||
       neighbor_monitor_links_.count(recv_ifindex) > 0) &&
      !guest_discovery_handler_.is_null()) {
    if (icmp6->icmp6_type == ND_NEIGHBOR_ADVERT) {
      const nd_neighbor_advert* na =
          reinterpret_cast<const nd_neighbor_advert*>(icmp6);
      guest_address = &(na->nd_na_target);
    } else if (icmp6->icmp6_type == ND_NEIGHBOR_SOLICIT) {
      guest_address = &(ip6->ip6_src);

      // b/187918638: some cellular modems never send proper NS and NA,
      // there is no chance that we get the guest IP as normally from NA.
      // Instead, we have to monitor DAD NS frames and use it as judgement.
      // Notice that since upstream never reply NA, this DAD never fails.
      // b/266514205: extent this workaround to all technologies as we are
      // observing similar behavior in some wifi APs.
      // Empty source IP indicates DAD
      if (net_base::IPv6Address(ip6->ip6_src).IsZero()) {
        const nd_neighbor_solicit* ns =
            reinterpret_cast<const nd_neighbor_solicit*>(icmp6);
        guest_address = &(ns->nd_ns_target);
      }
    }
  }

  if (guest_address &&
      ((guest_address->s6_addr[0] & 0xe0) == 0x20 ||   // Global Unicast
       (guest_address->s6_addr[0] & 0xfe) == 0xfc)) {  // Unique Local
    const net_base::IPv6Address guest_addr(*guest_address);
    guest_discovery_handler_.Run(recv_ifindex, guest_addr);
    VLOG(2) << "GuestDiscovery on interface " << recv_ifindex << ": "
            << guest_addr;
  }

  // RouterDiscovery event is triggered whenever an RA is received on a uplink.
  if (icmp6->icmp6_type == ND_ROUTER_ADVERT &&
      IsRouterInterface(recv_ifindex) && !router_discovery_handler_.is_null()) {
    const nd_opt_prefix_info* prefix_info = GetPrefixInfoOption(
        reinterpret_cast<const uint8_t*>(icmp6), len - sizeof(ip6_hdr));
    const auto ipv6_cidr = NDOptPrefixInfoToCIDR(prefix_info);
    if (ipv6_cidr) {
      router_discovery_handler_.Run(recv_ifindex, *ipv6_cidr);
      VLOG(2) << "RouterDiscovery on interface " << recv_ifindex << ": "
              << *ipv6_cidr;
    }
  }
}

void NDProxy::ResolveDestinationMac(const net_base::IPv6Address& dest_ipv6,
                                    uint8_t* dest_mac) {
  if (dest_ipv6 == kAllNodesMulticastAddress) {
    memcpy(dest_mac, &kAllNodesMulticastMacAddress, ETHER_ADDR_LEN);
    return;
  }
  if (dest_ipv6 == kAllRoutersMulticastAddress) {
    memcpy(dest_mac, &kAllRoutersMulticastMacAddress, ETHER_ADDR_LEN);
    return;
  }
  if (kSolicitedNodeMulticastCIDR.InSameSubnetWith(dest_ipv6)) {
    const in6_addr dest_in6_addr = dest_ipv6.ToIn6Addr();
    memcpy(dest_mac, &kSolicitedNodeMulticastMacAddressPrefix, ETHER_ADDR_LEN);
    memcpy(
        dest_mac + ETHER_ADDR_LEN - kSolicitedGroupSuffixLength,
        &dest_in6_addr.s6_addr[sizeof(in6_addr) - kSolicitedGroupSuffixLength],
        kSolicitedGroupSuffixLength);
    return;
  }

  MacAddress neighbor_mac;
  if (GetNeighborMac(dest_ipv6, &neighbor_mac)) {
    memcpy(dest_mac, neighbor_mac.data(), ETHER_ADDR_LEN);
    return;
  }

  memcpy(dest_mac, &kZeroMacAddress, ETHER_ADDR_LEN);
}

std::optional<net_base::IPv6Address> NDProxy::GetLinkLocalAddress(int ifindex) {
  std::ifstream proc_file("/proc/net/if_inet6");
  std::string line;
  while (std::getline(proc_file, line)) {
    // Line format in /proc/net/if_inet6:
    //   address ifindex prefix_len scope flags ifname
    const auto tokens = base::SplitString(line, " \t", base::TRIM_WHITESPACE,
                                          base::SPLIT_WANT_NONEMPTY);
    if (tokens.size() < 4) {
      continue;
    }
    if (tokens[3] != "20") {
      // We are only looking for link local address (scope value == "20")
      continue;
    }
    int line_if_id;
    if (!base::HexStringToInt(tokens[1], &line_if_id) ||
        line_if_id != ifindex) {
      continue;
    }

    std::vector<uint8_t> line_address;
    if (!base::HexStringToBytes(tokens[0], &line_address)) {
      continue;
    }

    const auto addr = net_base::IPv6Address::CreateFromBytes(
        line_address.data(), line_address.size());
    if (addr) {
      return addr;
    }
  }
  return std::nullopt;
}

bool NDProxy::GetLocalMac(int if_id, MacAddress* mac_addr) {
  ifreq ifr = {
      .ifr_ifindex = if_id,
  };
  if (ioctl(dummy_fd_.get(), SIOCGIFNAME, &ifr) < 0) {
    PLOG(ERROR) << "ioctl() failed to get interface name on interface "
                << if_id;
    return false;
  }
  if (ioctl(dummy_fd_.get(), SIOCGIFHWADDR, &ifr) < 0) {
    PLOG(ERROR) << "ioctl() failed to get MAC address on interface " << if_id;
    return false;
  }
  memcpy(mac_addr->data(), ifr.ifr_addr.sa_data, ETHER_ADDR_LEN);
  return true;
}

bool NDProxy::GetNeighborMac(const net_base::IPv6Address& ipv6_addr,
                             MacAddress* mac_addr) {
  DCHECK(rtnl_client_);

  const auto neighbor_mac_table = rtnl_client_->GetIPv6NeighborMacTable();
  const auto it = neighbor_mac_table.find(ipv6_addr);
  if (it == neighbor_mac_table.end()) {
    return false;
  }

  *mac_addr = it->second;
  return true;
}

void NDProxy::RegisterOnGuestIpDiscoveryHandler(
    GuestIpDiscoveryHandler handler) {
  guest_discovery_handler_ = std::move(handler);
}

void NDProxy::RegisterOnRouterDiscoveryHandler(RouterDiscoveryHandler handler) {
  router_discovery_handler_ = std::move(handler);
}

NDProxy::interface_mapping* NDProxy::MapForType(uint8_t type) {
  switch (type) {
    case ND_ROUTER_SOLICIT:
      return &if_map_rs_;
    case ND_ROUTER_ADVERT:
      return &if_map_ra_;
    case ND_NEIGHBOR_SOLICIT:
      return &if_map_ns_;
    case ND_NEIGHBOR_ADVERT:
      return &if_map_na_;
    default:
      LOG(DFATAL) << "Attempt to get interface map on illegal icmpv6 type "
                  << static_cast<int>(type);
      return nullptr;
  }
}

void NDProxy::StartRSRAProxy(int if_id_upstream,
                             int if_id_downstream,
                             bool modify_router_address) {
  VLOG(1) << "StartRARSProxy(" << if_id_upstream << ", " << if_id_downstream
          << (modify_router_address ? ", modify_router_address)" : ")");
  if_map_ra_[if_id_upstream].insert(if_id_downstream);
  if_map_rs_[if_id_downstream].insert(if_id_upstream);
  if (modify_router_address) {
    modify_ra_uplinks_.insert(if_id_upstream);
  }

  const auto addr = GetLinkLocalAddress(if_id_downstream);
  if (addr) {
    downlink_link_local_[if_id_downstream] = *addr;
  } else {
    LOG(WARNING) << "Cannot find a link local address on interface "
                 << if_id_downstream;
    downlink_link_local_[if_id_downstream] = net_base::IPv6Address();
  }
}

void NDProxy::StartNSNAProxy(int if_id_na_side, int if_id_ns_side) {
  VLOG(1) << "StartNSNAProxy(" << if_id_na_side << ", " << if_id_ns_side << ")";
  if_map_na_[if_id_na_side].insert(if_id_ns_side);
  if_map_ns_[if_id_ns_side].insert(if_id_na_side);
}

void NDProxy::StopProxy(int if_id1, int if_id2) {
  VLOG(1) << "StopProxy(" << if_id1 << ", " << if_id2 << ")";
  auto remove_pair = [if_id1, if_id2](interface_mapping& mapping) {
    mapping[if_id1].erase(if_id2);
    if (mapping[if_id1].empty()) {
      mapping.erase(if_id1);
    }
    mapping[if_id2].erase(if_id1);
    if (mapping[if_id2].empty()) {
      mapping.erase(if_id2);
    }
  };
  remove_pair(if_map_ra_);
  remove_pair(if_map_rs_);
  remove_pair(if_map_na_);
  remove_pair(if_map_ns_);
  if (!IsRouterInterface(if_id1)) {
    modify_ra_uplinks_.erase(if_id1);
  }
  if (!IsRouterInterface(if_id2)) {
    modify_ra_uplinks_.erase(if_id2);
  }
}

void NDProxy::StartNeighborMonitor(int if_id) {
  neighbor_monitor_links_.insert(if_id);
}

void NDProxy::StopNeighborMonitor(int if_id) {
  neighbor_monitor_links_.erase(if_id);
}

bool NDProxy::IsGuestInterface(int ifindex) {
  return if_map_rs_.find(ifindex) != if_map_rs_.end();
}

bool NDProxy::IsRouterInterface(int ifindex) {
  return if_map_ra_.find(ifindex) != if_map_ra_.end();
}

NDProxyDaemon::NDProxyDaemon(base::ScopedFD control_fd)
    : msg_dispatcher_(std::make_unique<MessageDispatcher<SubprocessMessage>>(
          std::move(control_fd))) {}

NDProxyDaemon::~NDProxyDaemon() {}

int NDProxyDaemon::OnInit() {
  // Prevent the main process from sending us any signals.
  if (setsid() < 0) {
    PLOG(ERROR) << "Failed to created a new session with setsid: exiting";
    return EX_OSERR;
  }

  EnterChildProcessJail();

  // Register control fd callbacks
  if (msg_dispatcher_) {
    msg_dispatcher_->RegisterFailureHandler(base::BindRepeating(
        &NDProxyDaemon::OnParentProcessExit, weak_factory_.GetWeakPtr()));
    msg_dispatcher_->RegisterMessageHandler(base::BindRepeating(
        &NDProxyDaemon::OnControlMessage, weak_factory_.GetWeakPtr()));
  }

  // Initialize NDProxy and register guest IP discovery callback
  if (!proxy_.Init()) {
    PLOG(ERROR) << "Failed to initialize NDProxy internal state";
    return EX_OSERR;
  }
  proxy_.RegisterOnGuestIpDiscoveryHandler(base::BindRepeating(
      &NDProxyDaemon::OnGuestIpDiscovery, weak_factory_.GetWeakPtr()));
  proxy_.RegisterOnRouterDiscoveryHandler(base::BindRepeating(
      &NDProxyDaemon::OnRouterDiscovery, weak_factory_.GetWeakPtr()));

  // Initialize data fd
  fd_ = NDProxy::PreparePacketSocket();
  if (!fd_.is_valid()) {
    return EX_OSERR;
  }

  // Start watching on data fd
  watcher_ = base::FileDescriptorWatcher::WatchReadable(
      fd_.get(), base::BindRepeating(&NDProxyDaemon::OnDataSocketReadReady,
                                     weak_factory_.GetWeakPtr()));
  LOG(INFO) << "Started watching on packet fd...";

  return Daemon::OnInit();
}

void NDProxyDaemon::OnDataSocketReadReady() {
  proxy_.ReadAndProcessOnePacket(fd_.get());
}

void NDProxyDaemon::OnParentProcessExit() {
  LOG(ERROR) << "Quitting because the parent process died";
  Quit();
}

void NDProxyDaemon::OnControlMessage(const SubprocessMessage& root_msg) {
  if (!root_msg.has_control_message() ||
      !root_msg.control_message().has_ndproxy_control()) {
    LOG(ERROR) << "Unexpected message type";
    return;
  }
  const NDProxyControlMessage& msg =
      root_msg.control_message().ndproxy_control();
  VLOG(4) << "Received NDProxyControlMessage: " << msg.type() << ": "
          << msg.if_id_primary() << "<->" << msg.if_id_secondary();
  switch (msg.type()) {
    case NDProxyControlMessage::START_NS_NA: {
      proxy_.StartNSNAProxy(msg.if_id_primary(), msg.if_id_secondary());
      proxy_.StartNSNAProxy(msg.if_id_secondary(), msg.if_id_primary());
      break;
    }
    case NDProxyControlMessage::START_NS_NA_RS_RA: {
      proxy_.StartNSNAProxy(msg.if_id_primary(), msg.if_id_secondary());
      proxy_.StartNSNAProxy(msg.if_id_secondary(), msg.if_id_primary());
      proxy_.StartRSRAProxy(msg.if_id_primary(), msg.if_id_secondary());
      break;
    }
    case NDProxyControlMessage::START_NS_NA_RS_RA_MODIFYING_ROUTER_ADDRESS: {
      // TODO(taoyl): therotically whe should be able to stop proxying NS from
      // downlink to uplink and NA from uplink to downlink as we set prefix to
      // be not ONLINK. However, Android ignores the ONLINK flag and always add
      // a local subnet route when receiving a prefix [1]. Consider addressing
      // this in Android so we can remove the first line below.
      // [1] LinkProperties::ensureDirectlyConnectedRoutes()
      proxy_.StartNSNAProxy(msg.if_id_primary(), msg.if_id_secondary());
      proxy_.StartNSNAProxy(msg.if_id_secondary(), msg.if_id_primary());
      proxy_.StartRSRAProxy(msg.if_id_primary(), msg.if_id_secondary(), true);
      break;
    }
    case NDProxyControlMessage::STOP_PROXY: {
      proxy_.StopProxy(msg.if_id_primary(), msg.if_id_secondary());
      break;
    }
    case NDProxyControlMessage::START_NEIGHBOR_MONITOR: {
      proxy_.StartNeighborMonitor(msg.if_id_primary());
      break;
    }
    case NDProxyControlMessage::STOP_NEIGHBOR_MONITOR: {
      proxy_.StopNeighborMonitor(msg.if_id_primary());
      break;
    }
    case NDProxyControlMessage::UNKNOWN:
    default:
      NOTREACHED();
  }
}

void NDProxyDaemon::OnGuestIpDiscovery(int if_id,
                                       const net_base::IPv6Address& ip6addr) {
  if (!msg_dispatcher_) {
    return;
  }
  NeighborDetectedSignal msg;
  msg.set_if_id(if_id);
  msg.set_ip(ip6addr.ToByteString());
  NDProxySignalMessage nm;
  *nm.mutable_neighbor_detected_signal() = msg;
  FeedbackMessage fm;
  *fm.mutable_ndproxy_signal() = nm;
  SubprocessMessage root_m;
  *root_m.mutable_feedback_message() = fm;
  msg_dispatcher_->SendMessage(root_m);
}

void NDProxyDaemon::OnRouterDiscovery(int if_id,
                                      const net_base::IPv6CIDR& prefix_cidr) {
  if (!msg_dispatcher_) {
    return;
  }
  RouterDetectedSignal msg;
  msg.set_if_id(if_id);
  msg.set_ip(prefix_cidr.address().ToByteString());
  msg.set_prefix_len(prefix_cidr.prefix_length());
  NDProxySignalMessage nm;
  *nm.mutable_router_detected_signal() = msg;
  FeedbackMessage fm;
  *fm.mutable_ndproxy_signal() = nm;
  SubprocessMessage root_m;
  *root_m.mutable_feedback_message() = fm;
  msg_dispatcher_->SendMessage(root_m);
}

}  // namespace patchpanel
