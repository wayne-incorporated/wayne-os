// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/net_util.h"

#include <errno.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <random>
#include <utility>
#include <vector>

#include <base/logging.h>
#include <base/strings/stringprintf.h>

namespace patchpanel {

namespace {

using flags_info_t = std::vector<std::pair<uint32_t, std::string>>;

// Helper for pretty printing flags
void AddFlags(std::ostream& stream,
              uint32_t flags,
              const flags_info_t& flags_info) {
  if (flags == 0) {
    stream << '0';
    return;
  }
  std::string sep = "";
  for (const auto& flag_descr : flags_info) {
    if ((flags & flag_descr.first) == 0)
      continue;
    stream << sep << flag_descr.second;
    sep = " | ";
  }
}

const flags_info_t kRtentryRTF = {
    {RTF_UP, "RTF_UP"},           {RTF_GATEWAY, "RTF_GATEWAY"},
    {RTF_HOST, "RTF_HOST"},       {RTF_REINSTATE, "RTF_REINSTATE"},
    {RTF_DYNAMIC, "RTF_DYNAMIC"}, {RTF_MODIFIED, "RTF_MODIFIED"},
    {RTF_MTU, "RTF_MTU"},         {RTF_MSS, "RTF_MSS"},
    {RTF_WINDOW, "RTF_WINDOW"},   {RTF_IRTT, "RTF_IRTT"},
    {RTF_REJECT, "RTF_REJECT"},
};

}  // namespace

net_base::IPv4Address ConvertUint32ToIPv4Address(uint32_t addr) {
  const uint32_t host_endian = ntohl(addr);
  return net_base::IPv4Address(static_cast<uint8_t>((host_endian >> 24) & 0xff),
                               static_cast<uint8_t>((host_endian >> 16) & 0xff),
                               static_cast<uint8_t>((host_endian >> 8) & 0xff),
                               static_cast<uint8_t>(host_endian & 0xff));
}

net_base::IPv4Address AddOffset(const net_base::IPv4Address& addr,
                                uint32_t offset) {
  const uint32_t host_endian = ntohl(addr.ToInAddr().s_addr) + offset;

  in_addr new_addr;
  new_addr.s_addr = htonl(host_endian);
  return net_base::IPv4Address(new_addr);
}

std::optional<uint32_t> Ipv4Addr(const std::string& bytes) {
  if (bytes.length() != 4) {
    return std::nullopt;
  }
  return Ipv4Addr(static_cast<unsigned char>(bytes[0]),
                  static_cast<unsigned char>(bytes[1]),
                  static_cast<unsigned char>(bytes[2]),
                  static_cast<unsigned char>(bytes[3]));
}

uint32_t Ipv4Netmask(int prefix_len) {
  return htonl((0xffffffffull << (32 - prefix_len)) & 0xffffffff);
}

uint32_t Ipv4BroadcastAddr(uint32_t base, int prefix_len) {
  return (base | ~Ipv4Netmask(prefix_len));
}

std::string IPv4AddressToString(uint32_t addr) {
  char buf[INET_ADDRSTRLEN] = {0};
  struct in_addr ia;
  ia.s_addr = addr;
  return !inet_ntop(AF_INET, &ia, buf, sizeof(buf)) ? "" : buf;
}

std::string IPv4AddressToString(std::vector<uint8_t> addr) {
  if (addr.size() != 4) {
    return "";
  }
  return IPv4AddressToString(Ipv4Addr(addr[0], addr[1], addr[2], addr[3]));
}

struct in_addr StringToIPv4Address(const std::string& buf) {
  struct in_addr addr = {};
  if (!inet_pton(AF_INET, buf.c_str(), &addr)) {
    memset(&addr, 0, sizeof(addr));
  }
  return addr;
}

std::string IPv4AddressToCidrString(uint32_t addr, int prefix_length) {
  return IPv4AddressToString(addr) + "/" + std::to_string(prefix_length);
}

std::string IPv4AddressToCidrString(std::vector<uint8_t> addr,
                                    int prefix_length) {
  if (addr.size() != 4) {
    return "";
  }
  return IPv4AddressToString(addr) + "/" + std::to_string(prefix_length);
}

std::string MacAddressToString(const MacAddress& addr) {
  return base::StringPrintf("%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1],
                            addr[2], addr[3], addr[4], addr[5]);
}

bool GenerateEUI64Address(in6_addr* address,
                          const in6_addr& prefix,
                          const MacAddress& mac) {
  // RFC 4291, Appendix A: Insert 0xFF and 0xFE to form EUI-64, then flip
  // universal/local bit
  memcpy(address, &prefix, sizeof(in6_addr));
  memcpy(&(address->s6_addr[8]), &(mac[0]), 3);
  memcpy(&(address->s6_addr[13]), &(mac[3]), 3);
  address->s6_addr[11] = 0xff;
  address->s6_addr[12] = 0xfe;
  address->s6_addr[8] ^= 0x2;
  return true;
}

void SetSockaddrIn(struct sockaddr* sockaddr,
                   const net_base::IPv4Address& addr) {
  struct sockaddr_in* sockaddr_in =
      reinterpret_cast<struct sockaddr_in*>(sockaddr);
  sockaddr_in->sin_family = AF_INET;
  sockaddr_in->sin_addr = addr.ToInAddr();
}

std::ostream& operator<<(std::ostream& stream, const struct in_addr& addr) {
  char buf[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &addr, buf, sizeof(buf));
  stream << buf;
  return stream;
}

std::ostream& operator<<(std::ostream& stream, const struct in6_addr& addr) {
  char buf[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
  stream << buf;
  return stream;
}

std::ostream& operator<<(std::ostream& stream, const struct sockaddr& addr) {
  switch (addr.sa_family) {
    case 0:
      return stream << "{unset}";
    case AF_INET:
      return stream << (const struct sockaddr_in&)addr;
    case AF_INET6:
      return stream << (const struct sockaddr_in6&)addr;
    case AF_UNIX:
      return stream << (const struct sockaddr_un&)addr;
    case AF_VSOCK:
      return stream << (const struct sockaddr_vm&)addr;
    case AF_PACKET:
      return stream << (const struct sockaddr_ll&)addr;
    default:
      return stream << "{family: " << addr.sa_family << ", (unknown)}";
  }
}

std::ostream& operator<<(std::ostream& stream,
                         const struct sockaddr_storage& addr) {
  return stream << (const struct sockaddr&)addr;
}

std::ostream& operator<<(std::ostream& stream, const struct sockaddr_in& addr) {
  char buf[INET_ADDRSTRLEN] = {0};
  inet_ntop(AF_INET, &addr.sin_addr, buf, sizeof(buf));
  return stream << "{family: AF_INET, port: " << ntohs(addr.sin_port)
                << ", addr: " << buf << "}";
}

std::ostream& operator<<(std::ostream& stream,
                         const struct sockaddr_in6& addr) {
  char buf[INET6_ADDRSTRLEN] = {0};
  inet_ntop(AF_INET6, &addr.sin6_addr, buf, sizeof(buf));
  return stream << "{family: AF_INET6, port: " << ntohs(addr.sin6_port)
                << ", addr: " << buf << "}";
}

std::ostream& operator<<(std::ostream& stream, const struct sockaddr_un& addr) {
  const size_t sun_path_length = sizeof(addr) - sizeof(sa_family_t);
  // Add room for one extra char to ensure |buf| is a null terminated string
  char buf[sun_path_length + 1] = {0};
  memcpy(buf, addr.sun_path, sun_path_length);
  if (buf[0] == '\0') {
    buf[0] = '@';
  }
  return stream << "{family: AF_UNIX, path: " << buf << "}";
}

std::ostream& operator<<(std::ostream& stream, const struct sockaddr_vm& addr) {
  return stream << "{family: AF_VSOCK, port: " << addr.svm_port
                << ", cid: " << addr.svm_cid << "}";
}

std::ostream& operator<<(std::ostream& stream, const struct sockaddr_ll& addr) {
  char ifname[IFNAMSIZ] = {};
  if (addr.sll_ifindex > 0) {
    if_indextoname(static_cast<uint32_t>(addr.sll_ifindex), ifname);
  }
  stream << "{family: AF_PACKET, ifindex=" << addr.sll_ifindex << " " << ifname;
  switch (addr.sll_pkttype) {
    case PACKET_HOST:
      stream << ", PACKET_HOST";
      break;
    case PACKET_BROADCAST:
      stream << ", PACKET_BROADCAST";
      break;
    case PACKET_MULTICAST:
      stream << ", PACKET_MULTICAST";
      break;
    case PACKET_OTHERHOST:
      stream << ", PACKET_OTHERHOST";
      break;
    case PACKET_OUTGOING:
      stream << ", PACKET_OUTGOING";
      break;
    case PACKET_LOOPBACK:
      stream << ", PACKET_LOOPBACK";
      break;
    case PACKET_USER:
      stream << ", PACKET_USER";
      break;
    case PACKET_KERNEL:
      stream << ", PACKET_KERNEL";
      break;
    default:
      // do not print sll_pkttype
      break;
  }
  return stream << base::StringPrintf(
             ", addr=%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x, "
             "protocol=0x%04xl}",
             addr.sll_addr[0], addr.sll_addr[1], addr.sll_addr[2],
             addr.sll_addr[3], addr.sll_addr[4], addr.sll_addr[5],
             addr.sll_addr[6], addr.sll_addr[7], htons(addr.sll_protocol));
}

std::ostream& operator<<(std::ostream& stream, const struct rtentry& route) {
  std::string rt_dev =
      route.rt_dev ? std::string(route.rt_dev, strnlen(route.rt_dev, IFNAMSIZ))
                   : "null";
  stream << "{rt_dst: " << route.rt_dst << ", rt_genmask: " << route.rt_genmask
         << ", rt_gateway: " << route.rt_gateway << ", rt_dev: " << rt_dev
         << ", rt_flags: ";
  AddFlags(stream, route.rt_flags, kRtentryRTF);
  return stream << "}";
}

uint16_t FoldChecksum(uint32_t sum) {
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  return static_cast<uint16_t>(~sum);
}

uint32_t NetChecksum(const void* data, size_t len) {
  uint32_t sum = 0;
  const uint16_t* word = reinterpret_cast<const uint16_t*>(data);
  for (; len > 1; len -= 2)
    sum += *word++;
  if (len)
    // Cast it as a uint8_t since there's only one byte left.
    sum += *(reinterpret_cast<const uint8_t*>(word));
  return sum;
}

uint16_t Ipv4Checksum(const iphdr* ip) {
  uint32_t sum = NetChecksum(ip, sizeof(iphdr));
  return FoldChecksum(sum);
}

uint16_t Udpv4Checksum(const uint8_t* udp_packet, size_t len) {
  if (len < sizeof(iphdr) + sizeof(udphdr)) {
    LOG(ERROR) << "UDP packet length is too small";
    return 0;
  }

  uint8_t pseudo_header[12];
  memset(pseudo_header, 0, sizeof(pseudo_header));

  struct iphdr* ip_hdr = (struct iphdr*)(udp_packet);
  struct udphdr* udp_hdr = (struct udphdr*)(udp_packet + sizeof(iphdr));

  // Fill in the pseudo-header.
  memcpy(pseudo_header, &ip_hdr->saddr, sizeof(in_addr));
  memcpy(pseudo_header + 4, &ip_hdr->daddr, sizeof(in_addr));
  memcpy(pseudo_header + 9, &ip_hdr->protocol, sizeof(uint8_t));
  memcpy(pseudo_header + 10, &udp_hdr->len, sizeof(uint16_t));

  // Compute pseudo-header checksum
  uint32_t sum = NetChecksum(pseudo_header, sizeof(pseudo_header));

  // UDP
  const uint8_t* udp_segment = udp_packet + sizeof(iphdr);
  // Safe subtraction because |len| is known to be larger than sizeof(iphdr)
  size_t udp_len = len - sizeof(iphdr);

  sum += NetChecksum(udp_segment, udp_len);

  return FoldChecksum(sum);
}

uint16_t Icmpv6Checksum(const uint8_t* ip6_packet, size_t len) {
  if (len < sizeof(ip6_hdr) + sizeof(icmp6_hdr)) {
    LOG(ERROR) << "ICMPv6 packet length is too small";
    return 0;
  }

  const struct ip6_hdr* ip6 =
      reinterpret_cast<const struct ip6_hdr*>(ip6_packet);

  uint32_t sum = 0;
  // Src and Dst IP
  for (size_t i = 0; i < (sizeof(struct in6_addr) >> 1); ++i)
    sum += ip6->ip6_src.s6_addr16[i];
  for (size_t i = 0; i < (sizeof(struct in6_addr) >> 1); ++i)
    sum += ip6->ip6_dst.s6_addr16[i];

  // Upper-Layer Packet Length
  sum += ip6->ip6_plen;
  // Next Header
  sum += IPPROTO_ICMPV6 << 8;

  // ICMP
  const struct icmp6_hdr* icmp6 =
      reinterpret_cast<const struct icmp6_hdr*>(ip6_packet + sizeof(ip6_hdr));
  // Safe subtraction because |len| is known to be larger than sizeof(iphdr)
  size_t icmp6_len = len - sizeof(ip6_hdr);
  sum += NetChecksum(icmp6, icmp6_len);

  return FoldChecksum(sum);
}

bool IsMulticastInterface(const std::string& ifname) {
  if (ifname.empty()) {
    return false;
  }

  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    // If IPv4 fails, try to open a socket using IPv6.
    fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) {
      LOG(ERROR) << "Unable to create socket";
      return false;
    }
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ);
  if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
    PLOG(ERROR) << "SIOCGIFFLAGS failed for " << ifname;
    close(fd);
    return false;
  }

  close(fd);
  return (ifr.ifr_flags & IFF_MULTICAST);
}

sa_family_t GetIpFamily(const std::string& ip_address) {
  struct in6_addr addr;
  if (inet_pton(AF_INET, ip_address.c_str(), &addr.s6_addr) == 1)
    return AF_INET;
  if (inet_pton(AF_INET6, ip_address.c_str(), &addr.s6_addr) == 1)
    return AF_INET6;
  return AF_UNSPEC;
}

}  // namespace patchpanel
