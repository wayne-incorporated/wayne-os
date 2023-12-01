// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/net_util.h"

#include <arpa/inet.h>
#include <byteswap.h>
#include <net/ethernet.h>

#include <gtest/gtest.h>

namespace patchpanel {

const uint8_t ping_frame[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x86, 0xdd, 0x60, 0x0b, 0x8d, 0xb4, 0x00, 0x40, 0x3a, 0x40, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x00, 0xb9, 0x3c, 0x13, 0x8f,
    0x00, 0x09, 0xde, 0x6a, 0x78, 0x5d, 0x00, 0x00, 0x00, 0x00, 0x8e, 0x13,
    0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
    0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
    0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};

const uint8_t rs_frame[] = {
    0x33, 0x33, 0x00, 0x00, 0x00, 0x02, 0x1a, 0x9b, 0x82, 0xbd, 0xc0, 0xa0,
    0x86, 0xdd, 0x60, 0x00, 0x00, 0x00, 0x00, 0x10, 0x3a, 0xff, 0xfe, 0x80,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2d, 0x75, 0xb2, 0x80, 0x97, 0x83,
    0x76, 0xbf, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x85, 0x00, 0x2f, 0xfc, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x01, 0x1a, 0x9b, 0x82, 0xbd, 0xc0, 0xa0};

const uint8_t ip_header[] = {0x45, 0x00, 0x00, 0x3d, 0x7c, 0x8e, 0x40,
                             0x00, 0x40, 0x11, 0x3d, 0x36, 0x64, 0x73,
                             0x5c, 0x02, 0x64, 0x73, 0x5c, 0x03};

const uint8_t udp_packet[] = {
    0x45, 0x00, 0x00, 0x65, 0x44, 0xf7, 0x40, 0x00, 0x3f, 0x11, 0x7d, 0x62,
    0x64, 0x57, 0x54, 0x5a, 0x64, 0x73, 0x5c, 0x0a, 0x9d, 0x6c, 0x09, 0xa4,
    0x00, 0x51, 0x58, 0xfb, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c,
    0x20, 0x20, 0x61, 0x73, 0x73, 0x75, 0x6d, 0x65, 0x73, 0x20, 0x20, 0x74,
    0x68, 0x61, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20, 0x49, 0x6e, 0x74, 0x65,
    0x72, 0x6e, 0x65, 0x74, 0x20, 0x20, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63,
    0x6f, 0x6c, 0x20, 0x20, 0x28, 0x49, 0x50, 0x29, 0x20, 0x20, 0x5b, 0x31,
    0x5d, 0x20, 0x69, 0x73, 0x20, 0x75, 0x73, 0x65, 0x64, 0x20, 0x61, 0x73,
    0x20, 0x74, 0x68, 0x65, 0x0a};

TEST(Ipv4, CreationAndStringConversion) {
  struct {
    std::string literal_address;
    uint8_t bytes[4];
  } test_cases[] = {
      {"0.0.0.0", {0, 0, 0, 0}},
      {"8.8.8.8", {8, 8, 8, 8}},
      {"8.8.4.4", {8, 8, 4, 4}},
      {"192.168.0.0", {192, 168, 0, 0}},
      {"100.115.92.5", {100, 115, 92, 5}},
      {"100.115.92.6", {100, 115, 92, 6}},
      {"224.0.0.251", {224, 0, 0, 251}},
      {"255.255.255.255", {255, 255, 255, 255}},
  };

  for (auto const& test_case : test_cases) {
    uint32_t addr = Ipv4Addr(test_case.bytes[0], test_case.bytes[1],
                             test_case.bytes[2], test_case.bytes[3]);
    std::vector<uint8_t> bytes = {test_case.bytes[0], test_case.bytes[1],
                                  test_case.bytes[2], test_case.bytes[3]};
    EXPECT_EQ(test_case.literal_address, IPv4AddressToString(addr));
    EXPECT_EQ(test_case.literal_address, IPv4AddressToString(bytes));
    EXPECT_EQ(addr, StringToIPv4Address(test_case.literal_address).s_addr);
  }
}

TEST(Ipv4, CreationAndCidrStringConversion) {
  struct {
    std::string literal_address;
    uint8_t bytes[4];
    int prefix_length;
  } test_cases[] = {
      {"0.0.0.0/0", {0, 0, 0, 0}, 0},
      {"192.168.0.0/24", {192, 168, 0, 0}, 24},
      {"100.115.92.5/30", {100, 115, 92, 5}, 30},
      {"100.115.92.6/30", {100, 115, 92, 6}, 30},
  };

  for (auto const& test_case : test_cases) {
    uint32_t addr = Ipv4Addr(test_case.bytes[0], test_case.bytes[1],
                             test_case.bytes[2], test_case.bytes[3]);
    std::vector<uint8_t> bytes = {test_case.bytes[0], test_case.bytes[1],
                                  test_case.bytes[2], test_case.bytes[3]};
    EXPECT_EQ(test_case.literal_address,
              IPv4AddressToCidrString(addr, test_case.prefix_length));
    EXPECT_EQ(test_case.literal_address,
              IPv4AddressToCidrString(bytes, test_case.prefix_length));
  }
}

TEST(Ipv4, IpChecksum) {
  alignas(4) uint8_t buffer[IP_MAXPACKET];

  iphdr* ip = reinterpret_cast<iphdr*>(buffer);

  memcpy(buffer, ip_header, sizeof(ip_header));
  uint16_t ori_cksum = ip->check;
  ip->check = 0;
  EXPECT_EQ(ori_cksum, Ipv4Checksum(ip));
}

TEST(Ipv4, UdpChecksum) {
  alignas(4) uint8_t buffer[IP_MAXPACKET];

  udphdr* udp = reinterpret_cast<udphdr*>(buffer + sizeof(iphdr));

  memcpy(buffer, udp_packet, sizeof(udp_packet));
  uint16_t ori_cksum = udp->check;
  udp->check = 0;
  EXPECT_EQ(ori_cksum, Udpv4Checksum(buffer, sizeof(udp_packet)));
}

TEST(Ipv6, IcmpChecksum) {
  alignas(4) uint8_t buffer_extended[IP_MAXPACKET + ETHER_HDR_LEN + 2];
  uint8_t* buffer = buffer_extended + 2;

  ip6_hdr* ip6 = reinterpret_cast<ip6_hdr*>(buffer + ETHER_HDR_LEN);
  icmp6_hdr* icmp6 =
      reinterpret_cast<icmp6_hdr*>(buffer + ETHER_HDR_LEN + sizeof(ip6_hdr));

  memcpy(buffer, ping_frame, sizeof(ping_frame));
  uint16_t ori_cksum = icmp6->icmp6_cksum;
  icmp6->icmp6_cksum = 0;
  size_t ip6_packet_len = sizeof(ping_frame) - ETHER_HDR_LEN;
  EXPECT_EQ(ori_cksum, Icmpv6Checksum(reinterpret_cast<const uint8_t*>(ip6),
                                      ip6_packet_len));

  memcpy(buffer, rs_frame, sizeof(rs_frame));
  ori_cksum = icmp6->icmp6_cksum;
  icmp6->icmp6_cksum = 0;
  ip6_packet_len = sizeof(rs_frame) - ETHER_HDR_LEN;
  EXPECT_EQ(ori_cksum, Icmpv6Checksum(reinterpret_cast<const uint8_t*>(ip6),
                                      ip6_packet_len));
}

TEST(Ipv6, EUI64Addr) {
  struct {
    std::string prefix;
    MacAddress mac_address;
    std::string eui64_address;
  } test_cases[] = {{"::", {0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, "::200:ff:fe00:0"},
                    {"2001:da8:ff:5002::",
                     {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc},
                     "2001:da8:ff:5002:1034:56ff:fe78:9abc"},
                    {"fe80::",
                     {0xf4, 0x99, 0x9f, 0xf4, 0x4f, 0xe4},
                     "fe80::f699:9fff:fef4:4fe4"}};
  in6_addr prefix;
  in6_addr addr;
  for (auto const& test_case : test_cases) {
    inet_pton(AF_INET6, test_case.prefix.c_str(), &prefix);
    GenerateEUI64Address(&addr, prefix, test_case.mac_address);
    char eui64_addr_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &addr, eui64_addr_str, INET6_ADDRSTRLEN);
    EXPECT_EQ(test_case.eui64_address, eui64_addr_str);
  }
}

TEST(Ipv4, BroadcastAddr) {
  uint32_t base = Ipv4Addr(100, 115, 92, 0);
  struct {
    int prefix_len;
    uint32_t want;
  } test_cases[] = {
      {24, Ipv4Addr(100, 115, 92, 255)},
      {29, Ipv4Addr(100, 115, 92, 7)},
      {30, Ipv4Addr(100, 115, 92, 3)},
      {31, Ipv4Addr(100, 115, 92, 1)},
  };

  for (const auto& t : test_cases) {
    EXPECT_EQ(Ipv4BroadcastAddr(base, t.prefix_len), t.want);
  }
}

TEST(IPv4, SetSockaddrIn) {
  struct sockaddr_storage sockaddr = {};
  std::ostringstream stream;

  SetSockaddrIn((struct sockaddr*)&sockaddr, {});
  stream << sockaddr;
  EXPECT_EQ("{family: AF_INET, port: 0, addr: 0.0.0.0}", stream.str());

  stream.str("");
  SetSockaddrIn((struct sockaddr*)&sockaddr,
                net_base::IPv4Address(192, 168, 1, 37));
  stream << sockaddr;
  EXPECT_EQ("{family: AF_INET, port: 0, addr: 192.168.1.37}", stream.str());
}

TEST(IpFamily, GetIpFamily) {
  struct {
    std::string ip_address;
    sa_family_t family;
  } test_cases[] = {
      {"0.0.0.0", AF_INET},
      {"100.115.92.6", AF_INET},
      {"255.255.255.255", AF_INET},
      {"::", AF_INET6},
      {"fe80::", AF_INET6},
      {"fe80::f699:9fff:fef4:4fe4", AF_INET6},
      {"", AF_UNSPEC},
      {"1234", AF_UNSPEC},
      {"0.0.0.0/0", AF_UNSPEC},
      {"1.1.1.256", AF_UNSPEC},
      {"fe80:f699:9fff:fef4:4fe4", AF_UNSPEC},
      {"fg80::", AF_UNSPEC},
  };

  for (const auto& t : test_cases) {
    EXPECT_EQ(GetIpFamily(t.ip_address), t.family);
  }
}

TEST(PrettyPrint, SocketAddrIn) {
  struct sockaddr_in ipv4_sockaddr = {};
  std::ostringstream stream;

  stream << ipv4_sockaddr;
  EXPECT_EQ("{family: AF_INET, port: 0, addr: 0.0.0.0}", stream.str());

  ipv4_sockaddr.sin_family = AF_INET;
  ipv4_sockaddr.sin_port = htons(1234);
  ipv4_sockaddr.sin_addr.s_addr = Ipv4Addr(100, 115, 92, 10);
  std::string expected_output =
      "{family: AF_INET, port: 1234, addr: 100.115.92.10}";

  stream.str("");
  stream << ipv4_sockaddr;
  EXPECT_EQ(expected_output, stream.str());

  stream.str("");
  stream << (const struct sockaddr&)ipv4_sockaddr;
  EXPECT_EQ(expected_output, stream.str());

  struct sockaddr_storage sockaddr_storage = {};
  memcpy(&sockaddr_storage, &ipv4_sockaddr, sizeof(ipv4_sockaddr));

  stream.str("");
  stream << sockaddr_storage;
  EXPECT_EQ(expected_output, stream.str());
}

TEST(PrettyPrint, SocketAddrIn6) {
  struct sockaddr_in6 ipv6_sockaddr = {};
  std::ostringstream stream;

  stream << ipv6_sockaddr;
  EXPECT_EQ("{family: AF_INET6, port: 0, addr: ::}", stream.str());

  ipv6_sockaddr.sin6_family = AF_INET6;
  ipv6_sockaddr.sin6_port = htons(2345);
  unsigned char addr[16] = {0x20, 0x01, 0xd,  0xb1, 0,    0,    0,    0,
                            0xab, 0xcd, 0x12, 0x34, 0x56, 0x78, 0xfe, 0xaa};
  memcpy(ipv6_sockaddr.sin6_addr.s6_addr, addr, sizeof(addr));
  std::string expected_output =
      "{family: AF_INET6, port: 2345, addr: 2001:db1::abcd:1234:5678:feaa}";

  stream.str("");
  stream << ipv6_sockaddr;
  EXPECT_EQ(expected_output, stream.str());

  stream.str("");
  stream << (const struct sockaddr&)ipv6_sockaddr;
  EXPECT_EQ(expected_output, stream.str());

  struct sockaddr_storage sockaddr_storage = {};
  memcpy(&sockaddr_storage, &ipv6_sockaddr, sizeof(ipv6_sockaddr));

  stream.str("");
  stream << sockaddr_storage;
  EXPECT_EQ(expected_output, stream.str());
}

TEST(PrettyPrint, SocketAddrVsock) {
  struct sockaddr_vm vm_sockaddr = {};
  std::ostringstream stream;

  stream << vm_sockaddr;
  EXPECT_EQ("{family: AF_VSOCK, port: 0, cid: 0}", stream.str());

  vm_sockaddr.svm_family = AF_VSOCK;
  vm_sockaddr.svm_port = 5555;
  vm_sockaddr.svm_cid = 4;
  std::string expected_output = "{family: AF_VSOCK, port: 5555, cid: 4}";

  stream.str("");
  stream << vm_sockaddr;
  EXPECT_EQ(expected_output, stream.str());

  stream.str("");
  stream << (const struct sockaddr&)vm_sockaddr;
  EXPECT_EQ(expected_output, stream.str());

  struct sockaddr_storage sockaddr_storage = {};
  memcpy(&sockaddr_storage, &vm_sockaddr, sizeof(vm_sockaddr));

  stream.str("");
  stream << sockaddr_storage;
  EXPECT_EQ(expected_output, stream.str());
}

TEST(PrettyPrint, SocketAddrUnix) {
  struct sockaddr_un unix_sockaddr = {};
  std::ostringstream stream;

  stream << unix_sockaddr;
  EXPECT_EQ("{family: AF_UNIX, path: @}", stream.str());

  // Fill |sun_path| with an invalid non-null-terminated c string.
  std::string bogus_output = "{family: AF_UNIX, path: ";
  for (size_t i = 0; i < sizeof(unix_sockaddr.sun_path); i++) {
    unix_sockaddr.sun_path[i] = 'a';
    bogus_output += 'a';
  }
  bogus_output += '}';
  stream.str("");
  stream << unix_sockaddr;
  EXPECT_EQ(bogus_output, stream.str());

  memset(&unix_sockaddr, 0, sizeof(unix_sockaddr));
  unix_sockaddr.sun_family = AF_UNIX;
  std::string sun_path = "/run/arc/adb";
  memcpy(&unix_sockaddr.sun_path, sun_path.c_str(), strlen(sun_path.c_str()));
  std::string expected_output = "{family: AF_UNIX, path: /run/arc/adb}";

  stream.str("");
  stream << unix_sockaddr;
  EXPECT_EQ(expected_output, stream.str());

  stream.str("");
  stream << (const struct sockaddr&)unix_sockaddr;
  EXPECT_EQ(expected_output, stream.str());

  struct sockaddr_storage sockaddr_storage = {};
  memcpy(&sockaddr_storage, &unix_sockaddr, sizeof(unix_sockaddr));

  stream.str("");
  stream << sockaddr_storage;
  EXPECT_EQ(expected_output, stream.str());
}

TEST(PrettyPrint, Rtentry) {
  struct rtentry route;
  memset(&route, 0, sizeof(route));
  std::ostringstream stream;

  stream << route;
  EXPECT_EQ(
      "{rt_dst: {unset}, rt_genmask: {unset}, rt_gateway: {unset}, rt_dev: "
      "null, rt_flags: 0}",
      stream.str());

  SetSockaddrIn(&route.rt_dst, net_base::IPv4Address(100, 115, 92, 128));
  SetSockaddrIn(&route.rt_genmask, net_base::IPv4Address(255, 255, 255, 252));
  SetSockaddrIn(&route.rt_gateway, net_base::IPv4Address(192, 168, 1, 1));
  std::string rt_dev = "eth0";
  route.rt_dev = const_cast<char*>(rt_dev.c_str());
  route.rt_flags =
      RTF_UP | RTF_GATEWAY | RTF_DYNAMIC | RTF_MODIFIED | RTF_REJECT;
  stream.str("");
  stream << route;
  EXPECT_EQ(
      "{rt_dst: {family: AF_INET, port: 0, addr: 100.115.92.128}, rt_genmask: "
      "{family: AF_INET, port: 0, addr: 255.255.255.252}, rt_gateway: {family: "
      "AF_INET, port: 0, addr: 192.168.1.1}, rt_dev: eth0, rt_flags: RTF_UP | "
      "RTF_GATEWAY | RTF_DYNAMIC | RTF_MODIFIED | RTF_REJECT}",
      stream.str());
}

}  // namespace patchpanel
