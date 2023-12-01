// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net-base/ip_address.h"

#include <gtest/gtest.h>

namespace net_base {
namespace {

TEST(IPAddressTest, IPv4Constructor) {
  constexpr IPv4Address ipv4_addr(192, 168, 10, 1);
  constexpr IPAddress address(ipv4_addr);

  EXPECT_EQ(address.GetFamily(), IPFamily::kIPv4);
  EXPECT_EQ(address.ToIPv4Address(), ipv4_addr);
  EXPECT_EQ(address.ToIPv6Address(), std::nullopt);
  EXPECT_EQ(address.ToString(), "192.168.10.1");
  EXPECT_EQ(address.ToByteString(), ipv4_addr.ToByteString());
}

TEST(IPAddressTest, IPv6Constructor) {
  constexpr IPv6Address ipv6_addr(0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                                  0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                                  0xee, 0xff);
  constexpr IPAddress address(ipv6_addr);

  EXPECT_EQ(address.GetFamily(), IPFamily::kIPv6);
  EXPECT_EQ(address.ToIPv4Address(), std::nullopt);
  EXPECT_EQ(address.ToIPv6Address(), ipv6_addr);
  EXPECT_EQ(address.ToString(), "11:2233:4455:6677:8899:aabb:ccdd:eeff");
  EXPECT_EQ(address.ToByteString(), ipv6_addr.ToByteString());
}

TEST(IPAddressTest, CreateFromString) {
  const auto ipv4_addr = *IPAddress::CreateFromString("192.168.10.1");
  EXPECT_EQ(ipv4_addr.GetFamily(), IPFamily::kIPv4);
  EXPECT_EQ(ipv4_addr.ToString(), "192.168.10.1");

  const auto ipv6_addr =
      *IPAddress::CreateFromString("11:2233:4455:6677:8899:aabb:ccdd:eeff");
  EXPECT_EQ(ipv6_addr.GetFamily(), IPFamily::kIPv6);
  EXPECT_EQ(ipv6_addr.ToString(), "11:2233:4455:6677:8899:aabb:ccdd:eeff");

  // Bad cases.
  EXPECT_EQ(std::nullopt, IPAddress::CreateFromString(""));
  EXPECT_EQ(std::nullopt, IPAddress::CreateFromString("192.168.10.1/10"));
  EXPECT_EQ(std::nullopt, IPAddress::CreateFromString("::1/10"));
}

TEST(IPAddressTest, CreateFromBytes) {
  constexpr uint8_t ipv4_bytes[4] = {192, 168, 10, 1};
  const auto ipv4_addr =
      *IPAddress::CreateFromBytes(ipv4_bytes, std::size(ipv4_bytes));
  EXPECT_EQ(ipv4_addr.GetFamily(), IPFamily::kIPv4);
  EXPECT_EQ(ipv4_addr.ToString(), "192.168.10.1");

  constexpr uint8_t ipv6_bytes[16] = {0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
                                      0x00, 0x00, 0x1a, 0xa9, 0x05, 0xff,
                                      0x7e, 0xbf, 0x14, 0xc5};
  const auto ipv6_addr =
      *IPAddress::CreateFromBytes(ipv6_bytes, std::size(ipv6_bytes));
  EXPECT_EQ(ipv6_addr.GetFamily(), IPFamily::kIPv6);
  EXPECT_EQ(ipv6_addr.ToString(), "fe80::1aa9:5ff:7ebf:14c5");
}

TEST(IPAddressTest, OperatorCmp) {
  const IPAddress kOrderedAddresses[] = {
      // We define that a IPv4 address is less than a IPv6 address.
      *IPAddress::CreateFromString("127.0.0.1"),
      *IPAddress::CreateFromString("192.168.1.1"),
      *IPAddress::CreateFromString("192.168.1.32"),
      *IPAddress::CreateFromString("192.168.2.1"),
      *IPAddress::CreateFromString("192.168.2.32"),
      *IPAddress::CreateFromString("255.255.255.255"),
      *IPAddress::CreateFromString("::1"),
      *IPAddress::CreateFromString("2401:fa00:480:c6::30"),
      *IPAddress::CreateFromString("2401:fa00:480:c6::1:10"),
      *IPAddress::CreateFromString("2401:fa00:480:f6::6"),
      *IPAddress::CreateFromString("2401:fa01:480:f6::1"),
      *IPAddress::CreateFromString("fe80:1000::"),
      *IPAddress::CreateFromString("ff02::1")};

  for (size_t i = 0; i < std::size(kOrderedAddresses); ++i) {
    for (size_t j = 0; j < std::size(kOrderedAddresses); ++j) {
      if (i < j) {
        EXPECT_TRUE(kOrderedAddresses[i] < kOrderedAddresses[j]);
        EXPECT_TRUE(kOrderedAddresses[i] != kOrderedAddresses[j]);
      } else {
        EXPECT_FALSE(kOrderedAddresses[i] < kOrderedAddresses[j]);
      }
    }
  }
}

}  // namespace
}  // namespace net_base
