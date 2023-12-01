// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net-base/ipv6_address.h"

#include <arpa/inet.h>

#include <array>

#include <base/logging.h>
#include <gtest/gtest.h>

namespace net_base {
namespace {

constexpr char kGoodString[] = "fe80::1aa9:5ff:7ebf:14c5";
constexpr IPv6Address::DataType kGoodData = {0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x1a, 0xa9, 0x05, 0xff,
                                             0x7e, 0xbf, 0x14, 0xc5};

TEST(IPv6AddressTest, DefaultConstructor) {
  constexpr IPv6Address default_addr;
  constexpr IPv6Address::DataType data{0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0, 0, 0, 0, 0, 0, 0};

  EXPECT_EQ(default_addr.data(), data);
}

TEST(IPv6AddressTest, Constructor) {
  // Constructed from std::array.
  constexpr IPv6Address address1(kGoodData);
  // Constructed from other instance.
  constexpr IPv6Address address2(address1);

  EXPECT_EQ(address1.data(), kGoodData);
  EXPECT_EQ(address1, address2);

  constexpr IPv6Address address3(0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
                                 0xff);
  EXPECT_EQ(address3.ToString(), "11:2233:4455:6677:8899:aabb:ccdd:eeff");
}

TEST(IPv6AddressTest, CreateFromString_Success) {
  const auto address = IPv6Address::CreateFromString(kGoodString);
  ASSERT_TRUE(address);
  EXPECT_EQ(address->data(), kGoodData);
}

TEST(IPv6AddressTest, ToString) {
  const IPv6Address address(kGoodData);
  EXPECT_EQ(address.ToString(), kGoodString);
  // Make sure std::ostream operator<<() works.
  LOG(INFO) << "address = " << address;
}

TEST(IPv6AddressTest, CreateFromString_Fail) {
  EXPECT_FALSE(IPv6Address::CreateFromString(""));
  EXPECT_FALSE(IPv6Address::CreateFromString("192.168.10.1"));
}

TEST(IPv6AddressTest, ToByteString) {
  const std::string expected = {
      static_cast<char>(0xfe), static_cast<char>(0x80), static_cast<char>(0x00),
      static_cast<char>(0x00), static_cast<char>(0x00), static_cast<char>(0x00),
      static_cast<char>(0x00), static_cast<char>(0x00), static_cast<char>(0x1a),
      static_cast<char>(0xa9), static_cast<char>(0x05), static_cast<char>(0xff),
      static_cast<char>(0x7e), static_cast<char>(0xbf), static_cast<char>(0x14),
      static_cast<char>(0xc5)};

  const IPv6Address address(kGoodData);
  EXPECT_EQ(address.ToByteString(), expected);
}

TEST(IPv4Address, In6Addr) {
  const struct in6_addr expected_addr = {
      {{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0xa9, 0x05, 0xff,
        0x7e, 0xbf, 0x14, 0xc5}}};
  const auto ipv6_addr = IPv6Address(expected_addr);
  EXPECT_EQ(ipv6_addr.ToString(), "fe80::1aa9:5ff:7ebf:14c5");

  const auto addr = ipv6_addr.ToIn6Addr();
  EXPECT_EQ(memcmp(&addr, &expected_addr, sizeof(addr)), 0);
}

TEST(IPv6AddressTest, CreateFromBytes) {
  const auto expected = IPv6Address(kGoodData);
  EXPECT_EQ(*IPv6Address::CreateFromBytes(kGoodData.data(), kGoodData.size()),
            expected);
}

TEST(IPv6AddressTest, IsZero) {
  const IPv6Address default_addr;
  EXPECT_TRUE(default_addr.IsZero());

  const IPv6Address address(kGoodData);
  EXPECT_FALSE(address.IsZero());
}

TEST(IPv6AddressTest, Order) {
  const IPv6Address kOrderedAddresses[] = {
      *IPv6Address::CreateFromString("::1"),
      *IPv6Address::CreateFromString("2401:fa00:480:c6::30"),
      *IPv6Address::CreateFromString("2401:fa00:480:c6::1:10"),
      *IPv6Address::CreateFromString("2401:fa00:480:f6::6"),
      *IPv6Address::CreateFromString("2401:fa01:480:f6::1"),
      *IPv6Address::CreateFromString("fe80:1000::"),
      *IPv6Address::CreateFromString("ff02::1")};

  for (size_t i = 0; i < std::size(kOrderedAddresses); ++i) {
    for (size_t j = 0; j < std::size(kOrderedAddresses); ++j) {
      if (i < j) {
        EXPECT_TRUE(kOrderedAddresses[i] < kOrderedAddresses[j]);
      } else {
        EXPECT_FALSE(kOrderedAddresses[i] < kOrderedAddresses[j]);
      }
    }
  }
}

TEST(IPv6CIDR, CreateFromCIDRString) {
  const auto address = *IPv6Address::CreateFromString("2401:fa00:480:c6::30");
  const auto cidr1 = IPv6CIDR::CreateFromCIDRString("2401:fa00:480:c6::30/0");
  ASSERT_TRUE(cidr1);
  EXPECT_EQ(cidr1->address(), address);
  EXPECT_EQ(cidr1->prefix_length(), 0);

  const auto cidr2 = IPv6CIDR::CreateFromCIDRString("2401:fa00:480:c6::30/25");
  ASSERT_TRUE(cidr2);
  EXPECT_EQ(cidr2->address(), address);
  EXPECT_EQ(cidr2->prefix_length(), 25);

  const auto cidr3 = IPv6CIDR::CreateFromCIDRString("2401:fa00:480:c6::30/128");
  ASSERT_TRUE(cidr3);
  EXPECT_EQ(cidr3->address(), address);
  EXPECT_EQ(cidr3->prefix_length(), 128);

  const auto cidr4 = IPv6CIDR::CreateFromCIDRString("2401:fa00:480:c6::30");
  ASSERT_TRUE(cidr4);
  EXPECT_EQ(cidr4->address(), address);
  EXPECT_EQ(cidr4->prefix_length(), 128);
}

TEST(IPv6CIDR, CreateFromCIDRString_Fail) {
  EXPECT_FALSE(IPv6CIDR::CreateFromCIDRString("192.168.10.1"));
  EXPECT_FALSE(IPv6CIDR::CreateFromCIDRString("192.168.10.1/24"));
  EXPECT_FALSE(IPv6CIDR::CreateFromCIDRString("2401:fa00:480:c6::30/-1"));
  EXPECT_FALSE(IPv6CIDR::CreateFromCIDRString("2401:fa00:480:c6::30/130"));
}

TEST(IPv6CIDR, CreateFromStringAndPrefix) {
  const std::string address_string = "fe80:1000::";
  const auto address = *IPv6Address::CreateFromString(address_string);

  const auto cidr1 = IPv6CIDR::CreateFromStringAndPrefix(address_string, 0);
  ASSERT_TRUE(cidr1);
  EXPECT_EQ(cidr1->address(), address);
  EXPECT_EQ(cidr1->prefix_length(), 0);

  const auto cidr2 = IPv6CIDR::CreateFromStringAndPrefix(address_string, 64);
  ASSERT_TRUE(cidr2);
  EXPECT_EQ(cidr2->address(), address);
  EXPECT_EQ(cidr2->prefix_length(), 64);

  const auto cidr3 = IPv6CIDR::CreateFromStringAndPrefix(address_string, 128);
  ASSERT_TRUE(cidr3);
  EXPECT_EQ(cidr3->address(), address);
  EXPECT_EQ(cidr3->prefix_length(), 128);
}

TEST(IPv6CIDR, CreateFromAddressAndPrefix) {
  const auto address = *IPv6Address::CreateFromString("::1");

  EXPECT_TRUE(IPv6CIDR::CreateFromAddressAndPrefix(address, 0));
  EXPECT_TRUE(IPv6CIDR::CreateFromAddressAndPrefix(address, 50));
  EXPECT_TRUE(IPv6CIDR::CreateFromAddressAndPrefix(address, 128));

  EXPECT_FALSE(IPv6CIDR::CreateFromAddressAndPrefix(address, 129));
  EXPECT_FALSE(IPv6CIDR::CreateFromAddressAndPrefix(address, -1));
}

TEST(IPv6CIDR, DefaultConstructor) {
  const IPv6CIDR default_cidr;
  EXPECT_EQ(default_cidr.address(), IPv6Address());
  EXPECT_EQ(default_cidr.prefix_length(), 0);

  const auto address = *IPv6Address::CreateFromString("::1");
  const auto cidr = IPv6CIDR(address);
  EXPECT_EQ(cidr.address(), address);
  EXPECT_EQ(cidr.prefix_length(), 0);
}

TEST(IPv6CIDR, GetPrefixAddress) {
  const auto cidr1 = *IPv6CIDR::CreateFromCIDRString("2401:fa00:480:f6::6/16");
  EXPECT_EQ(cidr1.GetPrefixAddress(), *IPv6Address::CreateFromString("2401::"));

  const auto cidr2 = *IPv6CIDR::CreateFromCIDRString("2401:fa00:480:f6::6/20");
  EXPECT_EQ(cidr2.GetPrefixAddress(),
            *IPv6Address::CreateFromString("2401:f000::"));

  const auto cidr3 = *IPv6CIDR::CreateFromCIDRString("2401:fa00:480:f6::6/0");
  EXPECT_EQ(cidr3.GetPrefixAddress(), *IPv6Address::CreateFromString("::"));

  const auto cidr4 = *IPv6CIDR::CreateFromCIDRString("2401:fa00:480:f6::6/128");
  EXPECT_EQ(cidr4.GetPrefixAddress(),
            *IPv6Address::CreateFromString("2401:fa00:480:f6::6"));
}

TEST(IPv6CIDR, InSameSubnetWith) {
  const auto cidr = *IPv6CIDR::CreateFromCIDRString("2401:fa00:480:f6::6/16");

  EXPECT_TRUE(cidr.InSameSubnetWith(*IPv6Address::CreateFromString("2401::")));
  EXPECT_TRUE(
      cidr.InSameSubnetWith(*IPv6Address::CreateFromString("2401:abc::")));
  EXPECT_TRUE(cidr.InSameSubnetWith(*IPv6Address::CreateFromString("2401::1")));

  EXPECT_FALSE(
      cidr.InSameSubnetWith(*IPv6Address::CreateFromString("2402::6")));
  EXPECT_FALSE(cidr.InSameSubnetWith(*IPv6Address::CreateFromString("::6")));
}

TEST(IPv6CIDR, ToString) {
  const std::string cidr_string = "2401:fa00:480:c6::1:10/24";
  const auto cidr = *IPv6CIDR::CreateFromCIDRString(cidr_string);
  EXPECT_EQ(cidr.ToString(), cidr_string);
  // Make sure std::ostream operator<<() works.
  LOG(INFO) << "cidr = " << cidr;
}

TEST(IPv6CIDR, GetNetmask) {
  EXPECT_EQ(*IPv6CIDR::GetNetmask(0), *IPv6Address::CreateFromString("::"));
  EXPECT_EQ(*IPv6CIDR::GetNetmask(4), *IPv6Address::CreateFromString("f000::"));
  EXPECT_EQ(*IPv6CIDR::GetNetmask(23),
            *IPv6Address::CreateFromString("ffff:fe00::"));
  EXPECT_EQ(*IPv6CIDR::GetNetmask(128),
            *IPv6Address::CreateFromString(
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));

  EXPECT_FALSE(IPv6CIDR::GetNetmask(-1));
  EXPECT_FALSE(IPv6CIDR::GetNetmask(129));
}

TEST(IPv6CIDR, ToNetmask) {
  const auto cidr1 = *IPv6CIDR::CreateFromCIDRString("2401:fa00::1/0");
  EXPECT_EQ(cidr1.ToNetmask(), *IPv6Address::CreateFromString("::"));

  const auto cidr2 = *IPv6CIDR::CreateFromCIDRString("2401:fa00::1/8");
  EXPECT_EQ(cidr2.ToNetmask(), *IPv6Address::CreateFromString("ff00::"));

  const auto cidr3 = *IPv6CIDR::CreateFromCIDRString("2401:fa00::1/24");
  EXPECT_EQ(cidr3.ToNetmask(), *IPv6Address::CreateFromString("ffff:ff00::"));
}

}  // namespace
}  // namespace net_base
