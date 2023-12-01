// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <arpa/inet.h>

#include <iterator>
#include <tuple>
#include <utility>
#include <vector>

#include <base/check.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/net/byte_string.h"
#include "shill/net/ip_address.h"

using testing::Eq;
using testing::Optional;
using testing::Test;

namespace shill {

namespace {
const char kV4String1[] = "192.168.10.1";
const unsigned char kV4Address1[] = {192, 168, 10, 1};
const char kV4String2[] = "192.168.10";
const unsigned char kV4Address2[] = {192, 168, 10};
const char kV6String1[] = "fe80::1aa9:5ff:7ebf:14c5";
const unsigned char kV6Address1[] = {0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x1a, 0xa9, 0x05, 0xff,
                                     0x7e, 0xbf, 0x14, 0xc5};
const char kV6String2[] = "1980:0:1000:1b02:1aa9:5ff:7ebf";
const unsigned char kV6Address2[] = {0x19, 0x80, 0x00, 0x00, 0x10, 0x00, 0x1b,
                                     0x02, 0x1a, 0xa9, 0x05, 0xff, 0x7e, 0xbf};

IPAddress::Family FlipFamily(IPAddress::Family f) {
  switch (f) {
    case IPAddress::kFamilyIPv4:
      return IPAddress::kFamilyIPv6;
    case IPAddress::kFamilyIPv6:
      return IPAddress::kFamilyIPv4;
    default:
      return IPAddress::kFamilyUnknown;
  }
}
}  // namespace

class IPAddressTest : public Test {
 protected:
  void TestAddress(IPAddress::Family family,
                   const std::string& good_string,
                   const ByteString& good_bytes,
                   const std::string& bad_string,
                   const ByteString& bad_bytes) {
    auto optional_result = IPAddress::CreateFromString(good_string, family);
    ASSERT_TRUE(optional_result.has_value());
    const IPAddress& good_addr = *optional_result;

    EXPECT_EQ(IPAddress::GetAddressLength(family), good_addr.GetLength());
    EXPECT_EQ(family, good_addr.family());
    EXPECT_FALSE(good_addr.IsDefault());
    EXPECT_EQ(0, memcmp(good_addr.GetConstData(), good_bytes.GetConstData(),
                        good_bytes.GetLength()));
    EXPECT_TRUE(good_addr.address().Equals(good_bytes));
    std::string address_string;
    EXPECT_TRUE(good_addr.IntoString(&address_string));
    EXPECT_EQ(good_string, address_string);

    EXPECT_THAT(IPAddress::CreateFromByteString(family, good_bytes),
                Optional(good_addr));
    EXPECT_THAT(IPAddress::CreateFromByteString(FlipFamily(family), good_bytes),
                std::nullopt);
    EXPECT_THAT(IPAddress::CreateFromString(good_string, family),
                Optional(good_addr));
    EXPECT_THAT(IPAddress::CreateFromStringAndPrefix(good_string, 0, family),
                Optional(good_addr));
    EXPECT_EQ(IPAddress::CreateFromString(good_string, FlipFamily(family)),
              std::nullopt);

    EXPECT_EQ(IPAddress::CreateFromString(bad_string), std::nullopt);
    EXPECT_EQ(IPAddress::CreateFromString(bad_string, family), std::nullopt);
    EXPECT_EQ(IPAddress::CreateFromByteString(family, bad_bytes), std::nullopt);
  }
};

TEST_F(IPAddressTest, Statics) {
  EXPECT_EQ(4, IPAddress::GetAddressLength(IPAddress::kFamilyIPv4));
  EXPECT_EQ(16, IPAddress::GetAddressLength(IPAddress::kFamilyIPv6));

  EXPECT_EQ(
      0, IPAddress::GetPrefixLengthFromMask(IPAddress::kFamilyIPv4, "0.0.0.0"));
  EXPECT_EQ(20, IPAddress::GetPrefixLengthFromMask(IPAddress::kFamilyIPv4,
                                                   "255.255.240.0"));
  EXPECT_EQ(32, IPAddress::GetPrefixLengthFromMask(IPAddress::kFamilyIPv4,
                                                   "255.255.255.255"));
  EXPECT_EQ(32, IPAddress::GetPrefixLengthFromMask(IPAddress::kFamilyIPv4, ""));
  EXPECT_EQ(32,
            IPAddress::GetPrefixLengthFromMask(IPAddress::kFamilyIPv4, "foo"));

  IPAddress addr4 = IPAddress::CreateFromFamily(IPAddress::kFamilyIPv4);

  EXPECT_EQ(4, addr4.GetLength());
  EXPECT_EQ(IPAddress::kFamilyIPv4, addr4.family());
  EXPECT_TRUE(addr4.IsDefault());
  EXPECT_TRUE(addr4.address().IsZero());
  EXPECT_TRUE(addr4.address().Equals(ByteString(4)));

  IPAddress addr6 = IPAddress::CreateFromFamily(IPAddress::kFamilyIPv6);

  EXPECT_EQ(16, addr6.GetLength());
  EXPECT_EQ(addr6.family(), IPAddress::kFamilyIPv6);
  EXPECT_TRUE(addr6.IsDefault());
  EXPECT_TRUE(addr6.address().IsZero());
  EXPECT_TRUE(addr6.address().Equals(ByteString(16)));

  EXPECT_FALSE(addr4.Equals(addr6));
}

TEST_F(IPAddressTest, IPv4) {
  TestAddress(IPAddress::kFamilyIPv4, kV4String1,
              ByteString(kV4Address1, sizeof(kV4Address1)), kV4String2,
              ByteString(kV4Address2, sizeof(kV4Address2)));
}

TEST_F(IPAddressTest, IPv6) {
  TestAddress(IPAddress::kFamilyIPv6, kV6String1,
              ByteString(kV6Address1, sizeof(kV6Address1)), kV6String2,
              ByteString(kV6Address2, sizeof(kV6Address2)));
}

TEST_F(IPAddressTest, CreateFromPrefixString) {
  // Makes the error message to know which string returns false in loop.
  auto error = [](const std::string& address) {
    return "input address is " + address;
  };

  // Tests for strings like IPv4 (e.g. 192.168.10.10/0, 192.168.10.10/-1).
  const std::string kIPv4String(kV4String1);

  // Checks if CreateFromPrefixString() returns true by valid strings for IPv4.
  ByteString kIPv4Address(kV4Address1, sizeof(kV4Address1));
  for (int prefix = 0; prefix < 33; prefix++) {
    const std::string input = kIPv4String + "/" + std::to_string(prefix);
    auto addr = IPAddress::CreateFromPrefixString(input);
    ASSERT_TRUE(addr.has_value()) << error(input);
    EXPECT_TRUE(addr->IsValid()) << error(input);
    EXPECT_EQ(IPAddress::kFamilyIPv4, addr->family()) << error(input);
    EXPECT_EQ(prefix, addr->prefix()) << error(input);
    EXPECT_TRUE(kIPv4Address.Equals(addr->address())) << error(input);

    // Specifying correct |family| should also work.
    addr = IPAddress::CreateFromPrefixString(input, IPAddress::kFamilyIPv4);
    EXPECT_TRUE(addr.has_value());
    addr = IPAddress::CreateFromPrefixString(input, IPAddress::kFamilyIPv6);
    EXPECT_FALSE(addr.has_value());
  }
  // Checks if CreateFromPrefixString() returns false by invalid strings for
  // IPv4.
  const std::vector<std::string> ipv4_invalid_cases = {"",
                                                       "192.168.10/10",
                                                       kIPv4String,
                                                       kIPv4String + "/",
                                                       kIPv4String + "/10x",
                                                       kIPv4String + "/33",
                                                       kIPv4String + "/-1"};
  for (const auto& input : ipv4_invalid_cases) {
    const auto addr = IPAddress::CreateFromPrefixString(input);
    EXPECT_FALSE(addr.has_value()) << error(input);
  }

  // Tests for strings like IPv6
  // (e.g. fe80::1aa9:5ff:7ebf:14c5/0, fe80::1aa9:5ff:7ebf:14c5/-1).
  const std::string kIPv6String(kV6String1);

  // Checks if CreateFromPrefixString() returns true by valid strings for IPv6.
  ByteString kIPv6Address(kV6Address1, sizeof(kV6Address1));
  for (int prefix = 0; prefix < 129; prefix++) {
    const std::string input = kIPv6String + "/" + std::to_string(prefix);
    auto addr = IPAddress::CreateFromPrefixString(input);
    ASSERT_TRUE(addr.has_value()) << error(input);
    EXPECT_TRUE(addr->IsValid()) << error(input);
    EXPECT_EQ(IPAddress::kFamilyIPv6, addr->family()) << error(input);
    EXPECT_EQ(prefix, addr->prefix()) << error(input);
    EXPECT_TRUE(kIPv6Address.Equals(addr->address())) << error(input);

    // Specifying correct |family| should also work.
    addr = IPAddress::CreateFromPrefixString(input, IPAddress::kFamilyIPv6);
    EXPECT_TRUE(addr.has_value());
    addr = IPAddress::CreateFromPrefixString(input, IPAddress::kFamilyIPv4);
    EXPECT_FALSE(addr.has_value());
  }
  // Checks if CreateFromPrefixString() returns false by invalid strings for
  // IPv6.
  const std::vector<std::string> ipv6_invalid_cases = {
      "",
      "1980:0:1000:1b02:1aa9:5ff:7ebf/64",
      kIPv6String,
      kIPv6String + "/",
      kIPv6String + "/64x",
      kIPv6String + "/129",
      kIPv6String + "/-1"};
  for (const auto& input : ipv6_invalid_cases) {
    const auto addr = IPAddress::CreateFromPrefixString(input);
    EXPECT_FALSE(addr.has_value()) << error(input);
  }
}

TEST_F(IPAddressTest, HasSameAddressAs) {
  const std::string kString1(kV4String1);
  IPAddress address0 = *IPAddress::CreateFromPrefixString(kString1 + "/0");
  IPAddress address1 = *IPAddress::CreateFromPrefixString(kString1 + "/10");
  IPAddress address2 = *IPAddress::CreateFromPrefixString(kString1 + "/0");

  EXPECT_FALSE(address0.Equals(address1));
  EXPECT_TRUE(address0.Equals(address2));
  EXPECT_TRUE(address0.HasSameAddressAs(address1));
  EXPECT_TRUE(address0.HasSameAddressAs(address2));
}

TEST_F(IPAddressTest, InvalidAddress) {
  EXPECT_EQ("<unknown>", IPAddress::CreateFromFamily_Deprecated(0).ToString());
  EXPECT_EQ("<unknown>",
            IPAddress::CreateFromFamily_Deprecated(IPAddress::kFamilyIPv4)
                .ToString());
  EXPECT_EQ("<unknown>",
            IPAddress::CreateFromFamily_Deprecated(IPAddress::kFamilyIPv6)
                .ToString());
}

struct PrefixMapping {
  PrefixMapping() : family(IPAddress::kFamilyUnknown), prefix(0) {}
  PrefixMapping(IPAddress::Family family_in,
                size_t prefix_in,
                const std::string& expected_address_in)
      : family(family_in),
        prefix(prefix_in),
        expected_address(expected_address_in) {}
  IPAddress::Family family;
  size_t prefix;
  std::string expected_address;
};

class IPAddressPrefixMappingTest
    : public testing::TestWithParam<PrefixMapping> {};

TEST_P(IPAddressPrefixMappingTest, TestPrefixMapping) {
  IPAddress address =
      IPAddress::GetAddressMaskFromPrefix(GetParam().family, GetParam().prefix);
  const auto expected_address = IPAddress::CreateFromString(
      GetParam().expected_address, GetParam().family);
  ASSERT_TRUE(expected_address.has_value());
  EXPECT_EQ(*expected_address, address);
}

INSTANTIATE_TEST_SUITE_P(
    IPAddressPrefixMappingTestRun,
    IPAddressPrefixMappingTest,
    ::testing::Values(
        PrefixMapping(IPAddress::kFamilyIPv4, 0, "0.0.0.0"),
        PrefixMapping(IPAddress::kFamilyIPv4, 1, "128.0.0.0"),
        PrefixMapping(IPAddress::kFamilyIPv4, 4, "240.0.0.0"),
        PrefixMapping(IPAddress::kFamilyIPv4, 7, "254.0.0.0"),
        PrefixMapping(IPAddress::kFamilyIPv4, 10, "255.192.0.0"),
        PrefixMapping(IPAddress::kFamilyIPv4, 13, "255.248.0.0"),
        PrefixMapping(IPAddress::kFamilyIPv4, 16, "255.255.0.0"),
        PrefixMapping(IPAddress::kFamilyIPv4, 19, "255.255.224.0"),
        PrefixMapping(IPAddress::kFamilyIPv4, 22, "255.255.252.0"),
        PrefixMapping(IPAddress::kFamilyIPv4, 25, "255.255.255.128"),
        PrefixMapping(IPAddress::kFamilyIPv4, 28, "255.255.255.240"),
        PrefixMapping(IPAddress::kFamilyIPv4, 31, "255.255.255.254"),
        PrefixMapping(IPAddress::kFamilyIPv4, 32, "255.255.255.255"),
        PrefixMapping(IPAddress::kFamilyIPv4, 33, "255.255.255.255"),
        PrefixMapping(IPAddress::kFamilyIPv4, 34, "255.255.255.255"),
        PrefixMapping(IPAddress::kFamilyIPv6, 0, "0::"),
        PrefixMapping(IPAddress::kFamilyIPv6, 1, "8000::"),
        PrefixMapping(IPAddress::kFamilyIPv6, 17, "ffff:8000::"),
        PrefixMapping(IPAddress::kFamilyIPv6, 34, "ffff:ffff:c000::"),
        PrefixMapping(IPAddress::kFamilyIPv6, 51, "ffff:ffff:ffff:e000::"),
        PrefixMapping(IPAddress::kFamilyIPv6, 68, "ffff:ffff:ffff:ffff:f000::"),
        PrefixMapping(IPAddress::kFamilyIPv6,
                      85,
                      "ffff:ffff:ffff:ffff:ffff:f800::"),
        PrefixMapping(IPAddress::kFamilyIPv6,
                      102,
                      "ffff:ffff:ffff:ffff:ffff:ffff:fc00::"),
        PrefixMapping(IPAddress::kFamilyIPv6,
                      119,
                      "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fe00"),
        PrefixMapping(IPAddress::kFamilyIPv6,
                      128,
                      "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        PrefixMapping(IPAddress::kFamilyIPv6,
                      136,
                      "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")));

struct NetworkPartMapping {
  NetworkPartMapping() : family(IPAddress::kFamilyUnknown) {}
  NetworkPartMapping(IPAddress::Family family_in,
                     const std::string& address_in,
                     size_t prefix_in,
                     const std::string& expected_network_in,
                     const std::string& expected_broadcast_in)
      : family(family_in),
        address(address_in),
        prefix(prefix_in),
        expected_network(expected_network_in),
        expected_broadcast(expected_broadcast_in) {}
  IPAddress::Family family;
  std::string address;
  size_t prefix;
  std::string expected_network;
  std::string expected_broadcast;
};

class IPAddressNetworkPartMappingTest
    : public testing::TestWithParam<NetworkPartMapping> {};

TEST_P(IPAddressNetworkPartMappingTest, TestNetworkPartMapping) {
  const auto address = IPAddress::CreateFromStringAndPrefix(
      GetParam().address, GetParam().prefix, GetParam().family);
  ASSERT_TRUE(address.has_value());
  const auto expected_network = IPAddress::CreateFromStringAndPrefix(
      GetParam().expected_network, GetParam().prefix, GetParam().family);
  ASSERT_TRUE(expected_network.has_value());
  EXPECT_EQ(*expected_network, address->GetNetworkPart());

  const auto expected_broadcast = IPAddress::CreateFromString(
      GetParam().expected_broadcast, GetParam().family);
  ASSERT_TRUE(expected_broadcast.has_value());
  EXPECT_EQ(*expected_broadcast, address->GetDefaultBroadcast());

  const auto address2 = IPAddress::CreateFromStringAndPrefix(GetParam().address,
                                                             GetParam().prefix);
  ASSERT_TRUE(address2.has_value());
  EXPECT_EQ(*address2, *address);
}

INSTANTIATE_TEST_SUITE_P(
    IPAddressNetworkPartMappingTestRun,
    IPAddressNetworkPartMappingTest,
    ::testing::Values(
        NetworkPartMapping(IPAddress::kFamilyIPv4,
                           "255.255.255.255",
                           0,
                           "0.0.0.0",
                           "255.255.255.255"),
        NetworkPartMapping(IPAddress::kFamilyIPv4,
                           "255.255.255.255",
                           32,
                           "255.255.255.255",
                           "255.255.255.255"),
        NetworkPartMapping(IPAddress::kFamilyIPv4,
                           "255.255.255.255",
                           24,
                           "255.255.255.0",
                           "255.255.255.255"),
        NetworkPartMapping(IPAddress::kFamilyIPv4,
                           "255.255.255.255",
                           16,
                           "255.255.0.0",
                           "255.255.255.255"),
        NetworkPartMapping(
            IPAddress::kFamilyIPv4, "0.0.0.0", 0, "0.0.0.0", "255.255.255.255"),
        NetworkPartMapping(
            IPAddress::kFamilyIPv4, "0.0.0.0", 32, "0.0.0.0", "0.0.0.0"),
        NetworkPartMapping(
            IPAddress::kFamilyIPv4, "0.0.0.0", 24, "0.0.0.0", "0.0.0.255"),
        NetworkPartMapping(
            IPAddress::kFamilyIPv4, "0.0.0.0", 16, "0.0.0.0", "0.0.255.255"),
        NetworkPartMapping(IPAddress::kFamilyIPv4,
                           "192.168.1.1",
                           24,
                           "192.168.1.0",
                           "192.168.1.255"),
        NetworkPartMapping(IPAddress::kFamilyIPv4,
                           "10.1.0.1",
                           8,
                           "10.0.0.0",
                           "10.255.255.255")));

struct CanReachAddressMapping {
  CanReachAddressMapping(const std::string& address_a_in,
                         size_t prefix_a_in,
                         const std::string& address_b_in,
                         size_t prefix_b_in,
                         bool expected_result_in)
      : address_a(address_a_in),
        prefix_a(prefix_a_in),
        address_b(address_b_in),
        prefix_b(prefix_b_in),
        expected_result(expected_result_in) {}
  std::string address_a;
  size_t prefix_a;
  std::string address_b;
  size_t prefix_b;
  size_t expected_result;
};

class IPAddressCanReachAddressMappingTest
    : public testing::TestWithParam<CanReachAddressMapping> {};

TEST_P(IPAddressCanReachAddressMappingTest, TestCanReachAddressMapping) {
  const auto address_a = IPAddress::CreateFromStringAndPrefix(
      GetParam().address_a, GetParam().prefix_a);
  ASSERT_TRUE(address_a.has_value());
  const auto address_b = IPAddress::CreateFromStringAndPrefix(
      GetParam().address_b, GetParam().prefix_b);
  ASSERT_TRUE(address_b.has_value());
  EXPECT_EQ(GetParam().expected_result, address_a->CanReachAddress(*address_b));
}

INSTANTIATE_TEST_SUITE_P(
    IPAddressCanReachAddressMappingTestRun,
    IPAddressCanReachAddressMappingTest,
    ::testing::Values(
        CanReachAddressMapping("fe80:1000::", 16, "fe80:2000::", 16, true),
        CanReachAddressMapping("fe80:1000::", 16, "fe80:2000::", 32, true),
        CanReachAddressMapping("fe80:1000::", 32, "fe80:2000::", 16, false),
        CanReachAddressMapping("192.168.1.1", 24, "192.168.1.2", 24, true),
        CanReachAddressMapping("192.168.1.1", 24, "192.168.2.2", 24, false),
        CanReachAddressMapping("192.168.1.1", 16, "192.168.2.2", 24, true),
        CanReachAddressMapping("192.168.1.1", 24, "192.168.2.2", 16, false),
        CanReachAddressMapping("fe80:1000::", 16, "192.168.2.2", 16, false)));

namespace {

IPAddress CreateAndUnwrapIPAddress(const std::string& addr_str) {
  const auto ret = IPAddress::CreateFromString(addr_str);
  CHECK(ret.has_value()) << addr_str << "is not a valid IP";
  return *ret;
}

// The order which these addresses are declared is important.  They
// should be listed in ascending order.
const IPAddress kIPv4OrderedAddresses[] = {
    CreateAndUnwrapIPAddress("127.0.0.1"),
    CreateAndUnwrapIPAddress("192.168.1.1"),
    CreateAndUnwrapIPAddress("192.168.1.32"),
    CreateAndUnwrapIPAddress("192.168.2.1"),
    CreateAndUnwrapIPAddress("192.168.2.32"),
    CreateAndUnwrapIPAddress("255.255.255.255")};

const IPAddress kIPv6OrderedAddresses[] = {
    CreateAndUnwrapIPAddress("::1"),
    CreateAndUnwrapIPAddress("2401:fa00:480:c6::30"),
    CreateAndUnwrapIPAddress("2401:fa00:480:c6::1:10"),
    CreateAndUnwrapIPAddress("2401:fa00:480:f6::6"),
    CreateAndUnwrapIPAddress("2401:fa01:480:f6::1"),
    CreateAndUnwrapIPAddress("fe80:1000::"),
    CreateAndUnwrapIPAddress("ff02::1")};

}  // namespace

class IPAddressIPv4ComparisonTest
    : public testing::TestWithParam<std::tuple<size_t, size_t>> {};

class IPAddressIPv6ComparisonTest
    : public testing::TestWithParam<std::tuple<size_t, size_t>> {};

class IPAddressCrossComparisonTest
    : public testing::TestWithParam<std::tuple<size_t, size_t>> {};

TEST_P(IPAddressIPv4ComparisonTest, LessThanTest) {
  size_t i = std::get<0>(GetParam());
  size_t j = std::get<1>(GetParam());

  if (i < j) {
    EXPECT_LT(kIPv4OrderedAddresses[i], kIPv4OrderedAddresses[j]);
  } else {
    EXPECT_FALSE(kIPv4OrderedAddresses[i] < kIPv4OrderedAddresses[j]);
  }
}

TEST_P(IPAddressIPv6ComparisonTest, LessThanTest) {
  size_t i = std::get<0>(GetParam());
  size_t j = std::get<1>(GetParam());

  if (i < j) {
    EXPECT_LT(kIPv6OrderedAddresses[i], kIPv6OrderedAddresses[j]);
  } else {
    EXPECT_FALSE(kIPv6OrderedAddresses[i] < kIPv6OrderedAddresses[j]);
  }
}

TEST_P(IPAddressCrossComparisonTest, LessThanTest) {
  size_t i4 = std::get<0>(GetParam());
  size_t i6 = std::get<1>(GetParam());

  EXPECT_TRUE(kIPv4OrderedAddresses[i4] < kIPv6OrderedAddresses[i6]);
  EXPECT_FALSE(kIPv6OrderedAddresses[i6] < kIPv4OrderedAddresses[i4]);
}

INSTANTIATE_TEST_SUITE_P(
    ComparisonTest,
    IPAddressIPv4ComparisonTest,
    testing::Combine(
        testing::Range<size_t>(0, std::size(kIPv4OrderedAddresses) - 1),
        testing::Range<size_t>(0, std::size(kIPv4OrderedAddresses) - 1)));

INSTANTIATE_TEST_SUITE_P(
    ComparisonTest,
    IPAddressIPv6ComparisonTest,
    testing::Combine(
        testing::Range<size_t>(0, std::size(kIPv6OrderedAddresses) - 1),
        testing::Range<size_t>(0, std::size(kIPv6OrderedAddresses) - 1)));

INSTANTIATE_TEST_SUITE_P(
    ComparisonTest,
    IPAddressCrossComparisonTest,
    testing::Combine(
        testing::Range<size_t>(0, std::size(kIPv4OrderedAddresses) - 1),
        testing::Range<size_t>(0, std::size(kIPv6OrderedAddresses) - 1)));

TEST(IPAddressMoveTest, MoveConstructor) {
  const IPAddress const_address = CreateAndUnwrapIPAddress(kV4String1);
  IPAddress source_address = CreateAndUnwrapIPAddress(kV4String1);
  EXPECT_EQ(const_address, source_address);

  const IPAddress dest_address(std::move(source_address));
  EXPECT_EQ(source_address.GetLength(), 0);
  EXPECT_FALSE(source_address.IsValid());
  EXPECT_EQ(const_address, dest_address);
}

TEST(IPAddressMoveTest, MoveAssignmentOperator) {
  const IPAddress const_address = CreateAndUnwrapIPAddress(kV4String1);
  IPAddress source_address = CreateAndUnwrapIPAddress(kV4String1);
  IPAddress dest_address =
      IPAddress::CreateFromFamily_Deprecated(IPAddress::kFamilyIPv4);

  EXPECT_EQ(const_address, source_address);
  EXPECT_FALSE(const_address.Equals(dest_address));

  dest_address = std::move(source_address);
  EXPECT_EQ(source_address.GetLength(), 0);
  EXPECT_FALSE(source_address.IsValid());
  EXPECT_EQ(const_address, dest_address);
}

TEST(IPAddressConversionTest, IPv4Address) {
  const auto ipv4 = net_base::IPv4Address(192, 168, 2, 1);
  const auto ip = IPAddress(ipv4);
  EXPECT_TRUE(ip.IsValid());
  EXPECT_EQ(ip.prefix(), 0);
  EXPECT_EQ(ip.ToString(), "192.168.2.1");

  EXPECT_EQ(*ip.ToIPv4Address(), ipv4);
  EXPECT_FALSE(ip.ToIPv6Address());
  EXPECT_FALSE(ip.ToIPv6CIDR());
}

TEST(IPAddressConversionTest, IPv6Address) {
  const auto ipv6 = *net_base::IPv6Address::CreateFromString("::1");
  const auto ip = IPAddress(ipv6);
  EXPECT_TRUE(ip.IsValid());
  EXPECT_EQ(ip.prefix(), 0);
  EXPECT_EQ(ip.ToString(), "::1");

  EXPECT_EQ(*ip.ToIPv6Address(), ipv6);
  EXPECT_FALSE(ip.ToIPv4Address());
  EXPECT_FALSE(ip.ToIPv4CIDR());
}

TEST(IPAddressConversionTest, IPv4CIDR) {
  const auto cidr = *net_base::IPv4CIDR::CreateFromCIDRString("192.168.2.1/24");
  const auto ip = IPAddress(cidr);
  EXPECT_TRUE(ip.IsValid());
  EXPECT_EQ(ip.prefix(), 24);
  EXPECT_EQ(ip.ToString(), "192.168.2.1");

  EXPECT_EQ(*ip.ToIPv4CIDR(), cidr);
  EXPECT_FALSE(ip.ToIPv6Address());
  EXPECT_FALSE(ip.ToIPv6CIDR());
}

TEST(IPAddressConversionTest, IPv6CIDR) {
  const auto cidr = *net_base::IPv6CIDR::CreateFromCIDRString("::1/26");
  const auto ip = IPAddress(cidr);
  EXPECT_TRUE(ip.IsValid());
  EXPECT_EQ(ip.prefix(), 26);
  EXPECT_EQ(ip.ToString(), "::1");

  EXPECT_EQ(*ip.ToIPv6CIDR(), cidr);
  EXPECT_FALSE(ip.ToIPv4Address());
  EXPECT_FALSE(ip.ToIPv4CIDR());
}

TEST(IPAddressCreationTest, CreateFromFamily) {
  const auto ipv4 = IPAddress::CreateFromFamily(IPAddress::kFamilyIPv4);
  EXPECT_EQ(ipv4.family(), IPAddress::kFamilyIPv4);
  EXPECT_TRUE(ipv4.IsValid());
  EXPECT_TRUE(ipv4.IsDefault());

  const auto ipv6 = IPAddress::CreateFromFamily(IPAddress::kFamilyIPv6);
  EXPECT_EQ(ipv6.family(), IPAddress::kFamilyIPv6);
  EXPECT_TRUE(ipv6.IsValid());
  EXPECT_TRUE(ipv6.IsDefault());

  const auto unknown = IPAddress::CreateFromFamily(IPAddress::kFamilyUnknown);
  EXPECT_EQ(unknown.family(), IPAddress::kFamilyUnknown);
  EXPECT_FALSE(unknown.IsValid());
  EXPECT_TRUE(unknown.IsDefault());
}

}  // namespace shill
