// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/subnet.h"

#include <arpa/inet.h>
#include <stdint.h>

#include <string>
#include <utility>
#include <vector>

#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/strings/string_util.h>
#include <gtest/gtest.h>

#include "patchpanel/net_util.h"

// TODO(akahuang): Change the unittest to concrete test cases, instead of using
// lots of calculation and for loop inside the test. (go/tott/643)

namespace patchpanel {
namespace {

constexpr net_base::IPv4Address kContainerBaseAddress(100, 115, 92, 192);
constexpr net_base::IPv4Address kVmBaseAddress(100, 115, 92, 24);
constexpr net_base::IPv4Address kParallelsBaseAddress(100, 115, 92, 128);

constexpr uint32_t kContainerSubnetPrefixLength = 28;
constexpr uint32_t kVmSubnetPrefixLength = 30;
constexpr uint32_t kParallelsSubnetPrefixLength = 28;

// kExpectedAvailableCount[i] == AvailableCount() for subnet with prefix_length
// i.
constexpr uint32_t kExpectedAvailableCount[] = {
    0xfffffffe, 0x7ffffffe, 0x3ffffffe, 0x1ffffffe, 0xffffffe, 0x7fffffe,
    0x3fffffe,  0x1fffffe,  0xfffffe,   0x7ffffe,   0x3ffffe,  0x1ffffe,
    0xffffe,    0x7fffe,    0x3fffe,    0x1fffe,    0xfffe,    0x7ffe,
    0x3ffe,     0x1ffe,     0xffe,      0x7fe,      0x3fe,     0x1fe,
    0xfe,       0x7e,       0x3e,       0x1e,       0xe,       0x6,
    0x2,        0x0,
};

class VmSubnetTest : public ::testing::TestWithParam<uint32_t> {};
class ContainerSubnetTest : public ::testing::TestWithParam<uint32_t> {};
class PrefixTest : public ::testing::TestWithParam<int> {};

void SetTrue(bool* value) {
  *value = true;
}

}  // namespace

TEST_P(VmSubnetTest, CIDRAtOffset) {
  uint32_t index = GetParam();
  Subnet subnet(
      *net_base::IPv4CIDR::CreateFromAddressAndPrefix(
          AddOffset(kVmBaseAddress, index * 4), kVmSubnetPrefixLength),
      base::DoNothing());

  for (uint32_t offset = 1; offset <= subnet.AvailableCount(); ++offset) {
    const auto expected_cidr = *net_base::IPv4CIDR::CreateFromAddressAndPrefix(
        AddOffset(kVmBaseAddress, index * 4 + offset), kVmSubnetPrefixLength);
    EXPECT_EQ(expected_cidr, subnet.CIDRAtOffset(offset));
  }
}

INSTANTIATE_TEST_SUITE_P(AllValues,
                         VmSubnetTest,
                         ::testing::Range(uint32_t{0}, uint32_t{26}));

TEST_P(ContainerSubnetTest, CIDRAtOffset) {
  uint32_t index = GetParam();
  Subnet subnet(*net_base::IPv4CIDR::CreateFromAddressAndPrefix(
                    AddOffset(kContainerBaseAddress, index * 16),
                    kContainerSubnetPrefixLength),
                base::DoNothing());

  for (uint32_t offset = 1; offset <= subnet.AvailableCount(); ++offset) {
    const auto expected_cidr = *net_base::IPv4CIDR::CreateFromAddressAndPrefix(
        AddOffset(kContainerBaseAddress, index * 16 + offset),
        kContainerSubnetPrefixLength);
    EXPECT_EQ(expected_cidr, subnet.CIDRAtOffset(offset));
  }
}

INSTANTIATE_TEST_SUITE_P(AllValues,
                         ContainerSubnetTest,
                         ::testing::Range(uint32_t{1}, uint32_t{4}));

TEST_P(PrefixTest, AvailableCount) {
  int prefix_length = GetParam();

  Subnet subnet(
      *net_base::IPv4CIDR::CreateFromAddressAndPrefix({}, prefix_length),
      base::DoNothing());
  EXPECT_EQ(kExpectedAvailableCount[prefix_length], subnet.AvailableCount());
}

INSTANTIATE_TEST_SUITE_P(AllValues, PrefixTest, ::testing::Range(8, 32));

TEST(SubtnetAddress, StringConversion) {
  Subnet container_subnet(
      *net_base::IPv4CIDR::CreateFromAddressAndPrefix(
          kContainerBaseAddress, kContainerSubnetPrefixLength),
      base::DoNothing());
  EXPECT_EQ("100.115.92.192/28", container_subnet.base_cidr().ToString());
  {
    EXPECT_EQ(*net_base::IPv4CIDR::CreateFromCIDRString("100.115.92.193/28"),
              container_subnet.AllocateAtOffset(1)->cidr());
    EXPECT_EQ(*net_base::IPv4CIDR::CreateFromCIDRString("100.115.92.194/28"),
              container_subnet.AllocateAtOffset(2)->cidr());
    EXPECT_EQ(*net_base::IPv4CIDR::CreateFromCIDRString("100.115.92.205/28"),
              container_subnet.AllocateAtOffset(13)->cidr());
    EXPECT_EQ(*net_base::IPv4CIDR::CreateFromCIDRString("100.115.92.206/28"),
              container_subnet.AllocateAtOffset(14)->cidr());
  }

  Subnet vm_subnet(*net_base::IPv4CIDR::CreateFromAddressAndPrefix(
                       kVmBaseAddress, kVmSubnetPrefixLength),
                   base::DoNothing());
  EXPECT_EQ("100.115.92.24/30", vm_subnet.base_cidr().ToString());
  {
    EXPECT_EQ(*net_base::IPv4CIDR::CreateFromCIDRString("100.115.92.25/30"),
              vm_subnet.AllocateAtOffset(1)->cidr());
    EXPECT_EQ(*net_base::IPv4CIDR::CreateFromCIDRString("100.115.92.26/30"),
              vm_subnet.AllocateAtOffset(2)->cidr());
  }

  Subnet parallels_subnet(
      *net_base::IPv4CIDR::CreateFromAddressAndPrefix(
          kParallelsBaseAddress, kParallelsSubnetPrefixLength),
      base::DoNothing());
  EXPECT_EQ("100.115.92.128/28", parallels_subnet.base_cidr().ToString());
  {
    EXPECT_EQ(*net_base::IPv4CIDR::CreateFromCIDRString("100.115.92.129/28"),
              parallels_subnet.AllocateAtOffset(1)->cidr());
    EXPECT_EQ(*net_base::IPv4CIDR::CreateFromCIDRString("100.115.92.130/28"),
              parallels_subnet.AllocateAtOffset(2)->cidr());
    EXPECT_EQ(*net_base::IPv4CIDR::CreateFromCIDRString("100.115.92.141/28"),
              parallels_subnet.AllocateAtOffset(13)->cidr());
    EXPECT_EQ(*net_base::IPv4CIDR::CreateFromCIDRString("100.115.92.142/28"),
              parallels_subnet.AllocateAtOffset(14)->cidr());
  }
}

// Tests that the Subnet runs the provided cleanup callback when it gets
// destroyed.
TEST(Subnet, Cleanup) {
  bool called = false;

  {
    Subnet subnet(*net_base::IPv4CIDR::CreateFromAddressAndPrefix({}, 24),
                  base::BindOnce(&SetTrue, &called));
  }

  EXPECT_TRUE(called);
}

// Tests that the subnet allows allocating all addresses in the subnet's range
// using an offset.
TEST(ParallelsSubnet, AllocateAtOffset) {
  Subnet subnet(*net_base::IPv4CIDR::CreateFromAddressAndPrefix(
                    kParallelsBaseAddress, kParallelsSubnetPrefixLength),
                base::DoNothing());

  std::vector<std::unique_ptr<SubnetAddress>> addrs;
  addrs.reserve(subnet.AvailableCount());

  for (uint32_t offset = 1; offset <= subnet.AvailableCount(); ++offset) {
    auto addr = subnet.AllocateAtOffset(offset);
    EXPECT_TRUE(addr);
    EXPECT_EQ(AddOffset(kParallelsBaseAddress, offset), addr->cidr().address());
    addrs.emplace_back(std::move(addr));
  }
}

// Tests that the subnet frees addresses when they are destroyed.
TEST(ParallelsSubnet, Free) {
  Subnet subnet(*net_base::IPv4CIDR::CreateFromAddressAndPrefix(
                    kParallelsBaseAddress, kParallelsSubnetPrefixLength),
                base::DoNothing());

  {
    auto addr = subnet.AllocateAtOffset(1);
    EXPECT_TRUE(addr);
  }

  EXPECT_TRUE(subnet.AllocateAtOffset(1));
}

}  // namespace patchpanel
