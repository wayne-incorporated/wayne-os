// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <arpa/inet.h>
#include <stdint.h>

#include <algorithm>
#include <deque>
#include <memory>
#include <random>
#include <string>
#include <utility>

#include <base/rand_util.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>

#include "patchpanel/subnet.h"
#include "patchpanel/subnet_pool.h"

using std::string;

namespace patchpanel {
namespace {
const net_base::IPv4CIDR kBaseCIDR =
    *net_base::IPv4CIDR::CreateFromCIDRString("100.115.92.24/30");
}  // namespace

TEST(SubnetPool, New_InvalidBaseCIDR) {
  const auto invalid_base_cidr =
      *net_base::IPv4CIDR::CreateFromCIDRString("192.168.1.1/30");
  auto pool = SubnetPool::New(invalid_base_cidr, 1);
  EXPECT_TRUE(pool == nullptr);
}

// Tests cannot create a pool with more than 32 supported subnets.
TEST(SubnetPool, New_InvalidMaxSubnets) {
  auto pool = SubnetPool::New(kBaseCIDR, 33);
  EXPECT_TRUE(pool == nullptr);
}

TEST(SubnetPool, Allocate) {
  auto pool = SubnetPool::New(kBaseCIDR, kMaxSubnets);

  auto subnet = pool->Allocate(1);
  EXPECT_EQ(subnet->base_cidr().ToString(), "100.115.92.24/30");
  subnet = pool->Allocate(2);
  EXPECT_EQ(subnet->base_cidr().ToString(), "100.115.92.28/30");
  subnet = pool->Allocate(3);
  EXPECT_EQ(subnet->base_cidr().ToString(), "100.115.92.32/30");
  subnet = pool->Allocate(32);
  EXPECT_EQ(subnet->base_cidr().ToString(), "100.115.92.148/30");
}

// Tests that the SubnetPool does not allocate more than max subnets at a time.
TEST(SubnetPool, AllocationRange) {
  auto pool = SubnetPool::New(kBaseCIDR, kMaxSubnets);

  std::deque<std::unique_ptr<Subnet>> subnets;
  for (size_t i = 0; i < kMaxSubnets; ++i) {
    auto subnet = pool->Allocate();
    ASSERT_TRUE(subnet);

    subnets.emplace_back(std::move(subnet));
  }
  EXPECT_EQ(subnets.size(), kMaxSubnets);
  EXPECT_FALSE(pool->Allocate());
}

// Tests that subnets are properly released and reused.
TEST(SubnetPool, Release) {
  auto pool = SubnetPool::New(kBaseCIDR, kMaxSubnets);

  // First allocate all the subnets.
  std::deque<std::unique_ptr<Subnet>> subnets;
  for (size_t i = 0; i < kMaxSubnets; ++i) {
    auto subnet = pool->Allocate();
    ASSERT_TRUE(subnet);

    subnets.emplace_back(std::move(subnet));
  }
  ASSERT_FALSE(pool->Allocate());

  // Now shuffle the elements.
  std::shuffle(subnets.begin(), subnets.end(),
               std::mt19937(static_cast<uint32_t>(base::RandUint64())));

  // Pop off the first element.
  auto subnet = std::move(subnets.front());
  subnets.pop_front();

  // Store the gateway and address for testing later.
  const auto base_cidr = subnet->base_cidr();

  // Release the subnet.
  subnet.reset();

  // Get a new subnet.
  subnet = pool->Allocate();
  ASSERT_TRUE(subnet);

  EXPECT_EQ(base_cidr, subnet->base_cidr());
}

TEST(SubnetPool, Index) {
  auto pool = SubnetPool::New(kBaseCIDR, kMaxSubnets);
  auto subnet = pool->Allocate(1);
  ASSERT_TRUE(subnet);
  EXPECT_FALSE(pool->Allocate(1));
  EXPECT_TRUE(pool->Allocate(0));
  EXPECT_TRUE(pool->Allocate());
  EXPECT_TRUE(pool->Allocate(2));
  EXPECT_TRUE(pool->Allocate(kMaxSubnets));
  subnet.reset();
  EXPECT_TRUE(pool->Allocate(1));
  EXPECT_FALSE(pool->Allocate(kMaxSubnets + 1));
}

}  // namespace patchpanel
