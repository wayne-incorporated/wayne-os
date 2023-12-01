// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/analytics/registry.h"

#include <memory>
#include <utility>

#include <base/test/task_environment.h>
#include <base/time/time.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "missive/analytics/resource_collector_mock.h"

using ::testing::AnyNumber;
using ::testing::Assign;

namespace reporting::analytics {

class RegistryTest : public ::testing::Test {
 protected:
  base::test::TaskEnvironment task_environment_;
};

TEST_F(RegistryTest, RegisterAndUnregister) {
  Registry registry;
  // Nothing can be removed from an empty registry
  ASSERT_FALSE(registry.Remove("nonexisting"));
  // Add two collectors and set up their destructor flags. We use these
  // destructor flags because the behavior of interleaving EXPECT_CALL within
  // the test is undefined by gtest.
  auto first_collector =
      std::make_unique<ResourceCollectorMock>(base::Seconds(40));
  bool first_collector_destructed = false;
  EXPECT_CALL(*first_collector, Destruct())
      .Times(1)
      .WillOnce(Assign(&first_collector_destructed, true));
  registry.Add("first-collector", std::move(first_collector));
  auto second_collector =
      std::make_unique<ResourceCollectorMock>(base::Minutes(30));
  bool second_collector_destructed = false;
  EXPECT_CALL(*second_collector, Destruct())
      .Times(1)
      .WillOnce(Assign(&second_collector_destructed, true));
  registry.Add("second-collector", std::move(second_collector));

  // Can't remove a collector that was not added
  ASSERT_FALSE(registry.Remove("third-collector"));
  // Remove an added collector
  ASSERT_FALSE(first_collector_destructed)
      << "first-collector is not yet removed but is destructed";
  ASSERT_TRUE(registry.Remove("first-collector"));
  ASSERT_TRUE(first_collector_destructed)
      << "first-collector is removed but is not destructed";
  // Can't remove the same collector twice
  ASSERT_FALSE(registry.Remove("first-collector"));
  // replacing the second collector
  ASSERT_FALSE(second_collector_destructed)
      << "second-collector is not yet replaced but is destructed";
  auto additional_collector =
      std::make_unique<ResourceCollectorMock>(base::Minutes(100));
  // We are not interested in destructor called by additional_collector
  EXPECT_CALL(*additional_collector, Destruct()).Times(AnyNumber());
  registry.Add("second-collector", std::move(additional_collector));
  ASSERT_TRUE(second_collector_destructed)
      << "second-collector is replaced but is not destructed";
}
}  // namespace reporting::analytics
