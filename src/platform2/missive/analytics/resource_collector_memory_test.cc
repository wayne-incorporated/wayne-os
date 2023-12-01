// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/analytics/resource_collector_memory.h"

#include <cstddef>
#include <memory>

#include <base/memory/scoped_refptr.h>
#include <base/test/task_environment.h>
#include <base/time/time.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "missive/analytics/metrics_test_util.h"
#include "missive/resources/resource_manager.h"

using ::testing::Eq;
using ::testing::Return;

namespace reporting::analytics {

class ResourceCollectorMemoryTest : public ::testing::TestWithParam<uint64_t> {
 protected:
  void SetUp() override {
    // Set used memory
    resource_->Discard(resource_->GetUsed());  // discard all
    ASSERT_THAT(resource_->GetUsed(), Eq(0));
    ASSERT_TRUE(resource_->Reserve(used_memory()));
  }

  uint64_t used_memory() const { return GetParam(); }

  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  // The time interval that resource collector is expected to collect resources
  const base::TimeDelta kInterval{base::Seconds(20)};
  const scoped_refptr<ResourceManager> resource_{
      base::MakeRefCounted<ResourceManager>(4 * 1024U * 1024U)};
  Metrics::TestEnvironment metrics_test_environment_;
  ResourceCollectorMemory resource_collector_{kInterval, resource_};
};

TEST_P(ResourceCollectorMemoryTest, SuccessfullySend) {
  // Proper data should be sent to UMA upon kInterval having elapsed
  EXPECT_CALL(Metrics::TestEnvironment::GetMockMetricsLibrary(),
              SendLinearToUMA(
                  /*name=*/ResourceCollectorMemory::kUmaName,
                  /*sample=*/
                  ResourceCollectorMemory::ConvertBytesTo0_1Mibs(used_memory()),
                  /*max=*/ResourceCollectorMemory::kUmaMax))
      .Times(1)
      .WillOnce(Return(true));
  task_environment_.FastForwardBy(kInterval);
  task_environment_.RunUntilIdle();
}

INSTANTIATE_TEST_SUITE_P(VaryingUsedMemory,  // all values are in bytes
                         ResourceCollectorMemoryTest,
                         testing::Values(0U,    // No memory usage
                                         300U,  // Low memory usage
                                         2000U *
                                             1024U,  // Moderate memory usage
                                         4055U * 1024U));  // Large memory usage
}  // namespace reporting::analytics
