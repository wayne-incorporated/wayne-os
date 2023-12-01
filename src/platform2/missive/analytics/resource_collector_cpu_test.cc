// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/analytics/resource_collector_cpu.h"

#include <memory>
#include <string>

#include <base/test/task_environment.h>
#include <base/time/time.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "missive/analytics/metrics_test_util.h"

using ::testing::_;
using ::testing::Ge;
using ::testing::Return;

namespace reporting::analytics {

class ResourceCollectorCpuTest : public ::testing::Test {
 protected:
  class MockCpuUsageTallier : public ResourceCollectorCpu::CpuUsageTallier {
   public:
    MOCK_METHOD(StatusOr<uint64_t>, Tally, (), (override));
  };

  void SetUp() override {
  }

  void MockCpu() {
    resource_collector_.tallier_ = std::make_unique<MockCpuUsageTallier>();
  }

  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  // The time interval that resource collector is expected to collect resources
  const base::TimeDelta kInterval{base::Hours(1)};
  // Replace the metrics library instance with a mock one
  Metrics::TestEnvironment metrics_test_environment_;
  ResourceCollectorCpu resource_collector_{kInterval};
};

TEST_F(ResourceCollectorCpuTest, SuccessfullySendRealCpu) {
  // A simple test that runs in a real CPU environment that a non-negative
  // percentage is sent.
  // Proper data should be sent to UMA upon kInterval having elapsed
  EXPECT_CALL(Metrics::TestEnvironment::GetMockMetricsLibrary(),
              SendPercentageToUMA(
                  /*name=*/ResourceCollectorCpu::kUmaName,
                  /*sample=*/Ge(0)))
      .Times(1)
      .WillOnce(Return(true));
  task_environment_.FastForwardBy(kInterval);
  task_environment_.RunUntilIdle();
}

// Emulate errors when retrieving CPU usage from the system.
TEST_F(ResourceCollectorCpuTest, FailToSendMockCpu) {
  MockCpu();
  EXPECT_CALL(
      *static_cast<MockCpuUsageTallier*>(resource_collector_.tallier_.get()),
      Tally())
      .Times(1)
      .WillOnce(Return(Status(error::INTERNAL, "Some internal error")));
  // Proper data should be sent to UMA upon kInterval having elapsed
  EXPECT_CALL(Metrics::TestEnvironment::GetMockMetricsLibrary(),
              SendPercentageToUMA(_, _))
      .Times(0);
  task_environment_.FastForwardBy(kInterval);
  task_environment_.RunUntilIdle();
}

class ResourceCollectorCpuTestWithCpuPercentageParams
    : public ResourceCollectorCpuTest,
      public ::testing::WithParamInterface<uint64_t> {
 protected:
  uint64_t cpu_percentage() { return GetParam(); }
};

TEST_P(ResourceCollectorCpuTestWithCpuPercentageParams,
       SuccessfullySendMockCpu) {
  MockCpu();
  EXPECT_CALL(
      *static_cast<MockCpuUsageTallier*>(resource_collector_.tallier_.get()),
      Tally())
      .Times(1)
      .WillOnce(Return(cpu_percentage()));
  // Proper data should be sent to UMA upon kInterval having elapsed
  EXPECT_CALL(Metrics::TestEnvironment::GetMockMetricsLibrary(),
              SendPercentageToUMA(
                  /*name=*/ResourceCollectorCpu::kUmaName,
                  /*sample=*/static_cast<int>(cpu_percentage())))
      .Times(1)
      .WillOnce(Return(true));
  task_environment_.FastForwardBy(kInterval);
  task_environment_.RunUntilIdle();
}

INSTANTIATE_TEST_SUITE_P(VaryingCpuUsagePercentage,
                         ResourceCollectorCpuTestWithCpuPercentageParams,
                         testing::Values(0U,      // No CPU usage
                                         300U,    // CPU usage exceeding 100%
                                         40U,     // Normal CPU usage
                                         100U));  // 100%
}  // namespace reporting::analytics
