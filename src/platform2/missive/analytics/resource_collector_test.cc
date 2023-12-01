// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/analytics/resource_collector.h"

#include <base/test/task_environment.h>
#include <base/time/time.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "missive/analytics/metrics_test_util.h"
#include "missive/analytics/resource_collector_mock.h"

using testing::AnyNumber;

namespace reporting::analytics {

class ResourceCollectorTest : public ::testing::TestWithParam<base::TimeDelta> {
 protected:
  void SetUp() override {
    // Uninterested in ResourceCollectorMock::Destruct calls
    EXPECT_CALL(resource_collector_, Destruct()).Times(AnyNumber());
  }

  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  // The time interval that resource collector is expected to collect resources
  const base::TimeDelta interval_{GetParam()};
  Metrics::TestEnvironment metrics_test_environment_;
  ResourceCollectorMock resource_collector_{interval_};
};

TEST_P(ResourceCollectorTest, CallOnceInAWhile) {
  // Collect() should get called 3 times
  EXPECT_CALL(resource_collector_, Collect()).Times(3);
  // Time moving forward 3 * interval_
  task_environment_.FastForwardBy(3 * interval_);
  task_environment_.RunUntilIdle();
}

TEST_P(ResourceCollectorTest, DontCallIfTimeNotUp) {
  // Collect() should not be called
  EXPECT_CALL(resource_collector_, Collect()).Times(0);
  // Time moving forward half of interval_
  task_environment_.FastForwardBy(interval_ / 2);
  task_environment_.RunUntilIdle();
}

INSTANTIATE_TEST_SUITE_P(VaryingTimeInterval,
                         ResourceCollectorTest,
                         testing::Values(base::Minutes(10),
                                         base::Seconds(20),
                                         base::Hours(1)));
}  // namespace reporting::analytics
