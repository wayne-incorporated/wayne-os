// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/client/report_queue.h"

#include <base/functional/bind.h>
#include <base/strings/strcat.h>
#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "missive/analytics/metrics.h"
#include "missive/analytics/metrics_test_util.h"
#include "missive/client/mock_report_queue.h"
#include "missive/proto/record.pb.h"
#include "missive/util/status.h"
#include "missive/util/status_macros.h"
#include "missive/util/statusor.h"
#include "missive/util/test_support_callbacks.h"

using ::testing::_;
using ::testing::Eq;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::WithArg;

namespace reporting {
namespace {

class ReportQueueTest : public ::testing::Test {
 protected:
  ReportQueueTest() = default;

  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};

  analytics::Metrics::TestEnvironment metrics_test_environment_;
};

TEST_F(ReportQueueTest, EnqueueTest) {
  MockReportQueue queue;
  EXPECT_CALL(queue, AddRecord(_, _, _))
      .WillOnce(WithArg<2>(Invoke([](ReportQueue::EnqueueCallback cb) {
        std::move(cb).Run(Status::StatusOK());
      })));
  EXPECT_CALL(analytics::Metrics::TestEnvironment::GetMockMetricsLibrary(),
              SendEnumToUMA(StrEq(ReportQueue::kEnqueueMetricsName),
                            Eq(error::OK), Eq(error::MAX_VALUE)))
      .WillOnce(Return(true));
  test::TestEvent<Status> e;
  queue.Enqueue("Record", FAST_BATCH, e.cb());
  ASSERT_OK(e.result());
  task_environment_.RunUntilIdle();  // For asynchronous UMA upload.
}

TEST_F(ReportQueueTest, EnqueueWithErrorTest) {
  MockReportQueue queue;
  EXPECT_CALL(queue, AddRecord(_, _, _))
      .WillOnce(WithArg<2>(Invoke([](ReportQueue::EnqueueCallback cb) {
        std::move(cb).Run(Status(error::CANCELLED, "Cancelled by test"));
      })));
  EXPECT_CALL(analytics::Metrics::TestEnvironment::GetMockMetricsLibrary(),
              SendEnumToUMA(StrEq(ReportQueue::kEnqueueMetricsName),
                            Eq(error::CANCELLED), Eq(error::MAX_VALUE)))
      .WillOnce(Return(true));
  test::TestEvent<Status> e;
  queue.Enqueue("Record", FAST_BATCH, e.cb());
  const auto result = e.result();
  ASSERT_FALSE(result.ok());
  ASSERT_THAT(result.error_code(), Eq(error::CANCELLED));
  task_environment_.RunUntilIdle();  // For asynchronous UMA upload.
}

TEST_F(ReportQueueTest, FlushTest) {
  MockReportQueue queue;
  EXPECT_CALL(queue, Flush(_, _))
      .WillOnce(WithArg<1>(Invoke([](ReportQueue::FlushCallback cb) {
        std::move(cb).Run(Status::StatusOK());
      })));
  test::TestEvent<Status> e;
  queue.Flush(MANUAL_BATCH, e.cb());
  ASSERT_OK(e.result());
}
}  // namespace
}  // namespace reporting
