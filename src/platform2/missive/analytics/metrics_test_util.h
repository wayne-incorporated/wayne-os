// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_ANALYTICS_METRICS_TEST_UTIL_H_
#define MISSIVE_ANALYTICS_METRICS_TEST_UTIL_H_

#include <memory>
#include <utility>

#include <base/memory/scoped_refptr.h>
#include <base/task/sequenced_task_runner.h>
#include <metrics/metrics_library.h>
#include <metrics/metrics_library_mock.h>

#include "missive/analytics/metrics.h"

namespace reporting::analytics {

// Replaces the metrics library with a mock upon construction and restores it
// once the test terminates. Also resets the task runner that the metrics
// library instance runs on. Normally used as a member of a test class.
class Metrics::TestEnvironment {
 public:
  TestEnvironment();
  TestEnvironment(const TestEnvironment&) = delete;
  TestEnvironment& operator=(const TestEnvironment&) = delete;
  ~TestEnvironment();

  // Initialize a mock metrics instance for test. This is automatically called
  // in `TestEnvironment`. Feel free to call this method directly if more
  // flexibility is needed. Must call `CleanUpMock` after test is done.
  static void InitializeMock();

  // Clean up mock metrics instance for test. Must be called on the same thread
  // as `InitializeMock`. This is usually not a problem if it is called on the
  // test thread because `InitializeMock` is normally called on the test thread.
  // It is automatically called by `~TestEnvironment`. Feel free to call this
  // method directly if more flexibility is needed.
  static void CleanUpMock();

  // Get the mock metrics library instance for test.
  // NiceMock to allow silent default actions.
  static ::testing::NiceMock<MetricsLibraryMock>& GetMockMetricsLibrary();

 private:
  // Pointers to the two methods that access hidden variables in metrics.cc.
  // Defined here instead of out of class in metrics_test_util.cc because this
  // is a friend class of Metrics.
  static constexpr auto GetMetricsLibrary = &Metrics::GetMetricsLibraryForTest;
  static constexpr auto GetMetricsTaskRunner =
      &Metrics::GetMetricsTaskRunnerForTest;
};
}  // namespace reporting::analytics
#endif  // MISSIVE_ANALYTICS_METRICS_TEST_UTIL_H_
