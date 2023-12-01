// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/analytics/metrics_test_util.h"

#include <atomic>

#include <base/logging.h>
#include <base/memory/scoped_refptr.h>
#include <base/run_loop.h>
#include <base/task/sequenced_task_runner.h>
#include <base/task/single_thread_task_runner.h>
#include <metrics/metrics_library_mock.h>

#include "missive/analytics/metrics.h"

namespace reporting::analytics {

Metrics::TestEnvironment::TestEnvironment() {
  InitializeMock();
}

Metrics::TestEnvironment::~TestEnvironment() {
  CleanUpMock();
}

// static
void Metrics::TestEnvironment::InitializeMock() {
  if (GetMetricsTaskRunner()) {
    LOG(ERROR) << "Metrics, either fake or real, already initialized or "
                  "scheduled to be initialized. skipping...";
    return;
  }
  // Switch to the current thread because EXPECT_CALL for another thread is
  // flaky.
  GetMetricsTaskRunner() = base::SequencedTaskRunner::GetCurrentDefault();
  // Safe to modify GetMetricsLibrary here because it is attached to the current
  // thread.
  GetMetricsLibrary() = new ::testing::NiceMock<MetricsLibraryMock>();
}

// static
void Metrics::TestEnvironment::CleanUpMock() {
  if (!GetMetricsTaskRunner()) {
    LOG(ERROR) << "Metrics not initialized. Skip cleanup.";
    return;
  }

  // Must be on the current task runner.
  ASSERT_EQ(base::SequencedTaskRunner::GetCurrentDefault(),
            GetMetricsTaskRunner());

  GetMetricsTaskRunner() = nullptr;
  // Safe to modify GetMetricsLibrary here because it is attached to the current
  // thread.
  delete GetMetricsLibrary();
  GetMetricsLibrary() = nullptr;

  // Clear the task runner up to this point to prevent GetMetricsLibrary from
  // being accidentally accessed by this task runner in a later test.
  base::RunLoop run_loop;
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, run_loop.QuitClosure());
}

// static
::testing::NiceMock<MetricsLibraryMock>&
Metrics::TestEnvironment::GetMockMetricsLibrary() {
  return *static_cast<::testing::NiceMock<MetricsLibraryMock>*>(
      GetMetricsLibrary());
}
}  // namespace reporting::analytics
