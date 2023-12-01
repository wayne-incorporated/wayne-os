// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <utility>

#include <base/threading/thread.h>
#include "debugd/src/metrics.h"
#include "metrics/metrics_library.h"
#include "metrics/metrics_library_mock.h"

namespace debugd {

namespace {

using ::testing::_;

// The log name tracked by the stopwatch.
constexpr char kLogName[] = "Perf.GetBigFeedbackLogs";
// The metrics name tracking the total duration of collecting the log.
constexpr char kMetricName[] = "ChromeOS.Debugd.Perf.GetBigFeedbackLogs";
// One lap name which is a subtask of the log collection process.
constexpr char kLapName1[] = "GetBluetoothBqr";
// The metrics name tracking the duration of the above lap/subtask.
constexpr char kLapMetricsName1[] =
    "ChromeOS.Debugd.Perf.GetBigFeedbackLogs.GetBluetoothBqr";

}  // namespace

class StopwatchTest : public ::testing::Test {
 protected:
  // Start the stopwatch and log the lap.
  void StartAndLogLap(std::unique_ptr<MetricsLibraryMock> metrics_lib,
                      const std::string& lap_name,
                      bool local_logging,
                      bool send_lap_to_uma) {
    Stopwatch stopwatch(kLogName, local_logging, send_lap_to_uma);
    stopwatch.metrics_library_ = std::move(metrics_lib);

    // The lap_start_ should match sw_start_ in the beginning.
    EXPECT_EQ(stopwatch.lap_start_, stopwatch.sw_start_);
    base::PlatformThread::Sleep(base::Milliseconds(2));

    stopwatch.Lap(lap_name);
    // The lap_start_ should have been advanced by 2 ms. Use >= to tolerate
    // delay.
    EXPECT_GE((stopwatch.lap_start_ - stopwatch.sw_start_).InMilliseconds(), 2);
  }
};

// Verify that when send_lap_to_uma is false, the lap metics is not sent.
TEST_F(StopwatchTest, LapMetricsIsNotSent) {
  auto metrics = std::make_unique<MetricsLibraryMock>();

  EXPECT_CALL(*metrics, SendToUMA(kLapMetricsName1, _, _, _, _)).Times(0);
  // Total elapsed time is always sent to UMA.
  EXPECT_CALL(*metrics, SendToUMA(kMetricName, _, _, _, _)).Times(1);
  StartAndLogLap(std::move(metrics), kLapName1, /*local_logging=*/false,
                 /*send_lap_to_uma=*/false);
}

// Verify that when send_lap_to_uma is true, the lap metics is sent.
TEST_F(StopwatchTest, LapMetricsIsSent) {
  auto metrics = std::make_unique<MetricsLibraryMock>();
  // A metrics named kLapMetricsName1 is sent once.
  EXPECT_CALL(*metrics, SendToUMA(kLapMetricsName1, _, _, _, _)).Times(1);
  // Total elapsed time is always sent to UMA.
  EXPECT_CALL(*metrics, SendToUMA(kMetricName, _, _, _, _)).Times(1);

  StartAndLogLap(std::move(metrics), kLapName1, /*local_logging=*/false,
                 /*send_lap_to_uma=*/true);
}

}  // namespace debugd
