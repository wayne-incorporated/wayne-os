// Copyright 2016 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/cumulative_use_time_metric.h"

#include <list>
#include <memory>
#include <utility>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>
#include <base/single_thread_task_runner.h>
#include <base/test/simple_test_clock.h>
#include <base/test/simple_test_tick_clock.h>
#include <base/threading/thread_task_runner_handle.h>
#include <base/time/time.h>
#include <gtest/gtest.h>
#include <metrics/metrics_library.h>

namespace login_manager {

namespace {

const char kTestMetricName[] = "Test.CumulativeUseTime";

// Returns arbitrary time to be used as reference for test clock.
base::Time GetReferenceTime() {
  base::Time::Exploded exploded_reference_time;
  exploded_reference_time.year = 2015;
  exploded_reference_time.month = 12;
  exploded_reference_time.day_of_month = 5;
  exploded_reference_time.day_of_week = 6;
  exploded_reference_time.hour = 11;
  exploded_reference_time.minute = 21;
  exploded_reference_time.second = 32;
  exploded_reference_time.millisecond = 512;

  base::Time time;
  CHECK(base::Time::FromLocalExploded(exploded_reference_time, &time));
  return time;
}

// Returns arbitrary time ticks to be used as reference for test ticks clock.
base::TimeTicks GetReferenceTimeTicks() {
  return base::TimeTicks::FromInternalValue(1000);
}

// Helper clock class that returns the same time as the clock provided in
// ctor. Not expected to be used after reference clock is gone.
class TestClockCopy : public base::Clock {
 public:
  explicit TestClockCopy(base::SimpleTestClock* clock) : clock_(clock) {}
  TestClockCopy(const TestClockCopy&) = delete;
  TestClockCopy& operator=(const TestClockCopy&) = delete;

  ~TestClockCopy() override = default;

  base::Time Now() const override { return clock_->Now(); }

 private:
  base::SimpleTestClock* clock_;
};

// Helper clock class that returns the same time as the clock provided in
// ctor. Not expected to be used after reference clock is gone.
class TestTickClockCopy : public base::TickClock {
 public:
  explicit TestTickClockCopy(base::SimpleTestTickClock* tick_clock)
      : tick_clock_(tick_clock) {}
  TestTickClockCopy(const TestTickClockCopy&) = delete;
  TestTickClockCopy& operator=(const TestTickClockCopy&) = delete;

  ~TestTickClockCopy() override = default;

  base::TimeTicks NowTicks() const override { return tick_clock_->NowTicks(); }

 private:
  base::SimpleTestTickClock* tick_clock_;
};

// Single thread task runner used in tests.
// Task runner handles incoming tasks in order they are posted - the assumption
// is that expected task execution time is increasing in monotonic manner.
// Also provides factories for clocks that get updated according to task runner
// time.
class FakeSingleThreadTaskRunner : public base::SingleThreadTaskRunner {
 public:
  FakeSingleThreadTaskRunner(base::SimpleTestClock* clock,
                             base::SimpleTestTickClock* tick_clock)
      : clock_(clock), tick_clock_(tick_clock) {}
  FakeSingleThreadTaskRunner(const FakeSingleThreadTaskRunner&) = delete;
  FakeSingleThreadTaskRunner& operator=(const FakeSingleThreadTaskRunner&) =
      delete;

  ~FakeSingleThreadTaskRunner() override = default;

  bool PostDelayedTask(const base::Location& from_here,
                       base::OnceClosure task,
                       base::TimeDelta delay) final {
    pending_tasks_.emplace_back(tick_clock_->NowTicks() + delay,
                                std::move(task));
    return true;
  }

  bool RunsTasksInCurrentSequence() const final { return true; }

  bool PostNonNestableDelayedTask(const base::Location& from_here,
                                  base::OnceClosure task,
                                  base::TimeDelta delay) final {
    return false;
  }

  // Advances internal task runner time, running all tasks whose run time falls
  // within provided time period.
  void AdvanceTime(base::TimeDelta delta) {
    base::TimeDelta remaining_delta = delta;
    while (!pending_tasks_.empty()) {
      base::TimeTicks task_time = pending_tasks_.front().first;
      if (task_time > tick_clock_->NowTicks() + remaining_delta)
        break;
      base::TimeDelta time_to_task = task_time - tick_clock_->NowTicks();
      // Verify the assumption that posted tasks are posted in order of their
      // expected execution - if this assumtion starts not holding,
      // |pending_tasks_| should be switched to priority_queue.
      ASSERT_GE(time_to_task, base::TimeDelta());

      // Update time before running the task.
      tick_clock_->Advance(time_to_task);
      clock_->Advance(time_to_task);
      remaining_delta -= time_to_task;

      std::move(pending_tasks_.front().second).Run();
      pending_tasks_.pop_front();
    }

    tick_clock_->Advance(remaining_delta);
    clock_->Advance(remaining_delta);
  }

 private:
  base::SimpleTestClock* clock_;
  base::SimpleTestTickClock* tick_clock_;

  // Backing storage for pending tasks. List is good enough since it is assumed
  // that tasks will be posted in order they expected to get run. If that
  // assumption becomes invalid, the data strucute should be changed.
  using PendingTask = std::pair<base::TimeTicks, base::OnceClosure>;
  std::list<PendingTask> pending_tasks_;
};

// Fake metrics library used in the tests.
class TestMetricsLibrary : public MetricsLibraryInterface {
 public:
  explicit TestMetricsLibrary(const std::string& expected_use_time_metric)
      : expected_use_time_metric_name_(expected_use_time_metric) {}
  TestMetricsLibrary(const TestMetricsLibrary&) = delete;
  TestMetricsLibrary& operator=(const TestMetricsLibrary&) = delete;

  ~TestMetricsLibrary() override = default;

  int GetAndResetTotalSent() {
    int result = total_sent_;
    total_sent_ = 0;
    return result;
  }

  int GetTotalSent() const { return total_sent_; }

  int GetAndResetTimesSent() {
    int result = times_sent_;
    times_sent_ = 0;
    return result;
  }

  int GetTimesSent() const { return times_sent_; }

  void Init() override {}

  bool IsGuestMode() override { return false; }

  bool AreMetricsEnabled() override { return true; }

  bool SendEnumToUMA(const std::string& name, int sample, int max) override {
    ADD_FAILURE() << "Should not be reached";
    return false;
  }

  bool SendBoolToUMA(const std::string& name, bool sample) override {
    ADD_FAILURE() << "Should not be reached";
    return false;
  }

  bool SendSparseToUMA(const std::string& name, int sample) override {
    ADD_FAILURE() << "Should not be reached";
    return false;
  }

  bool SendUserActionToUMA(const std::string& action) override {
    ADD_FAILURE() << "Should not be reached";
    return false;
  }

  bool SendCrashToUMA(const char* crash_kind) override {
    ADD_FAILURE() << "Should not be reached";
    return false;
  }

  bool SendCrosEventToUMA(const std::string& event) override {
    ADD_FAILURE() << "Should not be reached";
    return false;
  }

  bool SendToUMA(const std::string& name,
                 int sample,
                 int min,
                 int max,
                 int nbuckets) override {
    if (name != expected_use_time_metric_name_) {
      ADD_FAILURE() << "Unexpected metric name: '" << name << "', expected: '"
                    << expected_use_time_metric_name_ << "'.";
      return false;
    }

    EXPECT_GE(sample, min);
    EXPECT_LE(sample, max);
    total_sent_ += sample;
    ++times_sent_;
    return true;
  }

 private:
  const std::string expected_use_time_metric_name_;
  int total_sent_{0};
  int times_sent_{0};
};

}  // namespace

class CumulativeUseTimeMetricTest : public testing::Test {
 public:
  CumulativeUseTimeMetricTest()
      : task_runner_(new FakeSingleThreadTaskRunner(&clock_, &tick_clock_)),
        task_runner_handle_(task_runner_.get()) {}
  CumulativeUseTimeMetricTest(const CumulativeUseTimeMetricTest&) = delete;
  CumulativeUseTimeMetricTest& operator=(const CumulativeUseTimeMetricTest&) =
      delete;

  ~CumulativeUseTimeMetricTest() override = default;

  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());

    clock_.SetNow(GetReferenceTime());
    tick_clock_.SetNowTicks(GetReferenceTimeTicks());

    ResetCumulativeUseTimeMetric();

    // Verifying some assumptions made in tests about timing of
    // updating/uploading use time metrics.
    ASSERT_GT(UpdateCycle(), base::TimeDelta::FromSeconds(10));
    ASSERT_GT(UploadCycle(), 3 * UpdateCycle());
  }

  void TearDown() override { cumulative_use_time_metric_.reset(); }

  base::TimeDelta UpdateCycle() const {
    return cumulative_use_time_metric_->GetMetricsUpdateCycle();
  }

  base::TimeDelta UploadCycle() const {
    return cumulative_use_time_metric_->GetMetricsUploadCycle();
  }

  // Recreates |cumulative_use_time_metric_| properly setting its clocks, so
  // the time is in line with current test state.
  void ResetCumulativeUseTimeMetric() {
    cumulative_use_time_metric_.reset(new CumulativeUseTimeMetric(
        kTestMetricName, &metrics_library_, temp_dir_.GetPath(),
        std::make_unique<TestClockCopy>(&clock_),
        std::make_unique<TestTickClockCopy>(&tick_clock_)));
  }

  // Advances time in UpdateCycle chunks, running message loop on each
  // interval. The goal is to simulate running delayed cumulative_use_metric
  // tasks for updating the metric state.
  void AdvanceTime(base::TimeDelta delta) { task_runner_->AdvanceTime(delta); }

  // Advances time enough to ensure that any remaining usage data is sent to
  // UMA. It will ensure that the metric tracking is stopped before advancing
  // time in order to avoid increasing the metric value.
  void StopMetricAndEnsureRemainingDataSentToUMA() {
    cumulative_use_time_metric_->Stop();
    AdvanceTime(UploadCycle());
    // This should trigger sending data to UMA.
    cumulative_use_time_metric_->Start();
    cumulative_use_time_metric_->Stop();
  }

  // Used to simulate backing file corruption.
  bool DeleteTestDir() { return temp_dir_.Delete(); }

  bool WriteGarbageToMetricsFile(const std::string& data) {
    int written =
        base::WriteFile(cumulative_use_time_metric_->GetMetricsFileForTest(),
                        data.data(), data.size());
    return written == static_cast<int>(data.size());
  }

 protected:
  std::unique_ptr<CumulativeUseTimeMetric> cumulative_use_time_metric_;

  TestMetricsLibrary metrics_library_{kTestMetricName};

 private:
  base::SimpleTestClock clock_;
  base::SimpleTestTickClock tick_clock_;

  scoped_refptr<FakeSingleThreadTaskRunner> task_runner_;
  base::ThreadTaskRunnerHandle task_runner_handle_;

  base::ScopedTempDir temp_dir_;
};

TEST_F(CumulativeUseTimeMetricTest, MetricsNotReportedBeforeStart) {
  cumulative_use_time_metric_->Init("53.0.0.1");

  AdvanceTime(UpdateCycle());
  EXPECT_EQ(0, metrics_library_.GetTimesSent());
}

TEST_F(CumulativeUseTimeMetricTest, NotReportedAfterFirstUpdate) {
  cumulative_use_time_metric_->Init("53.0.0.2");

  cumulative_use_time_metric_->Start();

  AdvanceTime(UpdateCycle());
  EXPECT_EQ(0, metrics_library_.GetTimesSent());

  StopMetricAndEnsureRemainingDataSentToUMA();
  EXPECT_EQ(1, metrics_library_.GetTimesSent());
  EXPECT_EQ(UpdateCycle().InSeconds(), metrics_library_.GetTotalSent());
}

TEST_F(CumulativeUseTimeMetricTest, ReportOnceADay) {
  cumulative_use_time_metric_->Init("53.0.0.3");

  cumulative_use_time_metric_->Start();

  AdvanceTime(UpdateCycle());
  EXPECT_EQ(0, metrics_library_.GetTimesSent());

  AdvanceTime(UploadCycle() + UpdateCycle());
  EXPECT_EQ(1, metrics_library_.GetAndResetTimesSent());

  AdvanceTime(UpdateCycle());
  EXPECT_EQ(0, metrics_library_.GetAndResetTimesSent());

  AdvanceTime(UploadCycle() - UpdateCycle());

  EXPECT_EQ(1, metrics_library_.GetAndResetTimesSent());

  StopMetricAndEnsureRemainingDataSentToUMA();
  EXPECT_EQ((2 * UploadCycle() + 2 * UpdateCycle()).InSeconds(),
            metrics_library_.GetTotalSent());
}

TEST_F(CumulativeUseTimeMetricTest, NoReportOnFirstStart) {
  cumulative_use_time_metric_->Init("53.0.0.4");

  cumulative_use_time_metric_->Start();
  EXPECT_EQ(0, metrics_library_.GetTimesSent());
}

TEST_F(CumulativeUseTimeMetricTest, ReportOldOnInit) {
  cumulative_use_time_metric_->Init("53.0.0.5");

  cumulative_use_time_metric_->Start();

  AdvanceTime(UpdateCycle());
  cumulative_use_time_metric_->Stop();
  EXPECT_EQ(0, metrics_library_.GetAndResetTimesSent());

  AdvanceTime(UploadCycle());
  ResetCumulativeUseTimeMetric();
  cumulative_use_time_metric_->Init("53.0.0.5");

  EXPECT_EQ(1, metrics_library_.GetAndResetTimesSent());
  EXPECT_EQ(UpdateCycle().InSeconds(), metrics_library_.GetTotalSent());
}

TEST_F(CumulativeUseTimeMetricTest, ResetValueOnVersionChange) {
  cumulative_use_time_metric_->Init("53.0.0.5");

  cumulative_use_time_metric_->Start();

  AdvanceTime(UpdateCycle());
  cumulative_use_time_metric_->Stop();

  EXPECT_EQ(0, metrics_library_.GetAndResetTimesSent());

  AdvanceTime(UploadCycle());
  ResetCumulativeUseTimeMetric();
  cumulative_use_time_metric_->Init("53.0.0.6");
  cumulative_use_time_metric_->Start();

  EXPECT_EQ(0, metrics_library_.GetAndResetTimesSent());
}

TEST_F(CumulativeUseTimeMetricTest, RecoverOnUncleanRestart) {
  cumulative_use_time_metric_->Init("53.0.0.7");

  cumulative_use_time_metric_->Start();

  AdvanceTime(2 * UpdateCycle() + base::TimeDelta::FromSeconds(10));

  ResetCumulativeUseTimeMetric();
  cumulative_use_time_metric_->Init("53.0.0.7");

  StopMetricAndEnsureRemainingDataSentToUMA();

  EXPECT_GE(metrics_library_.GetAndResetTotalSent(),
            (2 * UpdateCycle()).InSeconds());
}

TEST_F(CumulativeUseTimeMetricTest, UploadCycleNotLostOnVersionUpdate) {
  cumulative_use_time_metric_->Init("53.0.0.8");

  cumulative_use_time_metric_->Start();

  AdvanceTime(2 * UpdateCycle());
  EXPECT_EQ(0, metrics_library_.GetAndResetTimesSent());

  cumulative_use_time_metric_->Stop();

  ResetCumulativeUseTimeMetric();

  cumulative_use_time_metric_->Init("53.0.0.9");
  cumulative_use_time_metric_->Start();

  AdvanceTime(UpdateCycle());
  EXPECT_EQ(0, metrics_library_.GetAndResetTimesSent());

  AdvanceTime(UploadCycle());

  EXPECT_EQ(1, metrics_library_.GetAndResetTimesSent());

  StopMetricAndEnsureRemainingDataSentToUMA();
  EXPECT_EQ((UploadCycle() + UpdateCycle()).InSeconds(),
            metrics_library_.GetTotalSent());
}

TEST_F(CumulativeUseTimeMetricTest, IncreaseTimeOnlyWhileActive) {
  cumulative_use_time_metric_->Init("53.0.1.0");

  AdvanceTime(2 * UpdateCycle());
  cumulative_use_time_metric_->Start();
  EXPECT_EQ(0, metrics_library_.GetTimesSent());

  AdvanceTime(base::TimeDelta::FromSeconds(2));
  cumulative_use_time_metric_->Stop();
  AdvanceTime(UploadCycle());
  cumulative_use_time_metric_->Start();

  EXPECT_EQ(1, metrics_library_.GetAndResetTimesSent());
  EXPECT_EQ(2, metrics_library_.GetAndResetTotalSent());
}

TEST_F(CumulativeUseTimeMetricTest, HandleLeftoverFromRoundingToSeconds) {
  cumulative_use_time_metric_->Init("53.0.1.0");
  cumulative_use_time_metric_->Start();

  base::TimeDelta residue = base::TimeDelta::FromMilliseconds(530);
  AdvanceTime(UpdateCycle() + residue);
  cumulative_use_time_metric_->Stop();

  StopMetricAndEnsureRemainingDataSentToUMA();

  EXPECT_EQ(1, metrics_library_.GetAndResetTimesSent());
  EXPECT_EQ(UpdateCycle().InSeconds(), metrics_library_.GetTotalSent());

  cumulative_use_time_metric_->Start();

  AdvanceTime(UploadCycle() + residue);

  StopMetricAndEnsureRemainingDataSentToUMA();

  EXPECT_EQ((UpdateCycle() + UploadCycle() + 2 * residue).InSeconds(),
            metrics_library_.GetTotalSent());
}

TEST_F(CumulativeUseTimeMetricTest, HandleInvalidMetricsDir) {
  ASSERT_TRUE(DeleteTestDir());
  cumulative_use_time_metric_->Init("53.0.2.0");

  cumulative_use_time_metric_->Start();
  AdvanceTime(2 * UpdateCycle());
  cumulative_use_time_metric_->Stop();

  StopMetricAndEnsureRemainingDataSentToUMA();
  EXPECT_EQ(1, metrics_library_.GetTimesSent());
  EXPECT_EQ(2 * UpdateCycle().InSeconds(), metrics_library_.GetTotalSent());
}

TEST_F(CumulativeUseTimeMetricTest, HandleMetricsDirCorruption) {
  cumulative_use_time_metric_->Init("53.0.3.0");

  cumulative_use_time_metric_->Start();
  AdvanceTime(2 * UpdateCycle());

  ASSERT_TRUE(DeleteTestDir());

  AdvanceTime(UpdateCycle());
  cumulative_use_time_metric_->Stop();

  StopMetricAndEnsureRemainingDataSentToUMA();
  EXPECT_EQ(1, metrics_library_.GetTimesSent());
  EXPECT_EQ((3 * UpdateCycle()).InSeconds(), metrics_library_.GetTotalSent());
}

TEST_F(CumulativeUseTimeMetricTest, HandleGarbageInMetricsFileOnStart_NotJSON) {
  cumulative_use_time_metric_->Init("53.0.3.0");

  cumulative_use_time_metric_->Start();
  AdvanceTime(UpdateCycle());
  EXPECT_EQ(0, metrics_library_.GetTimesSent());

  ASSERT_TRUE(WriteGarbageToMetricsFile("not JSON"));

  ResetCumulativeUseTimeMetric();

  cumulative_use_time_metric_->Init("53.0.3.0");
  cumulative_use_time_metric_->Start();

  AdvanceTime(UpdateCycle());
  cumulative_use_time_metric_->Stop();

  StopMetricAndEnsureRemainingDataSentToUMA();

  EXPECT_EQ(1, metrics_library_.GetTimesSent());
  EXPECT_EQ(UpdateCycle().InSeconds(), metrics_library_.GetTotalSent());
}

TEST_F(CumulativeUseTimeMetricTest,
       HandleGarbageInMetricsFileOnStart_UnexpectedJSON) {
  cumulative_use_time_metric_->Init("53.0.3.0");

  cumulative_use_time_metric_->Start();
  AdvanceTime(UpdateCycle());
  EXPECT_EQ(0, metrics_library_.GetTimesSent());

  ASSERT_TRUE(WriteGarbageToMetricsFile(
      "{\"start_time_\":1,\"elapsed_milliseconds\":3,\"a\":4}"));

  ResetCumulativeUseTimeMetric();

  cumulative_use_time_metric_->Init("53.0.3.0");
  cumulative_use_time_metric_->Start();

  AdvanceTime(UpdateCycle());
  cumulative_use_time_metric_->Stop();

  StopMetricAndEnsureRemainingDataSentToUMA();

  EXPECT_EQ(1, metrics_library_.GetTimesSent());
  EXPECT_EQ(UpdateCycle().InSeconds(), metrics_library_.GetTotalSent());
}

TEST_F(CumulativeUseTimeMetricTest, HandleMetricFileOverwrittenByGarbage) {
  cumulative_use_time_metric_->Init("53.0.3.0");

  cumulative_use_time_metric_->Start();
  AdvanceTime(UpdateCycle());

  EXPECT_EQ(0, metrics_library_.GetTimesSent());

  ASSERT_TRUE(WriteGarbageToMetricsFile("Not a JSON"));

  AdvanceTime(UpdateCycle());

  StopMetricAndEnsureRemainingDataSentToUMA();
  EXPECT_EQ(1, metrics_library_.GetTimesSent());
  // Metrics file was corrupted after initial read, so it should be possible to
  // recover from the corruption.
  EXPECT_EQ((2 * UpdateCycle()).InSeconds(), metrics_library_.GetTotalSent());
}

}  // namespace login_manager
