// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

#include <memory>
#include <utility>

#include <base/time/time.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "metrics/metrics_library_mock.h"
#include "metrics/timer.h"
#include "metrics/timer_mock.h"

using ::testing::_;
using ::testing::Return;

namespace chromeos_metrics {

namespace {
constexpr base::TimeDelta kStime1 = base::Milliseconds(1400);
constexpr base::TimeDelta kEtime1 = base::Milliseconds(3000);
constexpr base::TimeDelta kDelta1 = base::Milliseconds(1600);

constexpr base::TimeDelta kStime2 = base::Milliseconds(4200);
constexpr base::TimeDelta kEtime2 = base::Milliseconds(5000);
constexpr base::TimeDelta kDelta2 = base::Milliseconds(800);

constexpr base::TimeDelta kStime3 = base::Milliseconds(6600);
constexpr base::TimeDelta kEtime3 = base::Milliseconds(6800);
constexpr base::TimeDelta kDelta3 = base::Milliseconds(200);
}  // namespace

class TimerTest : public testing::Test {
 public:
  TimerTest() : clock_wrapper_mock_(new ClockWrapperMock()) {}

 protected:
  virtual void SetUp() {
    EXPECT_EQ(Timer::kTimerStopped, timer_.timer_state_);
    stime += kStime1;
    etime += kEtime1;
    stime2 += kStime2;
    etime2 += kEtime2;
    stime3 += kStime3;
    etime3 += kEtime3;
  }

  virtual void TearDown() {}

  Timer timer_;
  std::unique_ptr<ClockWrapperMock> clock_wrapper_mock_;
  base::TimeTicks stime, etime, stime2, etime2, stime3, etime3;
};

TEST_F(TimerTest, StartStop) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime))
      .WillOnce(Return(etime));
  timer_.clock_wrapper_ = std::move(clock_wrapper_mock_);
  ASSERT_TRUE(timer_.Start());
  ASSERT_TRUE(timer_.start_time_ == stime);
  ASSERT_TRUE(timer_.HasStarted());
  ASSERT_TRUE(timer_.Stop());
  ASSERT_EQ(timer_.elapsed_time_, kDelta1);

  base::TimeDelta elapsed_time;
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_, elapsed_time);

  ASSERT_FALSE(timer_.HasStarted());
}

TEST_F(TimerTest, ReStart) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime))
      .WillOnce(Return(etime));
  timer_.clock_wrapper_ = std::move(clock_wrapper_mock_);
  timer_.Start();
  base::TimeTicks buffer = timer_.start_time_;
  timer_.Start();
  ASSERT_FALSE(timer_.start_time_ == buffer);
}

TEST_F(TimerTest, Reset) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime()).WillOnce(Return(stime));
  timer_.clock_wrapper_ = std::move(clock_wrapper_mock_);
  timer_.Start();
  ASSERT_TRUE(timer_.Reset());
  ASSERT_FALSE(timer_.HasStarted());
}

TEST_F(TimerTest, SeparatedTimers) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime))
      .WillOnce(Return(etime))
      .WillOnce(Return(stime2))
      .WillOnce(Return(etime2));
  timer_.clock_wrapper_ = std::move(clock_wrapper_mock_);
  ASSERT_TRUE(timer_.Start());
  ASSERT_TRUE(timer_.Stop());
  ASSERT_EQ(timer_.elapsed_time_, kDelta1);
  ASSERT_TRUE(timer_.Start());
  ASSERT_TRUE(timer_.start_time_ == stime2);
  ASSERT_TRUE(timer_.Stop());
  ASSERT_EQ(timer_.elapsed_time_, kDelta2);
  ASSERT_FALSE(timer_.HasStarted());

  base::TimeDelta elapsed_time;
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(),
            elapsed_time.InMilliseconds());
}

TEST_F(TimerTest, InvalidStop) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime))
      .WillOnce(Return(etime));
  timer_.clock_wrapper_ = std::move(clock_wrapper_mock_);
  ASSERT_FALSE(timer_.Stop());
  // Now we try it again, but after a valid start/stop.
  timer_.Start();
  timer_.Stop();
  base::TimeDelta elapsed_time = timer_.elapsed_time_;
  ASSERT_FALSE(timer_.Stop());
  ASSERT_TRUE(elapsed_time == timer_.elapsed_time_);
}

TEST_F(TimerTest, InvalidElapsedTime) {
  base::TimeDelta elapsed_time;
  ASSERT_FALSE(timer_.GetElapsedTime(&elapsed_time));
}

TEST_F(TimerTest, PauseStartStopResume) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime))
      .WillOnce(Return(stime2))
      .WillOnce(Return(etime2))
      .WillOnce(Return(stime3))
      .WillOnce(Return(etime3));
  timer_.clock_wrapper_ = std::move(clock_wrapper_mock_);
  ASSERT_TRUE(timer_.Pause());  // Starts timer paused.
  ASSERT_TRUE(timer_.start_time_ == stime);
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Start());  // Restarts timer.
  ASSERT_TRUE(timer_.start_time_ == stime2);
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Stop());
  ASSERT_EQ(timer_.elapsed_time_, kDelta2);
  ASSERT_FALSE(timer_.HasStarted());
  base::TimeDelta elapsed_time;
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_, elapsed_time);

  ASSERT_TRUE(timer_.Resume());
  ASSERT_TRUE(timer_.HasStarted());
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(kDelta3, elapsed_time);
}

TEST_F(TimerTest, ResumeStartStopPause) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime))
      .WillOnce(Return(stime2))
      .WillOnce(Return(etime2))
      .WillOnce(Return(stime3));
  timer_.clock_wrapper_ = std::move(clock_wrapper_mock_);
  ASSERT_TRUE(timer_.Resume());
  ASSERT_TRUE(timer_.start_time_ == stime);
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Start());
  ASSERT_TRUE(timer_.start_time_ == stime2);
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Stop());
  ASSERT_EQ(timer_.elapsed_time_, kDelta2);
  ASSERT_FALSE(timer_.HasStarted());
  base::TimeDelta elapsed_time;
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_, elapsed_time);

  ASSERT_TRUE(timer_.Pause());
  ASSERT_TRUE(timer_.HasStarted());
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(0, elapsed_time.InMilliseconds());
}

TEST_F(TimerTest, StartResumeStop) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime))
      .WillOnce(Return(etime));
  timer_.clock_wrapper_ = std::move(clock_wrapper_mock_);
  ASSERT_TRUE(timer_.Start());
  ASSERT_TRUE(timer_.start_time_ == stime);
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_FALSE(timer_.Resume());
  ASSERT_TRUE(timer_.start_time_ == stime);
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Stop());
  ASSERT_EQ(timer_.elapsed_time_, kDelta1);
  ASSERT_FALSE(timer_.HasStarted());
  base::TimeDelta elapsed_time;
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(),
            elapsed_time.InMilliseconds());
}

TEST_F(TimerTest, StartPauseStop) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime))
      .WillOnce(Return(etime));
  timer_.clock_wrapper_ = std::move(clock_wrapper_mock_);
  ASSERT_TRUE(timer_.Start());
  ASSERT_TRUE(timer_.start_time_ == stime);
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Pause());
  ASSERT_TRUE(timer_.HasStarted());
  ASSERT_EQ(timer_.elapsed_time_, kDelta1);
  base::TimeDelta elapsed_time;
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_, elapsed_time);

  ASSERT_TRUE(timer_.Stop());
  ASSERT_EQ(timer_.elapsed_time_, kDelta1);
  ASSERT_FALSE(timer_.HasStarted());
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_, elapsed_time);
}

TEST_F(TimerTest, StartPauseResumeStop) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime))
      .WillOnce(Return(etime))
      .WillOnce(Return(stime2))
      .WillOnce(Return(etime2));
  timer_.clock_wrapper_ = std::move(clock_wrapper_mock_);
  ASSERT_TRUE(timer_.Start());
  ASSERT_TRUE(timer_.start_time_ == stime);
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Pause());
  ASSERT_TRUE(timer_.HasStarted());
  ASSERT_EQ(timer_.elapsed_time_, kDelta1);
  base::TimeDelta elapsed_time;
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_, elapsed_time);

  ASSERT_TRUE(timer_.Resume());
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Stop());
  ASSERT_EQ(timer_.elapsed_time_, kDelta1 + kDelta2);
  ASSERT_FALSE(timer_.HasStarted());
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_, elapsed_time);
}

TEST_F(TimerTest, PauseStop) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime()).WillOnce(Return(stime));
  timer_.clock_wrapper_ = std::move(clock_wrapper_mock_);
  ASSERT_TRUE(timer_.Pause());
  ASSERT_TRUE(timer_.start_time_ == stime);
  ASSERT_TRUE(timer_.HasStarted());
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(), 0);

  ASSERT_TRUE(timer_.Stop());
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(), 0);
  ASSERT_FALSE(timer_.HasStarted());
  base::TimeDelta elapsed_time;
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_, elapsed_time);
}

TEST_F(TimerTest, PauseResumeStop) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime))
      .WillOnce(Return(stime2))
      .WillOnce(Return(etime2));
  timer_.clock_wrapper_ = std::move(clock_wrapper_mock_);
  ASSERT_TRUE(timer_.Pause());
  ASSERT_TRUE(timer_.start_time_ == stime);
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Resume());
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Stop());
  ASSERT_EQ(timer_.elapsed_time_, kDelta2);
  ASSERT_FALSE(timer_.HasStarted());
  base::TimeDelta elapsed_time;
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_, elapsed_time);
}

TEST_F(TimerTest, StartPauseResumePauseStop) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime))
      .WillOnce(Return(etime))
      .WillOnce(Return(stime2))
      .WillOnce(Return(stime3))
      .WillOnce(Return(etime3));
  timer_.clock_wrapper_ = std::move(clock_wrapper_mock_);
  ASSERT_TRUE(timer_.Start());
  ASSERT_TRUE(timer_.start_time_ == stime);
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Pause());
  ASSERT_TRUE(timer_.HasStarted());
  ASSERT_EQ(timer_.elapsed_time_, kDelta1);
  base::TimeDelta elapsed_time;
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_, elapsed_time);

  ASSERT_TRUE(timer_.Resume());
  ASSERT_TRUE(timer_.HasStarted());
  // Make sure GetElapsedTime works while we're running.
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(kDelta1 + kStime3 - kStime2, elapsed_time);

  ASSERT_TRUE(timer_.Pause());
  ASSERT_TRUE(timer_.HasStarted());
  ASSERT_EQ(timer_.elapsed_time_, kDelta1 + kEtime3 - kStime2);
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_, elapsed_time);

  ASSERT_TRUE(timer_.Stop());
  ASSERT_EQ(timer_.elapsed_time_, kDelta1 + kEtime3 - kStime2);
  ASSERT_FALSE(timer_.HasStarted());
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_, elapsed_time);
}

TEST_F(TimerTest, StartPauseResumePauseResumeStop) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime))
      .WillOnce(Return(etime))
      .WillOnce(Return(stime2))
      .WillOnce(Return(etime2))
      .WillOnce(Return(stime3))
      .WillOnce(Return(etime3));
  timer_.clock_wrapper_ = std::move(clock_wrapper_mock_);
  ASSERT_TRUE(timer_.Start());
  ASSERT_TRUE(timer_.start_time_ == stime);
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Pause());
  ASSERT_TRUE(timer_.HasStarted());
  ASSERT_EQ(timer_.elapsed_time_, kDelta1);
  base::TimeDelta elapsed_time;
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_, elapsed_time);

  ASSERT_TRUE(timer_.Resume());
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Pause());
  ASSERT_TRUE(timer_.HasStarted());
  ASSERT_EQ(timer_.elapsed_time_, kDelta1 + kDelta2);
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_, elapsed_time);

  ASSERT_TRUE(timer_.Resume());
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Stop());
  ASSERT_EQ(timer_.elapsed_time_, kDelta1 + kDelta2 + kDelta3);
  ASSERT_FALSE(timer_.HasStarted());
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_, elapsed_time);
}

namespace {
const char kMetricName[] = "test-timer";
const int kMinSample = 0;
const int kMaxSample = 120 * 1E6;
const int kNumBuckets = 50;
}  // namespace

class TimerReporterTest : public testing::Test {
 public:
  TimerReporterTest()
      : timer_reporter_(kMetricName, kMinSample, kMaxSample, kNumBuckets),
        clock_wrapper_mock_(new ClockWrapperMock()) {}

 protected:
  virtual void SetUp() {
    timer_reporter_.set_metrics_lib(&lib_);
    EXPECT_EQ(timer_reporter_.histogram_name_, kMetricName);
    EXPECT_EQ(timer_reporter_.min_, kMinSample);
    EXPECT_EQ(timer_reporter_.max_, kMaxSample);
    EXPECT_EQ(timer_reporter_.num_buckets_, kNumBuckets);
    stime += kStime1;
    etime += kEtime1;
  }

  virtual void TearDown() { timer_reporter_.set_metrics_lib(nullptr); }

  TimerReporter timer_reporter_;
  MetricsLibraryMock lib_;
  std::unique_ptr<ClockWrapperMock> clock_wrapper_mock_;
  base::TimeTicks stime, etime;
};

TEST_F(TimerReporterTest, StartStopReport) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime))
      .WillOnce(Return(etime));
  timer_reporter_.clock_wrapper_ = std::move(clock_wrapper_mock_);
  EXPECT_CALL(lib_, SendToUMA(kMetricName, kDelta1.InMilliseconds(), kMinSample,
                              kMaxSample, kNumBuckets))
      .WillOnce(Return(true));
  ASSERT_TRUE(timer_reporter_.Start());
  ASSERT_TRUE(timer_reporter_.Stop());
  ASSERT_TRUE(timer_reporter_.ReportMilliseconds());
}

TEST_F(TimerReporterTest, InvalidReport) {
  ASSERT_FALSE(timer_reporter_.ReportMilliseconds());
}

}  // namespace chromeos_metrics
