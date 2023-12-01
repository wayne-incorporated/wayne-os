// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/common/activity_logger.h"

#include <base/check.h>
#include <base/memory/ptr_util.h>
#include <base/test/task_environment.h>
#include <gtest/gtest.h>

#include "power_manager/common/clock.h"

namespace power_manager {

class ActivityLoggerTest : public testing::Test {
 public:
  ActivityLoggerTest() : kName("test activity") {}
  ActivityLoggerTest(const ActivityLoggerTest&) = delete;
  ActivityLoggerTest& operator=(const ActivityLoggerTest&) = delete;

  ~ActivityLoggerTest() override = default;

  // Initialize |logger| for testing. Ownership remains with the caller.
  void Init(BaseActivityLogger* logger) {
    logger_ = logger;
    logger_->clock_for_test()->set_current_time_for_testing(
        base::TimeTicks() + base::Microseconds(100));  // Arbitrary.
    logger_->SetLogCallbackForTest(base::BindRepeating(
        &ActivityLoggerTest::SaveMessage, base::Unretained(this)));
  }

  void AdvanceTime(base::TimeDelta delta) {
    CHECK(logger_);
    logger_->clock_for_test()->set_current_time_for_testing(
        logger_->clock_for_test()->GetCurrentTime() + delta);
  }

  std::string PopMessage() {
    std::string message = last_message_;
    last_message_.clear();
    return message;
  }

 protected:
  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::TaskEnvironment::MainThreadType::IO,
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};

  const std::string kName;

  BaseActivityLogger* logger_;  // Not owned.

 private:
  // BaseActivityLogger::LogCallback that just saves messages passed to it.
  void SaveMessage(const std::string& message) {
    EXPECT_FALSE(message.empty()) << "Got request to log empty message";
    EXPECT_TRUE(last_message_.empty())
        << "Got request to log \"" << message << "\" before previous message \""
        << last_message_ << "\" was popped";
    last_message_ = message;
  }

  // The last message passed to SaveMessage().
  std::string last_message_;
};

TEST_F(ActivityLoggerTest, StartStopNoDelay) {
  StartStopActivityLogger logger(kName, base::TimeDelta(), base::TimeDelta());
  Init(&logger);
  EXPECT_EQ("", PopMessage());

  // A message should be logged immediately every time activity starts or stops.
  logger.OnActivityStarted();
  EXPECT_EQ(kName + " started", PopMessage());
  EXPECT_EQ(base::TimeDelta(), logger.GetStoppedTimerDelayForTest());
  logger.OnActivityStopped();
  EXPECT_EQ(kName + " stopped", PopMessage());
  logger.OnActivityStarted();
  EXPECT_EQ(kName + " started", PopMessage());
}

TEST_F(ActivityLoggerTest, StartStopWithDelay) {
  const base::TimeDelta kStoppedDelay = base::Seconds(5);
  StartStopActivityLogger logger(kName, kStoppedDelay, base::TimeDelta());
  Init(&logger);
  EXPECT_EQ("", PopMessage());

  // Start the activity. The "stopped" timer shouldn't be running.
  logger.OnActivityStarted();
  EXPECT_EQ(kName + " started", PopMessage());
  EXPECT_EQ(base::TimeDelta(), logger.GetStoppedTimerDelayForTest());

  // Immediately stopping the activity should start the "stopped" timer but not
  // log anything.
  logger.OnActivityStopped();
  EXPECT_EQ("", PopMessage());
  EXPECT_EQ(kStoppedDelay, logger.GetStoppedTimerDelayForTest());

  // Starting the activity again should stop the timer but not log.
  logger.OnActivityStarted();
  EXPECT_EQ("", PopMessage());
  EXPECT_EQ(base::TimeDelta(), logger.GetStoppedTimerDelayForTest());

  // Stop the activity a second time. This time, wait for the timer to fire,
  // which should result in the "stopped" message being logged with the delay.
  logger.OnActivityStopped();
  EXPECT_EQ(kStoppedDelay, logger.GetStoppedTimerDelayForTest());
  AdvanceTime(kStoppedDelay);
  ASSERT_TRUE(logger.TriggerStoppedTimerForTest());
  EXPECT_EQ(kName + " stopped 5 sec ago", PopMessage());

  // Starting the activity again now should log a message immediately.
  logger.OnActivityStarted();
  EXPECT_EQ(kName + " started", PopMessage());
}

TEST_F(ActivityLoggerTest, StartStopWithOngoing) {
  const base::TimeDelta kStoppedDelay = base::Seconds(5);
  const base::TimeDelta kOngoingDelay = base::Seconds(30);
  StartStopActivityLogger logger(kName, kStoppedDelay, kOngoingDelay);
  Init(&logger);
  EXPECT_EQ("", PopMessage());

  EXPECT_EQ(base::TimeDelta(), logger.GetOngoingTimerDelayForTest());
  logger.OnActivityStarted();
  EXPECT_EQ(kName + " started", PopMessage());

  // After activity starts, the "ongoing" timer should be started. Whenever it
  // fires, the "ongoing" message should be logged.
  EXPECT_EQ(kOngoingDelay, logger.GetOngoingTimerDelayForTest());
  AdvanceTime(kOngoingDelay);
  ASSERT_TRUE(logger.TriggerOngoingTimerForTest());
  EXPECT_EQ(kName + " ongoing", PopMessage());

  EXPECT_EQ(kOngoingDelay, logger.GetOngoingTimerDelayForTest());
  AdvanceTime(kOngoingDelay);
  ASSERT_TRUE(logger.TriggerOngoingTimerForTest());
  EXPECT_EQ(kName + " ongoing", PopMessage());

  // The "ongoing" timer should be stopped immediately when activity stops.
  logger.OnActivityStopped();
  EXPECT_EQ("", PopMessage());
  EXPECT_EQ(base::TimeDelta(), logger.GetOngoingTimerDelayForTest());

  // It should be started again when activity starts.
  logger.OnActivityStarted();
  EXPECT_EQ("", PopMessage());
  EXPECT_EQ(kOngoingDelay, logger.GetOngoingTimerDelayForTest());
  AdvanceTime(kOngoingDelay);
  ASSERT_TRUE(logger.TriggerOngoingTimerForTest());
  EXPECT_EQ(kName + " ongoing", PopMessage());
}

TEST_F(ActivityLoggerTest, StartStopDuplicateStop) {
  StartStopActivityLogger logger(kName, base::TimeDelta(), base::TimeDelta());
  Init(&logger);
  logger.OnActivityStarted();
  EXPECT_EQ(kName + " started", PopMessage());

  // A second OnActivityStopped() call shouldn't log the "stopped" message a
  // second time.
  logger.OnActivityStopped();
  EXPECT_EQ(kName + " stopped", PopMessage());
  logger.OnActivityStopped();
  EXPECT_EQ("", PopMessage());
}

TEST_F(ActivityLoggerTest, PeriodicNoOngoing) {
  const base::TimeDelta kStoppedDelay = base::Seconds(10);
  PeriodicActivityLogger logger(kName, kStoppedDelay, base::TimeDelta());
  Init(&logger);
  EXPECT_EQ("", PopMessage());

  // The first report should be logged immediately, but subsequent reports
  // before the "stopped" timer has fired shouldn't be logged.
  logger.OnActivityReported();
  EXPECT_EQ(kName + " reported", PopMessage());
  logger.OnActivityReported();
  EXPECT_EQ("", PopMessage());

  // We should log when the "stopped" timer fires.
  EXPECT_EQ(kStoppedDelay, logger.GetStoppedTimerDelayForTest());
  AdvanceTime(kStoppedDelay);
  ASSERT_TRUE(logger.TriggerStoppedTimerForTest());
  EXPECT_EQ(kName + " stopped; last reported 10 sec ago", PopMessage());

  // A new report should be logged now that activity has stopped.
  logger.OnActivityReported();
  EXPECT_EQ(kName + " reported", PopMessage());
}

TEST_F(ActivityLoggerTest, PeriodicWithOngoing) {
  const base::TimeDelta kStoppedDelay = base::Seconds(20);
  const base::TimeDelta kOngoingDelay = base::Seconds(25);
  PeriodicActivityLogger logger(kName, kStoppedDelay, kOngoingDelay);
  Init(&logger);
  EXPECT_EQ("", PopMessage());

  // Start the activity.
  logger.OnActivityReported();
  EXPECT_EQ(kName + " reported", PopMessage());
  EXPECT_EQ(kOngoingDelay, logger.GetOngoingTimerDelayForTest());

  // Send a second report after 15 seconds to keep the activity going.
  AdvanceTime(base::Seconds(15));
  logger.OnActivityReported();
  EXPECT_EQ("", PopMessage());

  // Advance the clock the remaining 10 seconds to the ongoing interval.
  AdvanceTime(base::Seconds(10));
  ASSERT_TRUE(logger.TriggerOngoingTimerForTest());
  EXPECT_EQ(kName + " ongoing; last reported 10 sec ago", PopMessage());

  // Now let the "stopped" timer fire 10 seconds later and check that the
  // "ongoing" timer is also stopped.
  AdvanceTime(base::Seconds(10));
  ASSERT_TRUE(logger.TriggerStoppedTimerForTest());
  EXPECT_EQ(kName + " stopped; last reported 20 sec ago", PopMessage());
  EXPECT_EQ(base::TimeDelta(), logger.GetOngoingTimerDelayForTest());
}

TEST_F(ActivityLoggerTest, OngoingState) {
  const base::TimeDelta kOngoingDelay = base::Seconds(10);
  OngoingStateActivityLogger logger(kOngoingDelay);
  Init(&logger);
  EXPECT_EQ("", PopMessage());

  logger.OnStateChanged("a");
  EXPECT_EQ("", PopMessage());
  EXPECT_EQ(kOngoingDelay, logger.GetOngoingTimerDelayForTest());
  AdvanceTime(kOngoingDelay);
  ASSERT_TRUE(logger.TriggerOngoingTimerForTest());
  EXPECT_EQ("a", PopMessage());

  AdvanceTime(kOngoingDelay / 2);
  logger.OnStateChanged("b");
  AdvanceTime(kOngoingDelay / 2);
  ASSERT_TRUE(logger.TriggerOngoingTimerForTest());
  EXPECT_EQ("b", PopMessage());

  logger.OnStateChanged("");
  EXPECT_EQ(base::TimeDelta(), logger.GetOngoingTimerDelayForTest());
}

}  // namespace power_manager
