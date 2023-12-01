// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_TIMER_MOCK_H_
#define METRICS_TIMER_MOCK_H_

#include <string>

#include <gmock/gmock.h>

#include "metrics/timer.h"

namespace chromeos_metrics {

class TimerMock : public Timer {
 public:
  MOCK_METHOD(bool, Start, (), (override));
  MOCK_METHOD(bool, Stop, (), (override));
  MOCK_METHOD(bool, Reset, (), (override));
  MOCK_METHOD(bool, HasStarted, (), (const, override));
  MOCK_METHOD(bool, GetElapsedTime, (base::TimeDelta*), (const, override));
};

class TimerReporterMock : public TimerReporter {
 public:
  TimerReporterMock() : TimerReporter("", 0, 0, 0) {}
  MOCK_METHOD(bool, Start, (), (override));
  MOCK_METHOD(bool, Stop, (), (override));
  MOCK_METHOD(bool, Reset, (), (override));
  MOCK_METHOD(bool, HasStarted, (), (const, override));
  MOCK_METHOD(bool, GetElapsedTime, (base::TimeDelta*), (const, override));
  MOCK_METHOD(bool, ReportMilliseconds, (), (const, override));
  MOCK_METHOD(bool, ReportSeconds, (), (const, override));
};

class ClockWrapperMock : public ClockWrapper {
 public:
  MOCK_METHOD(base::TimeTicks, GetCurrentTime, (), (const, override));
};

}  // namespace chromeos_metrics

#endif  // METRICS_TIMER_MOCK_H_
