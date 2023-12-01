// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "timberslide/mock_timberslide.h"
#include "timberslide/timberslide.h"

using testing::_;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;

namespace timberslide {
namespace {

const char kSampleLogs[] =
    "[0.001000 UART initialized after sysjump]\n"
    "[1.000000 Sensor create: 0x0]\n";

const char kExpectedLogsWithUptime[] =
    "1970-01-01T00:00:00.001000Z [0.001000 UART initialized after sysjump]\n"
    "1970-01-01T00:00:01.000000Z [1.000000 Sensor create: 0x0]\n";

const char kExpectedLogsWithoutUptime[] =
    "1970-01-01T00:00:00.000000Z [0.001000 UART initialized after sysjump]\n"
    "1970-01-01T00:00:00.000000Z [1.000000 Sensor create: 0x0]\n";

class LogListenerImplMock : public LogListener {
 public:
  MOCK_METHOD(void, OnLogLine, (const std::string&), (override));
};

TEST(TimberslideTest, ProcessLogBuffer_GetEcUptimeSupported) {
  auto now = base::Time::FromDoubleT(1.0);
  NiceMock<MockTimberSlide> mock;
  EXPECT_CALL(mock, GetEcUptime).WillOnce([](int64_t* time) {
    *time = 1 * base::Time::kMillisecondsPerSecond;
    return true;
  });
  std::string ret = mock.ProcessLogBuffer(kSampleLogs, now);
  EXPECT_EQ(ret, kExpectedLogsWithUptime);
}

TEST(TimberslideTest, ProcessLogBuffer_GetEcUptimeNotSupported) {
  auto now = base::Time::FromDoubleT(1.0);
  NiceMock<MockTimberSlide> mock;
  EXPECT_CALL(mock, GetEcUptime).WillOnce(Return(false));
  std::string ret = mock.ProcessLogBuffer(kSampleLogs, now);
  EXPECT_EQ(ret, kExpectedLogsWithoutUptime);
}

class TimberslideLogLineTest : public testing::TestWithParam<bool> {};

TEST_P(TimberslideLogLineTest, ProcessLogBuffer_OnLogLine) {
  base::Time now;
  auto metrics_listener = std::make_unique<LogListenerImplMock>();
  EXPECT_CALL(*metrics_listener, OnLogLine)
      .WillOnce([](const std::string& line) {
        EXPECT_EQ(line, "[0.001000 UART initialized after sysjump]");
      })
      .WillOnce([](const std::string& line) {
        EXPECT_EQ(line, "[1.000000 Sensor create: 0x0]");
      });
  NiceMock<MockTimberSlide> mock(std::move(metrics_listener));
  // We only pass the original EC log line to OnLogLine, not the additional
  // timestamp we add if uptime is supported, so we test both variants.
  ON_CALL(mock, GetEcUptime).WillByDefault(Return(GetParam()));
  std::string ret = mock.ProcessLogBuffer(kSampleLogs, now);
}

INSTANTIATE_TEST_SUITE_P(TimberslideTest,
                         TimberslideLogLineTest,
                         testing::Bool(),
                         testing::PrintToStringParamName());

}  // namespace
}  // namespace timberslide
