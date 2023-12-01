// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/mock_log.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/logging.h"

#include <base/logging.h>

using ::std::string;
using ::testing::_;

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kManager;
static string ObjectID(const testing::Test* m) {
  return "(mock_log_test)";
}
}  // namespace Logging

class MockLogTest : public testing::Test {
 protected:
  MockLogTest() = default;

  void LogSomething(const string& message) const { LOG(INFO) << message; }
  void SlogSomething(testing::Test* t, const string& message) const {
    ScopeLogger::GetInstance()->EnableScopesByName("manager");
    ScopeLogger::GetInstance()->set_verbose_level(2);
    SLOG(t, 2) << message;
    ScopeLogger::GetInstance()->EnableScopesByName("-manager");
    ScopeLogger::GetInstance()->set_verbose_level(0);
  }
};

TEST_F(MockLogTest, MatchMessageOnly) {
  ScopedMockLog log;
  const string kMessage("Something");
  EXPECT_CALL(log, Log(_, _, kMessage));
  LogSomething(kMessage);
}

TEST_F(MockLogTest, MatchSeverityAndMessage) {
  ScopedMockLog log;
  const string kMessage("Something");
  EXPECT_CALL(log, Log(logging::LOGGING_INFO, _, kMessage));
  LogSomething(kMessage);
}

TEST_F(MockLogTest, MatchSeverityAndFileAndMessage) {
  ScopedMockLog log;
  const string kMessage("Something");
  EXPECT_CALL(log, Log(logging::LOGGING_INFO,
                       ::testing::EndsWith("mock_log_test.cc"), kMessage));
  LogSomething(kMessage);
}

TEST_F(MockLogTest, MatchEmptyString) {
  ScopedMockLog log;
  const string kMessage("");
  EXPECT_CALL(log, Log(_, _, kMessage));
  LogSomething(kMessage);
}

TEST_F(MockLogTest, MatchMessageContainsBracketAndNewline) {
  ScopedMockLog log;
  const string kMessage("blah [and more blah] \n yet more blah\n\n\n");
  EXPECT_CALL(log, Log(_, _, kMessage));
  LogSomething(kMessage);
}

TEST_F(MockLogTest, MatchSlog) {
  ScopedMockLog log;
  const string kMessage("Something");
  const string kLogMessage("(anon) Something");
  EXPECT_CALL(log, Log(_, _, kLogMessage));
  SlogSomething(nullptr, kMessage);
}

TEST_F(MockLogTest, MatchSlogWithObject) {
  ScopedMockLog log;
  const string kMessage("Something");
  const string kLogMessage("(mock_log_test) Something");
  EXPECT_CALL(log, Log(_, _, kLogMessage));
  SlogSomething(this, kMessage);
}

TEST_F(MockLogTest, MatchWithGmockMatchers) {
  ScopedMockLog log;
  const string kMessage("Something");
  EXPECT_CALL(log,
              Log(::testing::Lt(::logging::LOGGING_ERROR),
                  ::testing::EndsWith(".cc"), ::testing::StartsWith("Some")));
  LogSomething(kMessage);
}

}  // namespace shill
