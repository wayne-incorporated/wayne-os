// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>

#include <base/check.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cfm-dfu-notification/dfu_log_notification.h"

namespace {

// The Scoped MockLog is inspired by shill/mock_log.h. The shill MockLog is
// not in a library and unfortunately not available to be included here.
// TODO(anchals): Make this into a test helper once more tests use it or
// want to use it. (maybe inside (platform2/cfm-testing))
class ScopedMockLog {
 public:
  ScopedMockLog();
  virtual ~ScopedMockLog();

  MOCK_METHOD(void, Log, (int, const char*, const std::string&));

 private:
  // This function gets invoked by the logging subsystem for each message that
  // is logged.  It calls ScopedMockLog::Log() declared above.  It must be a
  // static method because the logging subsystem does not allow for an object to
  // be passed.  See the typedef LogMessageHandlerFunction in base/logging.h for
  // this function signature.
  static bool HandleLogMessages(int severity,
                                const char* file,
                                int line,
                                size_t message_start,
                                const std::string& full_message);

  // A pointer to the current ScopedMockLog object.
  static ScopedMockLog* instance_;

  // A pointer to any pre-existing message handler function in the logging
  // system.  It is invoked after calling ScopedMockLog::Log().
  ::logging::LogMessageHandlerFunction previous_handler_;
};

ScopedMockLog* ScopedMockLog::instance_ = nullptr;

// static
bool ScopedMockLog::HandleLogMessages(int severity,
                                      const char* file,
                                      int line,
                                      size_t message_start,
                                      const std::string& full_message) {
  CHECK(instance_);

  // |full_message| looks like this if it came through MemoryLog:
  //   "[0514/165501:INFO:mock_log_test.cc(22)] Some message\n"
  // The user wants to match just the substring "Some message".  Strip off the
  // extra stuff.  |message_start| is the position where "Some message" begins.
  //
  // Note that the -1 is to remove the trailing return line.
  const std::string::size_type message_length =
      full_message.length() - message_start - 1;
  const std::string message(full_message, message_start, message_length);

  // Call Log.  Because Log is a mock method, this sets in motion the mocking
  // magic.
  instance_->Log(severity, file, message);

  // Invoke the previously installed message handler if there was one.
  if (instance_->previous_handler_) {
    return (*instance_->previous_handler_)(severity, file, line, message_start,
                                           full_message);
  }

  // Return false so that messages show up on stderr.
  return false;
}

ScopedMockLog::ScopedMockLog() {
  previous_handler_ = ::logging::GetLogMessageHandler();
  ::logging::SetLogMessageHandler(HandleLogMessages);
  instance_ = this;
}

ScopedMockLog::~ScopedMockLog() {
  ::logging::SetLogMessageHandler(previous_handler_);
  instance_ = nullptr;
}

class DfuLogNotificationTest : public testing::Test {
 public:
  DfuLogNotificationTest();
  ~DfuLogNotificationTest() override = default;

 protected:
  DfuLogNotification log_notification_;
};

DfuLogNotificationTest::DfuLogNotificationTest()
    : log_notification_(DfuLogNotification("Huddly IQ")) {}

TEST_F(DfuLogNotificationTest, VerifyStartLogTag) {
  ScopedMockLog log;
  EXPECT_CALL(log, Log(logging::LOGGING_INFO, testing::_,
                       testing::StartsWith("$#StartUpdate$#")));
  log_notification_.NotifyStartUpdate(300);
}

TEST_F(DfuLogNotificationTest, VerifyEndLogTag) {
  ScopedMockLog log;
  EXPECT_CALL(log, Log(logging::LOGGING_INFO, testing::_,
                       testing::StartsWith("$#EndUpdate$#")));
  log_notification_.NotifyEndUpdate(true);
}

TEST_F(DfuLogNotificationTest, VerifyPostUpdateLogTag) {
  ScopedMockLog log;
  EXPECT_CALL(log, Log(logging::LOGGING_INFO, testing::_,
                       testing::StartsWith("$#UpdateProgress$#")));
  log_notification_.NotifyUpdateProgress(0.3);
}

}  // namespace
