// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <base/files/file_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libhwsec-foundation/tpm_error/handle_auth_failure.cc"

namespace hwsec_foundation {

namespace {

// We used hard-coded hash value to verify if hash values accidentally change
// Note that if wrong_password_hash is changed, the corresponding code in
// crash-reporter should be also changed.
constexpr char sample_message[] = "auth failure: command 1, response 1\n";
constexpr char sample_message2[] = "auth failure: command 207, response 1\n";
constexpr char wrong_password_message[] =
    "auth failure: command 24, response 29\n";
constexpr uint32_t sample_hash = 0xd6ca7f57;
constexpr uint32_t sample_hash2 = 0xb349c715;
constexpr uint32_t wrong_password_hash = 0x2010c9ae;

constexpr struct TpmErrorData sample_data { 1, 1 };

bool HasError() {
  char error_msg[256] = {'\0'};
  int ret = FetchAuthFailureError(error_msg, sizeof(error_msg));
  if (ret && strlen(error_msg) != 0) {
    std::cerr << "error msg: " << error_msg << std::endl;
    return true;
  }
  return false;
}

int CheckHistory(base::FilePath current,
                 base::FilePath previous,
                 size_t* hash) {
  return CheckAuthFailureHistory(current.value().c_str(),
                                 previous.value().c_str(), hash);
}

}  // namespace

TEST(HandleAuthFailureTest, AuthFailureLogging) {
  std::string msg;
  base::FilePath current_log;
  base::FilePath permanent_log;
  base::CreateTemporaryFile(&current_log);
  base::CreateTemporaryFile(&permanent_log);
  // InitializeAuthFailureLogging expects a null log message handler.
  logging::SetLogMessageHandler(nullptr);
  InitializeAuthFailureLogging(current_log.value().c_str(),
                               permanent_log.value().c_str());

  LogAuthFailureCommand(sample_data);
  base::ReadFileToString(permanent_log, &msg);

  struct TpmErrorData data;
  EXPECT_TRUE(RE2::PartialMatch(msg, *auth_failure_command, &data.command,
                                &data.response));
  EXPECT_EQ(data, sample_data);
}

TEST(HandleAuthFailureTest, CheckAuthFailureHistoryExist) {
  size_t hash = 0;
  std::string msg;
  base::FilePath current_log;
  base::FilePath previous_log;
  base::CreateTemporaryFile(&current_log);
  base::CreateTemporaryFile(&previous_log);
  base::WriteFile(current_log, sample_message);

  // Check if error messages are present.
  base::FilePath forbidden("/tmp/a/b/c/d/e");
  EXPECT_FALSE(CheckHistory(current_log, forbidden, &hash));
  EXPECT_TRUE(HasError());
  EXPECT_EQ(hash, 0);

  // Check if the function could properly handle the log.
  hash = 0;
  EXPECT_TRUE(CheckHistory(current_log, previous_log, &hash));
  EXPECT_FALSE(HasError());
  base::ReadFileToString(previous_log, &msg);
  EXPECT_EQ(msg, sample_message);
  EXPECT_NE(hash, 0);

  hash = 0;
  base::WriteFile(current_log, sample_message2);
  EXPECT_TRUE(CheckHistory(current_log, previous_log, &hash));
  EXPECT_FALSE(HasError());
  base::ReadFileToString(previous_log, &msg);
  EXPECT_EQ(msg, sample_message2);
  EXPECT_NE(hash, 0);
}

TEST(HandleAuthFailureTest, CheckAuthFailureHistoryNotExist) {
  base::FilePath current_log;
  base::FilePath previous_log;

  EXPECT_FALSE(CheckHistory(current_log, previous_log, nullptr));
  EXPECT_FALSE(HasError());

  base::CreateTemporaryFile(&current_log);
  base::CreateTemporaryFile(&previous_log);

  EXPECT_FALSE(CheckHistory(current_log, previous_log, nullptr));
  EXPECT_FALSE(HasError());
}

TEST(HandleAuthFailureTest, AppendMessage) {
  base::FilePath log;
  base::CreateTemporaryFile(&log);
  std::string actual_msg;

  // Normally writing message to log file.
  EXPECT_TRUE(AppendMessage(log, sample_message));
  base::ReadFileToString(log, &actual_msg);
  EXPECT_EQ(actual_msg, sample_message);

  // Writing message to log file to reach the limit of log size.
  std::string test_large_msg;
  while (test_large_msg.size() <= kLogMaxSize) {
    test_large_msg += sample_message;
  }
  // Test if the oldest message could be removed when log lines exceed the
  // limit.
  EXPECT_TRUE(AppendMessage(log, test_large_msg));
  base::ReadFileToString(log, &actual_msg);

  EXPECT_EQ(actual_msg.size(), kLogRemainingSize);
}

TEST(HandleAuthFailureTest, GetCommandHash) {
  base::FilePath log;
  base::CreateTemporaryFile(&log);

  EXPECT_TRUE(AppendMessage(log, sample_message));
  size_t hash_x = GetCommandHash(log);
  EXPECT_TRUE(AppendMessage(log, sample_message));
  size_t hash_y = GetCommandHash(log);
  // Hash value of arbitrary number of same message should be identical.
  EXPECT_EQ(hash_x, hash_y);

  EXPECT_TRUE(AppendMessage(log, sample_message2));
  size_t hash_z = GetCommandHash(log);
  // Since we have other message, the hash value should be different.
  EXPECT_NE(hash_x, hash_z);
}

TEST(HandleAuthFailureTest, GetCommandHashStablity) {
  base::FilePath log;
  base::FilePath log2;
  base::FilePath log3;
  base::CreateTemporaryFile(&log);
  base::CreateTemporaryFile(&log2);
  base::CreateTemporaryFile(&log3);

  EXPECT_TRUE(AppendMessage(log, sample_message));
  EXPECT_EQ(GetCommandHash(log), sample_hash);

  EXPECT_TRUE(AppendMessage(log2, sample_message2));
  EXPECT_EQ(GetCommandHash(log2), sample_hash2);

  EXPECT_TRUE(AppendMessage(log3, wrong_password_message));
  EXPECT_EQ(GetCommandHash(log3), wrong_password_hash);
}

}  // namespace hwsec_foundation
