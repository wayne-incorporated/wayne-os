// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/crash_sender_base.h"

#include <string>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/strcat.h>
#include <brillo/key_value_store.h>
#include <gtest/gtest.h>

#include "crash-reporter/crash_sender_paths.h"
#include "crash-reporter/paths.h"
#include "crash-reporter/test_util.h"

namespace util {
namespace {
using ::testing::_;
using ::testing::Not;
using ::testing::StartsWith;

constexpr char kFakeClientId[] = "00112233445566778899aabbccddeeff";

// Creates the client ID file and stores the fake client ID in it.
bool CreateClientIdFile() {
  return test_util::CreateFile(
      paths::GetAt(paths::kCrashSenderStateDirectory, paths::kClientId),
      kFakeClientId);
}

// Set the file flag which indicates we are mocking crash sending, either
// successfully or as a a failure. This also creates the directory where
// uploads.log is written to since Chrome would normally be doing that.
bool SetMockCrashSending(bool success) {
  util::g_force_is_mock = true;
  util::g_force_is_mock_successful = success;
  return base::CreateDirectory(
      paths::Get(paths::ChromeCrashLog::Get()).DirName());
}

// Reset "force" flags to clear out IsMock flags
void ClearMockCrashSending() {
  util::g_force_is_mock = false;
  util::g_force_is_mock_successful = false;
}

// Set the flag which indicates we're mocking crash sending for Integration
// Tests, successfully or as a failure.
bool SetIntegrationTesting(bool success) {
  return test_util::CreateFile(paths::GetAt(paths::kSystemRunStateDirectory,
                                            paths::kMockCrashSending),
                               success ? "" : "0") &&
         base::CreateDirectory(
             paths::Get(paths::ChromeCrashLog::Get()).DirName());
}

class CrashSenderBaseForTesting : public util::SenderBase {
 public:
  CrashSenderBaseForTesting(std::unique_ptr<base::Clock> clock,
                            const Options& options)
      : util::SenderBase(std::move(clock), options) {
    // These methods are not implemented in this test and should not
    // be called.
    EXPECT_CALL(*this, MakeScopedProcessingFile(_)).Times(0);
    EXPECT_CALL(*this, RecordCrashRemoveReason(_)).Times(0);
  }

 private:
  MOCK_METHOD(std::unique_ptr<ScopedProcessingFileBase>,
              MakeScopedProcessingFile,
              (const base::FilePath& meta_file),
              (override));
  MOCK_METHOD(void,
              RecordCrashRemoveReason,
              (CrashRemoveReason reason),
              (override));
};

class CrashSenderBaseTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    test_dir_ = temp_dir_.GetPath();
    paths::SetPrefixForTesting(test_dir_);
  }

  void TearDown() override {
    ClearMockCrashSending();
    paths::SetPrefixForTesting(base::FilePath());
  }

  base::ScopedTempDir temp_dir_;
  base::FilePath test_dir_;
};

TEST_F(CrashSenderBaseTest, GetFilePathFromMetadata) {
  brillo::KeyValueStore metadata;
  metadata.LoadFromString("");
  EXPECT_EQ("", GetFilePathFromMetadata(metadata, "payload").value());

  metadata.LoadFromString("payload=test.log\n");
  EXPECT_EQ("test.log", GetFilePathFromMetadata(metadata, "payload").value());

  metadata.LoadFromString("payload=/foo/test.log\n");
  EXPECT_EQ("/foo/test.log",
            GetFilePathFromMetadata(metadata, "payload").value());
}

TEST_F(CrashSenderBaseTest, GetKindFromPayloadPath) {
  EXPECT_EQ("", GetKindFromPayloadPath(base::FilePath()));
  EXPECT_EQ("", GetKindFromPayloadPath(base::FilePath("foo")));
  EXPECT_EQ("log", GetKindFromPayloadPath(base::FilePath("foo.log")));
  EXPECT_EQ("txt", GetKindFromPayloadPath(base::FilePath("foo.txt")));
  // "dmp" is a special case.
  EXPECT_EQ("minidump", GetKindFromPayloadPath(base::FilePath("foo.dmp")));

  // ".gz" should be ignored.
  EXPECT_EQ("log", GetKindFromPayloadPath(base::FilePath("foo.log.gz")));
  EXPECT_EQ("minidump", GetKindFromPayloadPath(base::FilePath("foo.dmp.gz")));
  EXPECT_EQ("", GetKindFromPayloadPath(base::FilePath("foo.gz")));

  // The directory name should not affect the function.
  EXPECT_EQ("minidump",
            GetKindFromPayloadPath(base::FilePath("/1.2.3/foo.dmp.gz")));
}

TEST_F(CrashSenderBaseTest, ParseMetadata) {
  brillo::KeyValueStore metadata;
  std::string value;
  EXPECT_TRUE(ParseMetadata("", &metadata));
  EXPECT_TRUE(ParseMetadata("log=test.log\n", &metadata));
  EXPECT_TRUE(ParseMetadata("#comment\nlog=test.log\n", &metadata));

  EXPECT_TRUE(metadata.GetString("log", &value));
  // This will clear the previously parsed data.
  EXPECT_TRUE(ParseMetadata("payload=test.dmp\n", &metadata));
  EXPECT_FALSE(metadata.GetString("log", &value));

  // Underscores, dashes, and periods should allowed, as Chrome uses them.
  // https://crbug.com/821530.
  EXPECT_TRUE(ParseMetadata("abcABC012_.-=test.log\n", &metadata));
  EXPECT_TRUE(metadata.GetString("abcABC012_.-", &value));
  EXPECT_EQ("test.log", value);
  // Invalid upload paths should still be parseable
  EXPECT_TRUE(ParseMetadata("payload=a.d.dmp\nupload_file_=/\n", &metadata));

  // Invalid metadata should be detected.
  EXPECT_FALSE(ParseMetadata("=test.log\n", &metadata));
  EXPECT_FALSE(ParseMetadata("***\n", &metadata));
  EXPECT_FALSE(ParseMetadata("***=test.log\n", &metadata));
  EXPECT_FALSE(ParseMetadata("log\n", &metadata));
}

TEST_F(CrashSenderBaseTest, IsCompleteMetadata) {
  brillo::KeyValueStore metadata;
  metadata.LoadFromString("");
  EXPECT_FALSE(IsCompleteMetadata(metadata));

  metadata.LoadFromString("log=test.log\n");
  EXPECT_FALSE(IsCompleteMetadata(metadata));

  metadata.LoadFromString("log=test.log\ndone=1\n");
  EXPECT_TRUE(IsCompleteMetadata(metadata));

  metadata.LoadFromString("done=1\n");
  EXPECT_TRUE(IsCompleteMetadata(metadata));
}

TEST_F(CrashSenderBaseTest, ReadMetaFile_BlockAbsoluteAttachments) {
  const base::FilePath meta_file = test_dir_.Append("read_meta_file.meta");
  const base::FilePath payload_file = test_dir_.Append("read_meta_file.xyz");
  const base::FilePath log_file = test_dir_.Append("read_meta_file.log");
  const base::FilePath log2_file = test_dir_.Append("read_meta_file2.log");
  const std::string meta =
      base::StrCat({"payload=read_meta_file.xyz\n"
                    "exec_name=exec_bar\n"
                    "fake_report_id=456\n"
                    "upload_var_prod=bar\n"
                    "upload_file_test.log=",
                    log_file.value(),
                    "\n"
                    "upload_text_test2.log=",
                    log2_file.value(),
                    "\n"
                    "done=1\n"});
  ASSERT_TRUE(test_util::CreateFile(meta_file, meta));
  ASSERT_TRUE(test_util::CreateFile(payload_file, "payload file"));
  ASSERT_TRUE(test_util::CreateFile(log_file, "log file"));
  ASSERT_TRUE(test_util::CreateFile(log2_file, "log file 2"));
  brillo::KeyValueStore metadata;
  EXPECT_TRUE(ParseMetadata(meta, &metadata));

  const util::CrashDetails details = {
      .meta_file = meta_file,
      .payload_file = payload_file.BaseName(),
      .payload_kind = "log",
      .client_id = "client",
      .metadata = metadata,
  };

  SenderBase::Options options;
  CrashSenderBaseForTesting sender(
      std::make_unique<test_util::AdvancingClock>(), options);
  FullCrash crash = sender.ReadMetaFile(details);

  int log_files_blocked = 0;
  for (const auto& kv : crash.key_vals) {
    const std::string& key = kv.first;
    const std::string& val = kv.second;
    EXPECT_THAT(key, Not(StartsWith("upload_file_")));
    EXPECT_THAT(key, Not(StartsWith("upload_text_")));
    if (key == "file_blocked_by_path") {
      EXPECT_TRUE(val == log_file.value() || val == log2_file.value());
      log_files_blocked++;
    }
  }

  EXPECT_EQ(2, log_files_blocked);
}

TEST_F(CrashSenderBaseTest, CreateClientId) {
  std::string client_id = GetClientId();
  EXPECT_EQ(client_id.length(), 32);
  // Make sure it returns the same one multiple times.
  EXPECT_EQ(client_id, GetClientId());
}

TEST_F(CrashSenderBaseTest, RetrieveClientId) {
  CreateClientIdFile();
  EXPECT_EQ(kFakeClientId, GetClientId());
}

TEST_F(CrashSenderBaseTest, GetSleepTime) {
  const base::FilePath meta_file = test_dir_.Append("test.meta");
  base::TimeDelta max_spread_time = base::Seconds(0);

  // This should fail since meta_file does not exist.
  base::TimeDelta sleep_time;
  EXPECT_FALSE(
      GetSleepTime(meta_file, max_spread_time, kMaxHoldOffTime, &sleep_time));

  ASSERT_TRUE(test_util::CreateFile(meta_file, ""));

  // sleep_time should be close enough to kMaxHoldOffTime since the meta file
  // was just created, but 10% error is allowed just in case.
  EXPECT_TRUE(
      GetSleepTime(meta_file, max_spread_time, kMaxHoldOffTime, &sleep_time));
  EXPECT_NEAR(kMaxHoldOffTime.InSecondsF(), sleep_time.InSecondsF(),
              kMaxHoldOffTime.InSecondsF() * 0.1);

  // Zero hold-off time and zero sleep time should always give zero sleep time.
  EXPECT_TRUE(GetSleepTime(meta_file, max_spread_time,
                           base::Seconds(0) /*hold_off_time*/, &sleep_time));
  EXPECT_EQ(base::Seconds(0), sleep_time);

  // Even if file is new, a zero hold-off time means we choose a time between
  // 0 and max_spread_time.
  ASSERT_TRUE(test_util::TouchFileHelper(meta_file, base::Time::Now()));
  EXPECT_TRUE(GetSleepTime(meta_file, base::Seconds(60) /*max_spread_time*/,
                           base::Seconds(0) /*hold_off_time*/, &sleep_time));
  EXPECT_LE(base::Seconds(0), sleep_time);
  EXPECT_GE(base::Seconds(60), sleep_time);

  // Make the meta file old enough so hold-off time is not necessary.
  const base::Time now = base::Time::Now();
  ASSERT_TRUE(test_util::TouchFileHelper(meta_file, now - kMaxHoldOffTime));

  // sleep_time should always be 0, since max_spread_time is set to 0.
  EXPECT_TRUE(
      GetSleepTime(meta_file, max_spread_time, kMaxHoldOffTime, &sleep_time));
  EXPECT_EQ(base::Seconds(0), sleep_time);

  // sleep_time should be in range [0, 10].
  max_spread_time = base::Seconds(10);
  EXPECT_TRUE(
      GetSleepTime(meta_file, max_spread_time, kMaxHoldOffTime, &sleep_time));
  EXPECT_LE(base::Seconds(0), sleep_time);
  EXPECT_GE(base::Seconds(10), sleep_time);

  // If the meta file is current, the minimum sleep time should be
  // kMaxHoldOffTime but the maximum is still max_spread_time.
  max_spread_time = base::Seconds(60);
  ASSERT_TRUE(test_util::TouchFileHelper(meta_file, base::Time::Now()));
  EXPECT_TRUE(
      GetSleepTime(meta_file, max_spread_time, kMaxHoldOffTime, &sleep_time));
  // 0.9 in case we got preempted for 3 seconds between the file touch and the
  // GetSleepTime().
  EXPECT_LE(kMaxHoldOffTime * 0.9, sleep_time);
  EXPECT_GE(base::Seconds(60), sleep_time);
}

TEST_F(CrashSenderBaseTest, IsMock) {
  // Ensure the state is clean
  EXPECT_FALSE(IsMock());
  EXPECT_FALSE(IsIntegrationTest());

  ASSERT_TRUE(SetMockCrashSending(false));
  EXPECT_TRUE(IsMock());
  EXPECT_FALSE(IsMockSuccessful());
  EXPECT_FALSE(IsIntegrationTest());  // Shouldn't change

  ASSERT_TRUE(SetMockCrashSending(true));
  EXPECT_TRUE(IsMock());
  EXPECT_TRUE(IsMockSuccessful());
  EXPECT_FALSE(IsIntegrationTest());  // Shouldn't change

  ClearMockCrashSending();
  EXPECT_FALSE(IsMock());
}

// Ensure that IsIntegrationTest implies IsMock, but not the opposite
TEST_F(CrashSenderBaseTest, IsIntegrationTest) {
  EXPECT_FALSE(IsMock());
  EXPECT_FALSE(IsIntegrationTest());

  ASSERT_TRUE(SetIntegrationTesting(false));
  EXPECT_TRUE(IsIntegrationTest());
  EXPECT_TRUE(IsMock());
  EXPECT_FALSE(IsMockSuccessful());

  ASSERT_TRUE(SetIntegrationTesting(true));
  EXPECT_TRUE(IsIntegrationTest());
  EXPECT_TRUE(IsMock());
  EXPECT_TRUE(IsMockSuccessful());
}

TEST_F(CrashSenderBaseTest, GetImageType) {
  EXPECT_EQ("", GetImageType());
  ASSERT_TRUE(SetMockCrashSending(false));
  EXPECT_EQ("mock-fail", GetImageType());
  ASSERT_TRUE(test_util::CreateFile(paths::Get(paths::kLeaveCoreFile), ""));
  EXPECT_EQ("dev", GetImageType());
  ASSERT_TRUE(test_util::CreateFile(
      paths::GetAt(paths::kEtcDirectory, paths::kLsbRelease),
      "CHROMEOS_RELEASE_TRACK=testimage-channel"));
  EXPECT_EQ("test", GetImageType());
}

TEST_F(CrashSenderBaseTest, ScopedProcessingFile) {
  const base::FilePath meta_file = test_dir_.Append("meta_file.meta");
  const base::FilePath processing_file =
      test_dir_.Append("meta_file.processing");
  ASSERT_TRUE(test_util::CreateFile(meta_file, ""));

  ASSERT_FALSE(base::PathExists(processing_file));
  {
    ScopedProcessingFile processing(meta_file);
    EXPECT_TRUE(base::PathExists(processing_file));
  }
  EXPECT_FALSE(base::PathExists(processing_file));
}

TEST_F(CrashSenderBaseTest, DummyScopedProcessingFile) {
  const base::FilePath meta_file = test_dir_.Append("meta_file.meta");
  const base::FilePath processing_file =
      test_dir_.Append("meta_file.processing");
  ASSERT_TRUE(test_util::CreateFile(meta_file, ""));

  ASSERT_FALSE(base::PathExists(processing_file));
  {
    DummyScopedProcessingFile processing(meta_file);
    EXPECT_FALSE(base::PathExists(processing_file));
  }
  EXPECT_FALSE(base::PathExists(processing_file));
}

}  // namespace
}  // namespace util
