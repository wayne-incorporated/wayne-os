// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/clobber_state_collector.h"

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "crash-reporter/test_util.h"

namespace {

using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::Return;

// Log config file name.
const char kLogConfigFileName[] = "log_config_file";
const char kTmpfilesLogName[] = "tmpfiles.log";

// A bunch of random rules to put into the log config file.
const char kLogConfigFileContents[] =
    "clobber-state=echo 'found clobber.log'\n";

class ClobberStateCollectorMock : public ClobberStateCollector {
 public:
  ClobberStateCollectorMock() : ClobberStateCollector() {}
  MOCK_METHOD(void, SetUpDBus, (), (override));

  void set_tmpfiles_log(const base::FilePath& tmpfiles_log) {
    tmpfiles_log_ = tmpfiles_log;
  }
};

void Initialize(ClobberStateCollectorMock* collector,
                base::ScopedTempDir* scoped_tmp_dir,
                const std::string& contents) {
  ASSERT_TRUE(scoped_tmp_dir->CreateUniqueTempDir());
  EXPECT_CALL(*collector, SetUpDBus()).WillRepeatedly(Return());
  base::FilePath log_config_path =
      scoped_tmp_dir->GetPath().Append(kLogConfigFileName);
  ASSERT_TRUE(test_util::CreateFile(log_config_path, kLogConfigFileContents));

  base::FilePath tmpfiles_log_path =
      scoped_tmp_dir->GetPath().Append(kTmpfilesLogName);
  ASSERT_TRUE(test_util::CreateFile(tmpfiles_log_path, contents));
  collector->set_tmpfiles_log(tmpfiles_log_path);

  collector->Initialize(false);

  collector->set_crash_directory_for_test(scoped_tmp_dir->GetPath());
  collector->set_log_config_path(log_config_path.value());
}

}  // namespace

TEST(ClobberStateCollectorTest, TestClobberState) {
  ClobberStateCollectorMock collector;
  base::ScopedTempDir tmp_dir;
  base::FilePath meta_path;
  base::FilePath report_path;
  std::string report_contents;

  constexpr const char kTmpfilesContents[] =
      "/usr/lib/tmpfiles.d/vm_tools.conf:35: Duplicate line for path"
      "\"/run/arc/sdcard\", ignoring.\n"
      "contents of tmpfiles.log\n";
  Initialize(&collector, &tmp_dir, kTmpfilesContents);

  EXPECT_TRUE(collector.Collect());

  // Check report collection.
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      tmp_dir.GetPath(), "clobber_state.*.meta", &meta_path));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      tmp_dir.GetPath(), "clobber_state.*.log", &report_path));

  // Check meta contents.
  std::string meta_contents;
  EXPECT_TRUE(base::ReadFileToString(meta_path, &meta_contents));
  EXPECT_THAT(meta_contents, HasSubstr("sig=contents of tmpfiles.log"));

  // Check report contents.
  EXPECT_TRUE(base::ReadFileToString(report_path, &report_contents));
  EXPECT_EQ("found clobber.log\n", report_contents);
}

TEST(ClobberStateCollectorTest, TestClobberState_WarningOnly) {
  ClobberStateCollectorMock collector;
  base::ScopedTempDir tmp_dir;
  base::FilePath meta_path;
  base::FilePath report_path;
  std::string report_contents;

  constexpr const char kTmpfilesContents[] =
      "/usr/lib/tmpfiles.d/vm_tools.conf:35: Duplicate line for path "
      "\"/run/arc/sdcard\", ignoring.\n"
      "/usr/lib/tmpfiles.d/vm_tools.conf:36: Duplicate line for path "
      "\"/run/camera\", ignoring.\n"
      "/usr/lib/tmpfiles.d/vm_tools.conf:38: Duplicate line for path "
      "\"/run/perfetto\", ignoring.\nignoring.";
  Initialize(&collector, &tmp_dir, kTmpfilesContents);

  EXPECT_TRUE(collector.Collect());

  // Check report collection.
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      tmp_dir.GetPath(), "clobber_state.*.meta", &meta_path));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      tmp_dir.GetPath(), "clobber_state.*.log", &report_path));

  // Check meta contents.
  std::string meta_contents;
  EXPECT_TRUE(base::ReadFileToString(meta_path, &meta_contents));
  EXPECT_THAT(meta_contents, HasSubstr(std::string("sig=") + kNoErrorLogged));

  // Check report contents.
  EXPECT_TRUE(base::ReadFileToString(report_path, &report_contents));
  EXPECT_EQ("found clobber.log\n", report_contents);
}

TEST(ClobberStateCollectorTest, TestClobberState_KnownIssue) {
  static constexpr const struct {
    const char* log;
    const char* sig;
  } test_cases[] = {
      {"Failed to create directory or subvolume "
       "\"/var/lib/metrics/structured\": Bad message",
       "sig=Bad message"},
      {"Failed to create directory or subvolume "
       "\"/var/lib/metrics/structured/chromium\": Input/output error",
       "sig=Input/output error"},
      {"\tFailed to create directory or subvolume \"/var/log/vmlog\": "
       "No space left on device",
       "sig=No space left on device"},
      {"rm_rf(/var/lib/dbus/machine-id): Read-only file system",
       "sig=Read-only file system"},
      {"/usr/lib/tmpfiles.d/vm_tools.conf:35: Duplicate line for path"
       "\"/run/arc/sdcard\", ignoring.\n"
       "Failed to open directory 'cras': Structure needs cleaning\n",
       "sig=Structure needs cleaning"},
  };

  for (const auto& test_case : test_cases) {
    ClobberStateCollectorMock collector;
    base::ScopedTempDir tmp_dir;
    base::FilePath meta_path;
    base::FilePath report_path;
    std::string report_contents;
    Initialize(&collector, &tmp_dir, test_case.log);

    EXPECT_TRUE(collector.Collect());

    // Check report collection.
    EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
        tmp_dir.GetPath(), "clobber_state.*.meta", &meta_path));
    EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
        tmp_dir.GetPath(), "clobber_state.*.log", &report_path));

    // Check meta contents.
    std::string meta_contents;
    EXPECT_TRUE(base::ReadFileToString(meta_path, &meta_contents));
    EXPECT_THAT(meta_contents, HasSubstr(test_case.sig));

    // Check report contents.
    EXPECT_TRUE(base::ReadFileToString(report_path, &report_contents));
    EXPECT_EQ("found clobber.log\n", report_contents);
  }
}
