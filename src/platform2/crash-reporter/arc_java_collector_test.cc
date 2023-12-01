// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/arc_java_collector.h"

#include <inttypes.h>

#include <memory>
#include <sstream>
#include <utility>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/stringprintf.h>
#include <base/test/simple_test_clock.h>
#include <gtest/gtest.h>

#include "crash-reporter/arc_util.h"
#include "crash-reporter/paths.h"
#include "crash-reporter/test_util.h"
#include "crash-reporter/util.h"

namespace {

constexpr char kTestCrashDirectory[] = "test-crash-directory";
constexpr int64_t kFakeNow = 1598929274543LL;
constexpr char kKernelName[] = "Linux";
constexpr char kKernelVersion[] = "3.8.11 #1 SMP Wed Aug 22 02:18:30 PDT 2018";
constexpr char kLsbContents[] =
    "CHROMEOS_RELEASE_BOARD=lumpy\n"
    "CHROMEOS_RELEASE_VERSION=6727.0.2015_01_26_0853\n"
    "CHROMEOS_RELEASE_NAME=Chromium OS\n"
    "CHROMEOS_RELEASE_CHROME_MILESTONE=82\n"
    "CHROMEOS_RELEASE_TRACK=beta-channel\n"
    "CHROMEOS_RELEASE_DESCRIPTION=6727.0.2015_01_26_0853 (Test Build - foo)";
const base::Time kFakeOsTime = base::Time::UnixEpoch() + base::Days(1234);

}  // namespace

class TestArcJavaCollector : public ArcJavaCollector {
 public:
  explicit TestArcJavaCollector(const base::FilePath& crash_directory) {
    Initialize(false /* early */);
    set_crash_directory_for_test(crash_directory);
  }
  ~TestArcJavaCollector() override = default;

  bool HasMetaData(const std::string& key, const std::string& value) const {
    const std::string metadata =
        base::StringPrintf("%s=%s\n", key.c_str(), value.c_str());
    return extra_metadata_.find(metadata) != std::string::npos;
  }
};

class ArcJavaCollectorTest : public ::testing::Test {
 public:
  ~ArcJavaCollectorTest() override = default;

  void SetUp() override {
    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());

    test_crash_directory_ =
        scoped_temp_dir_.GetPath().Append(kTestCrashDirectory);
    ASSERT_TRUE(base::CreateDirectory(test_crash_directory_));

    paths::SetPrefixForTesting(scoped_temp_dir_.GetPath());
    collector_ = std::make_unique<TestArcJavaCollector>(test_crash_directory_);

    std::unique_ptr<base::SimpleTestClock> test_clock =
        std::make_unique<base::SimpleTestClock>();
    test_clock->SetNow(base::Time::UnixEpoch() + base::Milliseconds(kFakeNow));
    collector_->set_test_clock(std::move(test_clock));
    collector_->set_test_kernel_info(kKernelName, kKernelVersion);

    base::FilePath lsb_release =
        paths::Get(paths::kEtcDirectory).Append("lsb-release");
    ASSERT_TRUE(test_util::CreateFile(lsb_release, kLsbContents));
    ASSERT_TRUE(base::TouchFile(lsb_release, kFakeOsTime, kFakeOsTime));
    collector_->set_lsb_release_for_test(lsb_release);
  }

  void TearDown() override { paths::SetPrefixForTesting(base::FilePath()); }

 protected:
  base::ScopedTempDir scoped_temp_dir_;
  base::FilePath test_crash_directory_;
  std::unique_ptr<TestArcJavaCollector> collector_;
};

TEST_F(ArcJavaCollectorTest, CreateReportForJavaCrash) {
  const std::string crash_type = "system_app";
  const arc_util::BuildProperty build_property = {
      .device = "rammus_cheets",
      .board = "shyvana",
      .cpu_abi = "x86_64",
      .fingerprint =
          "google/rammus/rammus_cheets:11/R93-14002.0.0/7409467:user/"
          "release-keys",
  };

  arc_util::CrashLogHeaderMap map;
  map["Process"] = "com.android.settings";
  map["PID"] = "2123";
  map["UID"] = "1000";
  map["Flags"] = "0x28c9be45";
  map["Package"] = "com.android.settings v30 (11)";
  map["Foreground"] = "Yes";
  map["Process-Runtime"] = "8274";
  map["Build"] =
      "google/rammus/rammus_cheets:11/R93-14002.0.0/7409467:user/release-keys";

  const std::string exception_info =
      "android.app.RemoteServiceException: shell-induced crash\n"
      "        at "
      "android.app.ActivityThread$H.handleMessage(ActivityThread.java:2005)\n"
      "        at android.os.Handler.dispatchMessage(Handler.java:106)\n"
      "        at android.os.Looper.loop(Looper.java:223)\n"
      "        at android.app.ActivityThread.main(ActivityThread.java:7717)\n"
      "        at java.lang.reflect.Method.invoke(Native Method)\n"
      "        at "
      "com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit."
      "java:592)\n"
      "        at "
      "com.android.internal.os.ZygoteInit.main(ZygoteInit.java:947)\n";
  std::string log =
      "Process: com.android.settings\n"
      "PID: 2123\n"
      "UID: 1000\n"
      "Flags: 0x28c9be45\n"
      "Package: com.android.settings v30 (11)\n"
      "Foreground: Yes\n"
      "Process-Runtime: 8274\n"
      "Build: "
      "google/rammus/rammus_cheets:11/R93-14002.0.0/7409467:user/release-keys\n"
      "\n" +
      exception_info;

  const base::TimeDelta uptime_value = base::Milliseconds(123456);
  const std::string uptime_formatted = "2min 3s";

  bool out_of_capacity = false;
  collector_->CreateReportForJavaCrash(crash_type, build_property, map,
                                       exception_info, log, uptime_value,
                                       &out_of_capacity);

  // check .log file
  base::FilePath log_path;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "com_android_settings.*.*.*.*.log", &log_path));
  std::string log_content;
  EXPECT_TRUE(base::ReadFileToString(log_path, &log_content));
  EXPECT_EQ(log_content, log);

  // check .info file
  base::FilePath info_path;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "com_android_settings.*.*.*.*.info", &info_path));
  std::string info_content;
  EXPECT_TRUE(base::ReadFileToString(info_path, &info_content));
  EXPECT_EQ(info_content, exception_info);

  // check .meta file
  const std::string product_version = arc_util::GetProductVersion();
  const std::string meta_expected = base::StringPrintf(
      "upload_var_collector=ARC_java\n"
      "upload_var_prod=ChromeOS_ARC\n"
      "upload_var_process=com.android.settings\n"
      "upload_var_crash_type=system_app\n"
      "upload_var_chrome_os_version=6727.0.2015_01_26_0853\n"
      "upload_var_uptime=%s\n"
      "upload_var_arc_version=google/rammus/rammus_cheets:11/R93-14002.0.0/"
      "7409467:user/release-keys\n"
      "upload_var_android_version=11\n"
      "upload_var_device=rammus_cheets\n"
      "upload_var_board=shyvana\n"
      "upload_var_cpu_abi=x86_64\n"
      "upload_var_package=com.android.settings v30 (11)\n"
      "upload_text_exception_info=%s\n"
      "upload_var_channel=beta\n"
      "upload_var_reportTimeMillis=%" PRId64
      "\n"
      "exec_name=com.android.settings\n"
      "ver=%s\n"
      "upload_var_lsb-release=6727.0.2015_01_26_0853 (Test Build - foo)\n"
      "upload_var_cros_milestone=82\n"
      "os_millis=%" PRId64
      "\n"
      "upload_var_osName=%s\n"
      "upload_var_osVersion=%s\n"
      "payload=%s\n"
      "done=1\n",
      uptime_formatted.c_str(), info_path.BaseName().value().c_str(), kFakeNow,
      product_version.c_str(),
      (kFakeOsTime - base::Time::UnixEpoch()).InMilliseconds(), kKernelName,
      kKernelVersion, log_path.BaseName().value().c_str());
  base::FilePath meta_path;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "com_android_settings.*.*.*.*.meta", &meta_path));
  std::string meta_content;
  EXPECT_TRUE(base::ReadFileToString(meta_path, &meta_content));
  EXPECT_EQ(meta_content, meta_expected);
}

TEST_F(ArcJavaCollectorTest, AddArcMetaData) {
  const std::string process_name = "com.android.settings";
  const std::string crash_type = "system_app";

  const base::TimeDelta uptime_value =
      base::Milliseconds(123456789);  // 1d 10h 17min 36s
  const std::string uptime_formatted = "1d 10h 17min 36s";

  collector_->AddArcMetaData(process_name, crash_type, uptime_value);
  EXPECT_TRUE(collector_->HasMetaData(arc_util::kProcessField, process_name));
  EXPECT_TRUE(collector_->HasMetaData(arc_util::kCrashTypeField, crash_type));
  EXPECT_TRUE(
      collector_->HasMetaData(arc_util::kUptimeField, uptime_formatted));
}
