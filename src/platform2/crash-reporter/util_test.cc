// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/util.h"

#include <stdlib.h>

#include <fcntl.h>
#include <limits>
#include <memory>
#include <sys/mman.h>

#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/rand_util.h>
#include <base/strings/strcat.h>
#include <base/test/simple_test_clock.h>
#include <base/time/time.h>
#include <libcrossystem/crossystem_fake.h>
#include <brillo/process/process.h>
#include <brillo/streams/memory_stream.h>
#include <brillo/syslog_logging.h>
#include <gtest/gtest.h>

#include "crash-reporter/crash_sender_paths.h"
#include "crash-reporter/crossystem.h"
#include "crash-reporter/paths.h"
#include "crash-reporter/test_util.h"
#include "metrics/metrics_library_mock.h"

// The QEMU emulator we use to run unit tests on simulated ARM boards does not
// support memfd_create. (https://bugs.launchpad.net/qemu/+bug/1734792) Skip
// tests that rely on memfd_create on ARM boards.
#if defined(ARCH_CPU_ARM_FAMILY)
#define DISABLED_ON_QEMU_FOR_MEMFD_CREATE(test_name) DISABLED_##test_name
#else
#define DISABLED_ON_QEMU_FOR_MEMFD_CREATE(test_name) test_name
#endif

namespace util {
namespace {

using ::testing::AllOf;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Optional;
using ::testing::StrEq;

constexpr char kLsbReleaseContents[] =
    "CHROMEOS_RELEASE_BOARD=bob\n"
    "CHROMEOS_RELEASE_NAME=Chromium OS\n"
    "CHROMEOS_RELEASE_VERSION=10964.0.2018_08_13_1405\n";

constexpr char kHwClassContents[] = "fake_hwclass";

constexpr char kGzipPath[] = "/bin/gzip";

constexpr char kSemiRandomData[] =
    "ABJCI239AJSDLKJ;kalkjkjsd98723;KJHASD87;kqw3p088ad;lKJASDP823;KJ";
constexpr int kRandomDataMinLength = 32768;   // 32kB
constexpr int kRandomDataMaxLength = 262144;  // 256kB

constexpr char kReadFdToStreamContents[] = "1234567890";

constexpr char kLdArgv0[] = "LD_ARGV0";

// Verifies that |raw_file| corresponds to the gzip'd version of
// |compressed_file| by decompressing it and comparing the contents. Returns
// true if they match, false otherwise. This will overwrite the contents of
// |compressed_file| in the process of doing this.
bool VerifyCompression(const base::FilePath& raw_file,
                       const base::FilePath& compressed_file) {
  if (!base::PathExists(raw_file)) {
    LOG(ERROR) << "raw_file doesn't exist for verifying compression: "
               << raw_file.value();
    return false;
  }
  if (!base::PathExists(compressed_file)) {
    LOG(ERROR) << "compressed_file doesn't exist for verifying compression: "
               << compressed_file.value();
    return false;
  }
  brillo::ProcessImpl proc;
  proc.AddArg(kGzipPath);
  proc.AddArg("-d");  // decompress
  proc.AddArg(compressed_file.value());
  std::string error;
  const int res = util::RunAndCaptureOutput(&proc, STDERR_FILENO, &error);
  if (res < 0) {
    PLOG(ERROR) << "Failed to execute gzip";
    return false;
  }
  if (res != 0) {
    LOG(ERROR) << "Failed to un-gzip " << compressed_file.value();
    util::LogMultilineError(error);
    return false;
  }
  base::FilePath uncompressed_file = compressed_file.RemoveFinalExtension();
  std::string raw_contents;
  std::string uncompressed_contents;
  if (!base::ReadFileToString(raw_file, &raw_contents)) {
    LOG(ERROR) << "Failed reading in raw_file " << raw_file.value();
    return false;
  }
  if (!base::ReadFileToString(uncompressed_file, &uncompressed_contents)) {
    LOG(ERROR) << "Failed reading in uncompressed_file "
               << uncompressed_file.value();
    return false;
  }
  return raw_contents == uncompressed_contents;
}

// We use a somewhat random string of ASCII data to better reflect the data we
// would be compressing for real. We also shouldn't use something like
// base::RandBytesAsString() because that will generate uniformly random data
// which does not compress.
std::string CreateSemiRandomString(size_t size) {
  std::string result;
  result.reserve(size);
  while (result.length() < size) {
    int rem = size - result.length();
    if (rem > sizeof(kSemiRandomData) - 1)
      rem = sizeof(kSemiRandomData) - 1;
    int rand_start = base::RandInt(0, rem - 1);
    int rand_end = base::RandInt(rand_start + 1, rem);
    result.append(&kSemiRandomData[rand_start], rand_end - rand_start);
  }
  return result;
}

}  // namespace

class CrashCommonUtilTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
    test_dir_ = scoped_temp_dir_.GetPath();
    paths::SetPrefixForTesting(test_dir_);
    base::FilePath file = scoped_temp_dir_.GetPath().Append("tmpfile");
    ASSERT_TRUE(test_util::CreateFile(file, kReadFdToStreamContents));
    fd_ = open(file.value().c_str(), O_RDONLY);

    // We need to properly init the CommandLine object for the metrics tests,
    // which log it.
    base::CommandLine::Init(0, nullptr);
  }

  void TearDown() override { paths::SetPrefixForTesting(base::FilePath()); }

  base::FilePath test_dir_;
  base::ScopedTempDir scoped_temp_dir_;
  unsigned int fd_;
};

TEST_F(CrashCommonUtilTest, IsCrashTestInProgress) {
  EXPECT_FALSE(IsCrashTestInProgress());
  ASSERT_TRUE(
      test_util::CreateFile(paths::GetAt(paths::kSystemRunStateDirectory,
                                         paths::kCrashTestInProgress),
                            ""));
  EXPECT_TRUE(IsCrashTestInProgress());
}

TEST_F(CrashCommonUtilTest, IsDeviceCoredumpUploadAllowed) {
  EXPECT_FALSE(IsDeviceCoredumpUploadAllowed());
  ASSERT_TRUE(
      test_util::CreateFile(paths::GetAt(paths::kCrashReporterStateDirectory,
                                         paths::kDeviceCoredumpUploadAllowed),
                            ""));
  EXPECT_TRUE(IsDeviceCoredumpUploadAllowed());
}

TEST_F(CrashCommonUtilTest, IsDeveloperImage) {
  EXPECT_FALSE(IsDeveloperImage());

  ASSERT_TRUE(test_util::CreateFile(paths::Get(paths::kLeaveCoreFile), ""));
  EXPECT_TRUE(IsDeveloperImage());

  ASSERT_TRUE(
      test_util::CreateFile(paths::GetAt(paths::kSystemRunStateDirectory,
                                         paths::kCrashTestInProgress),
                            ""));
  EXPECT_FALSE(IsDeveloperImage());
}

TEST_F(CrashCommonUtilTest, IsTestImage) {
  EXPECT_FALSE(IsTestImage());

  // Should return false because the channel is stable.
  ASSERT_TRUE(test_util::CreateFile(
      paths::GetAt(paths::kEtcDirectory, paths::kLsbRelease),
      "CHROMEOS_RELEASE_TRACK=stable-channel"));
  EXPECT_FALSE(IsTestImage());

  // Should return true because the channel is testimage.
  ASSERT_TRUE(test_util::CreateFile(
      paths::GetAt(paths::kEtcDirectory, paths::kLsbRelease),
      "CHROMEOS_RELEASE_TRACK=testimage-channel"));
  EXPECT_TRUE(IsTestImage());

  // Should return false if kCrashTestInProgress is present.
  ASSERT_TRUE(
      test_util::CreateFile(paths::GetAt(paths::kSystemRunStateDirectory,
                                         paths::kCrashTestInProgress),
                            ""));
  EXPECT_FALSE(IsTestImage());
}

TEST_F(CrashCommonUtilTest, IsOfficialImage) {
  EXPECT_FALSE(IsOfficialImage());

  // Check if lsb-release is handled correctly.
  ASSERT_TRUE(test_util::CreateFile(
      paths::Get("/etc/lsb-release"),
      "CHROMEOS_RELEASE_DESCRIPTION=10964.0 (Test Build) developer-build"));
  EXPECT_FALSE(IsOfficialImage());

  ASSERT_TRUE(test_util::CreateFile(
      paths::Get("/etc/lsb-release"),
      "CHROMEOS_RELEASE_DESCRIPTION=10964.0 (Official Build) canary-channel"));
  EXPECT_TRUE(IsOfficialImage());
}

TEST_F(CrashCommonUtilTest, HasMockConsent) {
  ASSERT_TRUE(test_util::CreateFile(paths::Get("/etc/lsb-release"),
                                    "CHROMEOS_RELEASE_TRACK=testimage-channel\n"
                                    "CHROMEOS_RELEASE_DESCRIPTION=12985.0.0 "
                                    "(Official Build) dev-channel asuka test"));
  EXPECT_FALSE(HasMockConsent());
  ASSERT_TRUE(test_util::CreateFile(
      paths::GetAt(paths::kSystemRunStateDirectory, paths::kMockConsent), ""));
  EXPECT_TRUE(HasMockConsent());
}

TEST_F(CrashCommonUtilTest, IgnoresMockConsentNonTest) {
  ASSERT_TRUE(test_util::CreateFile(paths::Get("/etc/lsb-release"),
                                    "CHROMEOS_RELEASE_TRACK=dev-channel\n"
                                    "CHROMEOS_RELEASE_DESCRIPTION=12985.0.0 "
                                    "(Official Build) dev-channel asuka"));
  EXPECT_FALSE(HasMockConsent());
  ASSERT_TRUE(test_util::CreateFile(
      paths::GetAt(paths::kSystemRunStateDirectory, paths::kMockConsent), ""));
  EXPECT_FALSE(HasMockConsent());
}

TEST_F(CrashCommonUtilTest, GetOsTimestamp) {
  // If we can't read /etc/lsb-release then we should be returning the null
  // time.
  EXPECT_TRUE(util::GetOsTimestamp().is_null());

  base::FilePath lsb_file_path = paths::Get("/etc/lsb-release");
  ASSERT_TRUE(test_util::CreateFile(lsb_file_path, "foo=bar"));
  base::Time old_time = base::Time::Now() - base::Days(366);
  ASSERT_TRUE(base::TouchFile(lsb_file_path, old_time, old_time));
  // ext2/ext3 seem to have a timestamp granularity of 1s.
  EXPECT_EQ(util::GetOsTimestamp().ToTimeVal().tv_sec,
            old_time.ToTimeVal().tv_sec);
}

TEST_F(CrashCommonUtilTest, IsBuildTimestampTooOldForUploads) {
  base::SimpleTestClock clock;
  const base::Time now = test_util::GetDefaultTime();
  clock.SetNow(now);
  int64_t now_millis = (now - base::Time::UnixEpoch()).InMilliseconds();

  EXPECT_TRUE(util::IsBuildTimestampTooOldForUploads(0, &clock));

  EXPECT_FALSE(util::IsBuildTimestampTooOldForUploads(
      now_millis - base::Days(179).InMilliseconds(), &clock));
  EXPECT_TRUE(util::IsBuildTimestampTooOldForUploads(
      now_millis - base::Days(181).InMilliseconds(), &clock));

  // Crashes with invalid timestamps should upload.
  EXPECT_FALSE(util::IsBuildTimestampTooOldForUploads(
      now_millis + base::Days(1).InMilliseconds(), &clock));
  EXPECT_FALSE(util::IsBuildTimestampTooOldForUploads(-1, &clock));
  EXPECT_TRUE(util::IsBuildTimestampTooOldForUploads(
      std::numeric_limits<uint64_t>::min(), &clock));
}

TEST_F(CrashCommonUtilTest, GetHardwareClass) {
  crossystem::Crossystem stub_crossystem(
      std::make_unique<crossystem::fake::CrossystemFake>());
  auto old_instance = crossystem::ReplaceInstanceForTest(&stub_crossystem);

  // HWID file not found and failed to get the "hwid" system property.
  EXPECT_EQ("undefined", GetHardwareClass());

  // HWID file not found and but manage to get the "hwid" system property.
  stub_crossystem.VbSetSystemPropertyString("hwid", "TEST_HWID_123");
  EXPECT_EQ("TEST_HWID_123", GetHardwareClass());

  // When the HWID file exists, it should prioritize to return the file content.
  ASSERT_TRUE(test_util::CreateFile(
      paths::Get("/sys/devices/platform/chromeos_acpi/HWID"),
      kHwClassContents));
  EXPECT_EQ(kHwClassContents, GetHardwareClass());

  crossystem::ReplaceInstanceForTest(old_instance);
}

TEST_F(CrashCommonUtilTest, GetBootModeString) {
  crossystem::Crossystem stub_crossystem(
      std::make_unique<crossystem::fake::CrossystemFake>());
  auto old_instance = crossystem::ReplaceInstanceForTest(&stub_crossystem);

  EXPECT_EQ("missing-crossystem", GetBootModeString());

  stub_crossystem.VbSetSystemPropertyInt("devsw_boot", 1);
  EXPECT_EQ("dev", GetBootModeString());

  stub_crossystem.VbSetSystemPropertyInt("devsw_boot", 123);
  EXPECT_EQ("", GetBootModeString());

  ASSERT_TRUE(
      test_util::CreateFile(paths::GetAt(paths::kSystemRunStateDirectory,
                                         paths::kCrashTestInProgress),
                            ""));
  EXPECT_EQ("", GetBootModeString());

  crossystem::ReplaceInstanceForTest(old_instance);
}

TEST_F(CrashCommonUtilTest, GetCachedKeyValue) {
  ASSERT_TRUE(test_util::CreateFile(paths::Get("/etc/lsb-release"),
                                    kLsbReleaseContents));
  ASSERT_TRUE(test_util::CreateFile(paths::Get("/empty/lsb-release"), ""));

  std::string value;
  // No directories are specified.
  EXPECT_FALSE(GetCachedKeyValue(base::FilePath("lsb-release"),
                                 "CHROMEOS_RELEASE_VERSION", {}, &value));
  // A non-existent directory is specified.
  EXPECT_FALSE(GetCachedKeyValue(base::FilePath("lsb-release"),
                                 "CHROMEOS_RELEASE_VERSION",
                                 {paths::Get("/non-existent")}, &value));

  // A non-existent base name is specified.
  EXPECT_FALSE(GetCachedKeyValue(base::FilePath("non-existent"),
                                 "CHROMEOS_RELEASE_VERSION",
                                 {paths::Get("/etc")}, &value));

  // A wrong key is specified.
  EXPECT_FALSE(GetCachedKeyValue(base::FilePath("lsb-release"), "WRONG_KEY",
                                 {paths::Get("/etc")}, &value));

  // This should succeed.
  EXPECT_TRUE(GetCachedKeyValue(base::FilePath("lsb-release"),
                                "CHROMEOS_RELEASE_VERSION",
                                {paths::Get("/etc")}, &value));
  EXPECT_EQ("10964.0.2018_08_13_1405", value);

  // A non-existent directory is included, but this should still succeed.
  EXPECT_TRUE(GetCachedKeyValue(
      base::FilePath("lsb-release"), "CHROMEOS_RELEASE_VERSION",
      {paths::Get("/non-existent"), paths::Get("/etc")}, &value));
  EXPECT_EQ("10964.0.2018_08_13_1405", value);

  // A empty file is included, but this should still succeed.
  EXPECT_TRUE(GetCachedKeyValue(
      base::FilePath("lsb-release"), "CHROMEOS_RELEASE_VERSION",
      {paths::Get("/empty"), paths::Get("/etc")}, &value));
  EXPECT_EQ("10964.0.2018_08_13_1405", value);
}

TEST_F(CrashCommonUtilTest, GetCachedKeyValueDefault) {
  std::string value;
  EXPECT_FALSE(
      GetCachedKeyValueDefault(base::FilePath("test.txt"), "FOO", &value));

  // kEtcDirectory is the second candidate directory.
  ASSERT_TRUE(test_util::CreateFile(
      paths::GetAt(paths::kEtcDirectory, "test.txt"), "FOO=2\n"));
  EXPECT_TRUE(
      GetCachedKeyValueDefault(base::FilePath("test.txt"), "FOO", &value));
  EXPECT_EQ("2", value);

  // kCrashReporterStateDirectory is the first candidate directory.
  ASSERT_TRUE(test_util::CreateFile(
      paths::GetAt(paths::kCrashReporterStateDirectory, "test.txt"),
      "FOO=1\n"));
  EXPECT_TRUE(
      GetCachedKeyValueDefault(base::FilePath("test.txt"), "FOO", &value));
  EXPECT_EQ("1", value);
}

TEST_F(CrashCommonUtilTest, GetUserCrashDirectories) {
  auto mock =
      std::make_unique<org::chromium::SessionManagerInterfaceProxyMock>();

  std::vector<base::FilePath> directories;

  test_util::SetActiveSessions(mock.get(), {});
  EXPECT_TRUE(GetUserCrashDirectories(mock.get(), &directories));
  EXPECT_TRUE(directories.empty());

  test_util::SetActiveSessions(mock.get(),
                               {{"user1", "hash1"}, {"user2", "hash2"}});
  EXPECT_TRUE(GetUserCrashDirectories(mock.get(), &directories));
  EXPECT_EQ(2, directories.size());
  EXPECT_EQ(paths::Get("/home/user/hash1/crash").value(),
            directories[0].value());
  EXPECT_EQ(paths::Get("/home/user/hash2/crash").value(),
            directories[1].value());
}

TEST_F(CrashCommonUtilTest, GzipStream) {
  std::string content = CreateSemiRandomString(
      base::RandInt(kRandomDataMinLength, kRandomDataMaxLength));
  std::vector<unsigned char> compressed_content =
      util::GzipStream(brillo::MemoryStream::OpenCopyOf(
          content.c_str(), content.length(), nullptr));
  EXPECT_FALSE(compressed_content.empty());
  EXPECT_LT(compressed_content.size(), content.size())
      << "Didn't actually compress";
  base::FilePath raw_file;
  ASSERT_TRUE(base::CreateTemporaryFileInDir(test_dir_, &raw_file));
  base::FilePath compressed_file_name;
  ASSERT_TRUE(base::CreateTemporaryFileInDir(test_dir_, &compressed_file_name));
  // Remove the file we will decompress to or gzip will fail on decompression.
  ASSERT_TRUE(base::DeleteFile(compressed_file_name));
  compressed_file_name = compressed_file_name.AddExtension(".gz");
  ASSERT_EQ(base::WriteFile(raw_file, content.c_str(), content.length()),
            content.length());
  {
    base::File compressed_file(
        compressed_file_name, base::File::FLAG_WRITE | base::File::FLAG_CREATE);
    ASSERT_TRUE(compressed_file.IsValid());
    ssize_t write_result = HANDLE_EINTR(write(compressed_file.GetPlatformFile(),
                                              compressed_content.data(),
                                              compressed_content.size()));
    ASSERT_EQ(write_result, compressed_content.size());
  }
  EXPECT_TRUE(VerifyCompression(raw_file, compressed_file_name))
      << "Random input data: " << content;
}

TEST_F(CrashCommonUtilTest,
       DISABLED_ON_QEMU_FOR_MEMFD_CREATE(ReadMemfdToStringEmpty)) {
  int memfd = memfd_create("test_memfd", 0);
  std::string read_outs;
  EXPECT_FALSE(ReadMemfdToString(memfd, &read_outs));
}

TEST_F(CrashCommonUtilTest,
       DISABLED_ON_QEMU_FOR_MEMFD_CREATE(ReadMemfdToStringSuccess)) {
  int memfd = memfd_create("test_memfd", 0);
  const std::string write_ins = "Test data to write into memfd";
  ASSERT_EQ(write(memfd, write_ins.c_str(), strlen(write_ins.c_str())),
            strlen(write_ins.c_str()));
  std::string read_outs;
  EXPECT_TRUE(ReadMemfdToString(memfd, &read_outs));
  EXPECT_EQ(read_outs, write_ins);
}

TEST_F(CrashCommonUtilTest, ReadFdToStream) {
  std::stringstream stream;
  EXPECT_TRUE(ReadFdToStream(fd_, &stream));
  EXPECT_EQ(kReadFdToStreamContents, stream.str());
}

TEST_F(CrashCommonUtilTest, GetNextLine) {
  std::string test_line_1 = "test line 1";
  std::string test_line_2 = "line 2";
  base::FilePath test_file_path = test_dir_.Append("testfile");

  ASSERT_TRUE(test_util::CreateFile(
      test_file_path, base::StrCat({test_line_1, "\n", test_line_2})));

  base::File test_file(test_file_path,
                       base::File::FLAG_OPEN | base::File::FLAG_READ);
  ASSERT_TRUE(test_file.IsValid());

  std::string line;
  // Read a line and verify correct data is read.
  EXPECT_EQ(util::GetNextLine(test_file, line), test_line_1.length());
  EXPECT_EQ(line, test_line_1);
  // Read last line which may not end with a '\n', so read till EOF.
  EXPECT_EQ(util::GetNextLine(test_file, line), test_line_2.length());
  EXPECT_EQ(line, test_line_2);
  // Verify that nothing is read once EOF is reached.
  EXPECT_EQ(util::GetNextLine(test_file, line), 0);
}

TEST_F(CrashCommonUtilTest, IsFeedbackAllowedMock) {
  MetricsLibraryMock mock_metrics;
  mock_metrics.set_metrics_enabled(false);

  ASSERT_TRUE(test_util::CreateFile(paths::Get("/etc/lsb-release"),
                                    "CHROMEOS_RELEASE_TRACK=testimage-channel\n"
                                    "CHROMEOS_RELEASE_DESCRIPTION=12985.0.0 "
                                    "(Official Build) dev-channel asuka test"));

  EXPECT_FALSE(IsFeedbackAllowed(&mock_metrics));
  ASSERT_TRUE(test_util::CreateFile(
      paths::GetAt(paths::kSystemRunStateDirectory, paths::kMockConsent), ""));
  EXPECT_TRUE(HasMockConsent());

  EXPECT_TRUE(IsFeedbackAllowed(&mock_metrics));
}

TEST_F(CrashCommonUtilTest, IsFeedbackAllowedDev) {
  MetricsLibraryMock mock_metrics;
  mock_metrics.set_metrics_enabled(false);

  EXPECT_FALSE(IsFeedbackAllowed(&mock_metrics));

  ASSERT_TRUE(test_util::CreateFile(paths::Get(paths::kLeaveCoreFile), ""));

  EXPECT_TRUE(IsFeedbackAllowed(&mock_metrics));
}

// Disable this test when in a VM because there's no easy way to mock the
// VmSupport class.
// TODO(https://crbug.com/1150011): When that class can be replaced for tests,
// use a fake implementation here to set metrics consent appropriately.
#if !USE_KVM_GUEST
TEST_F(CrashCommonUtilTest, IsFeedbackAllowedRespectsMetricsLib) {
  MetricsLibraryMock mock_metrics;
  mock_metrics.set_metrics_enabled(false);

  EXPECT_FALSE(IsFeedbackAllowed(&mock_metrics));

  mock_metrics.set_metrics_enabled(true);
  EXPECT_TRUE(IsFeedbackAllowed(&mock_metrics));
}

TEST_F(CrashCommonUtilTest, IsBootFeedbackAllowedRespectsMetricsLib) {
  MetricsLibraryMock mock_metrics;
  mock_metrics.set_metrics_enabled(false);

  EXPECT_FALSE(IsBootFeedbackAllowed(&mock_metrics));

  mock_metrics.set_metrics_enabled(true);
  EXPECT_TRUE(IsBootFeedbackAllowed(&mock_metrics));
}

TEST_F(CrashCommonUtilTest, IsBootFeedbackAllowedRespectsFile) {
  MetricsLibraryMock mock_metrics;
  mock_metrics.set_metrics_enabled(true);
  ASSERT_TRUE(test_util::CreateFile(paths::Get(paths::kBootConsentFile), "0"));

  // Last user opted out, so we should disable.
  EXPECT_FALSE(IsBootFeedbackAllowed(&mock_metrics));

  // Both last user opted in as well as device owner, opt in.
  ASSERT_TRUE(test_util::CreateFile(paths::Get(paths::kBootConsentFile), "1"));
  EXPECT_TRUE(IsBootFeedbackAllowed(&mock_metrics));

  // Last user opted in, but device owner opted out, so opt out.
  mock_metrics.set_metrics_enabled(false);
  EXPECT_FALSE(IsBootFeedbackAllowed(&mock_metrics));
}
#endif  // USE_KVM_GUEST

// Verify that SkipCrashCollection behaves as expected for filter-in.
TEST_F(CrashCommonUtilTest, SkipCrashCollection_FilterIn) {
  // Force test image.
  ASSERT_TRUE(test_util::CreateFile(
      paths::GetAt(paths::kEtcDirectory, paths::kLsbRelease),
      "CHROMEOS_RELEASE_TRACK=testimage-channel"));

  int argc = 2;
  const char* argv_some_exec[] = {"/sbin/crash_reporter",
                                  "--user=--user=14074:11:0:0:some_exec"};
  const char* argv_foobar[] = {"/sbin/crash_reporter",
                               "--user=--user=14074:11:0:0:foobar"};

  // With neither file existing, both should be collected.
  ASSERT_FALSE(base::PathExists(
      paths::GetAt(paths::kSystemRunStateDirectory, paths::kFilterInFile)));
  ASSERT_FALSE(base::PathExists(
      paths::GetAt(paths::kSystemRunStateDirectory, paths::kFilterOutFile)));

  EXPECT_FALSE(SkipCrashCollection(argc, argv_some_exec));
  EXPECT_FALSE(SkipCrashCollection(argc, argv_foobar));

  // Create filter-in with "none" -- both should be skipped
  ASSERT_TRUE(test_util::CreateFile(
      paths::GetAt(paths::kSystemRunStateDirectory, paths::kFilterInFile),
      "none"));
  EXPECT_TRUE(SkipCrashCollection(argc, argv_some_exec));
  EXPECT_TRUE(SkipCrashCollection(argc, argv_foobar));

  // Create filter-in with "some_exec" -- some_exec should be allowed.
  ASSERT_TRUE(test_util::CreateFile(
      paths::GetAt(paths::kSystemRunStateDirectory, paths::kFilterInFile),
      "some_exec"));
  EXPECT_FALSE(SkipCrashCollection(argc, argv_some_exec));
  EXPECT_TRUE(SkipCrashCollection(argc, argv_foobar));
}

// Verify that SkipCrashCollection behaves as expected for filter-out.
TEST_F(CrashCommonUtilTest, SkipCrashCollection_FilterOut) {
  // Force test image.
  ASSERT_TRUE(test_util::CreateFile(
      paths::GetAt(paths::kEtcDirectory, paths::kLsbRelease),
      "CHROMEOS_RELEASE_TRACK=testimage-channel"));

  int argc = 2;
  const char* argv_some_exec[] = {"/sbin/crash_reporter",
                                  "--user=--user=14074:11:0:0:some_exec"};
  const char* argv_foobar[] = {"/sbin/crash_reporter",
                               "--user=--user=14074:11:0:0:foobar"};

  // With neither file existing, both should be collected.
  ASSERT_FALSE(base::PathExists(
      paths::GetAt(paths::kSystemRunStateDirectory, paths::kFilterInFile)));
  ASSERT_FALSE(base::PathExists(
      paths::GetAt(paths::kSystemRunStateDirectory, paths::kFilterOutFile)));

  EXPECT_FALSE(SkipCrashCollection(argc, argv_some_exec));
  EXPECT_FALSE(SkipCrashCollection(argc, argv_foobar));

  // Create filter-out with "some_exec" -- some_exec should be skipped, but
  // not foobar.
  ASSERT_TRUE(test_util::CreateFile(
      paths::GetAt(paths::kSystemRunStateDirectory, paths::kFilterOutFile),
      "some_exec"));
  EXPECT_TRUE(SkipCrashCollection(argc, argv_some_exec));
  EXPECT_FALSE(SkipCrashCollection(argc, argv_foobar));
}

// Test fixture for |GetPathToThisBinary()|.
class CrashCommonUtilGetPathToThisBinaryTest : public CrashCommonUtilTest {
 public:
  CrashCommonUtilGetPathToThisBinaryTest()
      : argv_path_("fake_crash_reporter"), override_path_("override") {}

 protected:
  void SetUp() override {
    CrashCommonUtilTest::SetUp();

    // Set working directory and create temp files to serve as fake "binaries".
    // Needed because the paths given to GetPathToThisBinary() must actually
    // exist for it to operate as intended.
    EXPECT_TRUE(GetCurrentDirectory(&original_cwd_));
    EXPECT_TRUE(SetCurrentDirectory(test_dir_));
    ASSERT_TRUE(base::WriteFile(argv_path_, ""));
    ASSERT_TRUE(base::WriteFile(override_path_, ""));
  }

  void TearDown() override {
    EXPECT_TRUE(SetCurrentDirectory(original_cwd_));
    EXPECT_EQ(unsetenv(kLdArgv0), 0);

    CrashCommonUtilTest::TearDown();
  }

  const char* test_argv_[2] = {"fake_crash_reporter", "--install"};
  base::FilePath argv_path_;
  base::FilePath override_path_;

 private:
  base::FilePath original_cwd_;
};

TEST_F(CrashCommonUtilGetPathToThisBinaryTest, UsesArgv) {
  // If the overriding environment variable is not set, argv[0] is used
  // to determine this binary's path.
  EXPECT_EQ(unsetenv(kLdArgv0), 0);
  base::FilePath path = util::GetPathToThisBinary(test_argv_);

  EXPECT_EQ(path.DirName(), test_dir_);
  EXPECT_EQ(path.BaseName(), argv_path_);
}

TEST_F(CrashCommonUtilGetPathToThisBinaryTest, UsesEnvVar) {
  EXPECT_EQ(setenv(kLdArgv0, override_path_.value().c_str(), 1 /* replace */),
            0);
  base::FilePath path = util::GetPathToThisBinary(test_argv_);

  EXPECT_EQ(path.DirName(), test_dir_);
  EXPECT_EQ(path.BaseName(), override_path_);
}

TEST_F(CrashCommonUtilGetPathToThisBinaryTest, IgnoresEmptyEnvVar) {
  EXPECT_EQ(setenv(kLdArgv0, "", 1 /* replace */), 0);
  base::FilePath path = util::GetPathToThisBinary(test_argv_);

  EXPECT_EQ(path.DirName(), test_dir_);
  EXPECT_EQ(path.BaseName(), argv_path_);
}

TEST_F(CrashCommonUtilTest, RedactDigests) {
  struct {
    bool ret;
    std::string input;
    const std::string expected;
  } test_data[] = {
      {false, "same", "same"},
      {false, "0123456789abcdefABCDEF0Z23456789abcdefAB",
       "0123456789abcdefABCDEF0Z23456789abcdefAB"},
      {true,
       "rm_rf(/home/chronos/u-0123456789abcdefABCDEF0123456789abcdefAB): Bad "
       "message",
       "rm_rf(/home/chronos/u-<Redacted Digest>): Bad message"},
      {true, "0123456789abcdefABCDEF0123456789abcdefAB", "<Redacted Digest>"},
  };

  for (auto [ret, input, expected] : test_data) {
    EXPECT_EQ(RedactDigests(&input), ret);
    EXPECT_EQ(input, expected);
  }
}

TEST_F(CrashCommonUtilTest, ExtractChromeVersionFromMetadata_Success) {
  constexpr char kChromeMetadata[] =
      R"--({
  "content": {
    "version": "104.0.5106.0"
  },
  "metadata_version": 1
})--";
  base::FilePath metadata_path = test_dir_.Append("metadata.json");
  ASSERT_TRUE(test_util::CreateFile(metadata_path, kChromeMetadata));

  EXPECT_THAT(ExtractChromeVersionFromMetadata(metadata_path),
              Optional(StrEq("104.0.5106.0")));
}

TEST_F(CrashCommonUtilTest, ExtractChromeVersionFromMetadata_NoSuchFile) {
  brillo::ClearLog();
  base::FilePath metadata_path = test_dir_.Append("metadata.json");
  EXPECT_THAT(ExtractChromeVersionFromMetadata(metadata_path),
              Eq(std::nullopt));
  EXPECT_THAT(brillo::GetLog(),
              HasSubstr("Could not read Chrome metadata file"));
}

TEST_F(CrashCommonUtilTest, ExtractChromeVersionFromMetadata_NotJSON) {
  brillo::ClearLog();
  base::FilePath metadata_path = test_dir_.Append("metadata.json");
  ASSERT_TRUE(test_util::CreateFile(metadata_path, "Not JSON data"));

  EXPECT_THAT(ExtractChromeVersionFromMetadata(metadata_path),
              Eq(std::nullopt));
  EXPECT_THAT(brillo::GetLog(),
              AllOf(HasSubstr("Error parsing Chrome metadata file"),
                    HasSubstr("as JSON")));
}

TEST_F(CrashCommonUtilTest,
       ExtractChromeVersionFromMetadata_NotOuterDictionary) {
  brillo::ClearLog();
  base::FilePath metadata_path = test_dir_.Append("metadata.json");
  ASSERT_TRUE(test_util::CreateFile(metadata_path, R"("104.0.5106.0")"));

  EXPECT_THAT(ExtractChromeVersionFromMetadata(metadata_path),
              Eq(std::nullopt));
  EXPECT_THAT(
      brillo::GetLog(),
      AllOf(
          HasSubstr("Error parsing Chrome metadata file"),
          HasSubstr(
              "expected outermost value to be a DICTIONARY but got a string")));
}

TEST_F(CrashCommonUtilTest, ExtractChromeVersionFromMetadata_NoContent) {
  brillo::ClearLog();
  base::FilePath metadata_path = test_dir_.Append("metadata.json");
  constexpr char kChromeMetadata[] =
      R"--({
  "metadata_version": 2,
  "someotherwayofgettingversion": {
    "something": "104.0.5106.0"
  }
})--";
  ASSERT_TRUE(test_util::CreateFile(metadata_path, kChromeMetadata));

  EXPECT_THAT(ExtractChromeVersionFromMetadata(metadata_path),
              Eq(std::nullopt));
  EXPECT_THAT(brillo::GetLog(),
              AllOf(HasSubstr("Error parsing Chrome metadata file"),
                    HasSubstr("could not find 'content' key")));
}

TEST_F(CrashCommonUtilTest, ExtractChromeVersionFromMetadata_ContentNotDict) {
  brillo::ClearLog();
  base::FilePath metadata_path = test_dir_.Append("metadata.json");
  constexpr char kChromeMetadata[] =
      R"--({
  "metadata_version": 2,
  "content": "104.0.5106.0"
})--";
  ASSERT_TRUE(test_util::CreateFile(metadata_path, kChromeMetadata));

  EXPECT_THAT(ExtractChromeVersionFromMetadata(metadata_path),
              Eq(std::nullopt));
  EXPECT_THAT(brillo::GetLog(),
              AllOf(HasSubstr("Error parsing Chrome metadata file"),
                    HasSubstr("content is not a DICT but instead a string")));
}

TEST_F(CrashCommonUtilTest, ExtractChromeVersionFromMetadata_NoVersion) {
  brillo::ClearLog();
  base::FilePath metadata_path = test_dir_.Append("metadata.json");
  constexpr char kChromeMetadata[] =
      R"--({
  "metadata_version": 2,
  "content": {
    "chrome_version": "104.0.5106.0"
  }
})--";
  ASSERT_TRUE(test_util::CreateFile(metadata_path, kChromeMetadata));

  EXPECT_THAT(ExtractChromeVersionFromMetadata(metadata_path),
              Eq(std::nullopt));
  EXPECT_THAT(brillo::GetLog(),
              AllOf(HasSubstr("Error parsing Chrome metadata file"),
                    HasSubstr("could not find 'version' key")));
}

TEST_F(CrashCommonUtilTest, ExtractChromeVersionFromMetadata_VersionNotString) {
  brillo::ClearLog();
  base::FilePath metadata_path = test_dir_.Append("metadata.json");
  constexpr char kChromeMetadata[] =
      R"--({
  "metadata_version": 2,
  "content": {
    "version": 104
  }
})--";
  ASSERT_TRUE(test_util::CreateFile(metadata_path, kChromeMetadata));

  EXPECT_THAT(ExtractChromeVersionFromMetadata(metadata_path),
              Eq(std::nullopt));
  EXPECT_THAT(brillo::GetLog(),
              AllOf(HasSubstr("Error parsing Chrome metadata file"),
                    HasSubstr("version is not a string but instead a int")));
}

}  // namespace util
