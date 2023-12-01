// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/chrome_collector.h"

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <functional>
#include <utility>

#include <base/auto_reset.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/memory/weak_ptr.h>
#include <base/test/task_environment.h>
#include <base/strings/strcat.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/data_encoding.h>
#include <brillo/syslog_logging.h>
#include <debugd/dbus-proxy-mocks.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "crash-reporter/test_util.h"

using base::FilePath;
using ::testing::_;
using ::testing::AnyNumber;
using ::testing::HasSubstr;
using ::testing::Invoke;
using ::testing::Not;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::WithArgs;

namespace {
const char kTestCrashDirectory[] = "test-crash-directory";

// We must have an upload_file_minidump to get a payload name.
const char kCrashFormatGood[] =
    "value1:10:abcdefghijvalue2:5:12345"
    "upload_file_minidump\"; filename=\"dump\":3:abc";
const char kCrashFormatGoodLacros[] =
    "upload_file_minidump\"; filename=\"dump\":3:abc"
    "prod:13:Chrome_Lacros";
const char kCrashFormatNoDump[] = "value1:10:abcdefghijvalue2:5:12345";
const char kCrashFormatEmbeddedNewline[] =
    "value1:10:abcd\r\nghijvalue2:5:12\n34"
    "upload_file_minidump\"; filename=\"dump\":3:a\nc";
// Inputs that should fail ParseCrashLog regardless of crash_type.
const char* const kCrashFormatBadValuesCommon[] = {
    // Last length too long
    "value1:10:abcdefghijvalue2:6:12345",
    // Length is followed by something other than a colon.
    "value1:10:abcdefghijvalue2:5f:12345",
    // Length not terminated
    "value1:10:abcdefghijvalue2:5",
    // No last length.
    "value1:10:abcdefghijvalue2:",
    // Length value missing
    "value1:10:abcdefghijvalue2::12345",
    // Length not a number
    "value1:10:abcdefghijvalue2:five:12345",
    // Last length too short
    "value1:10:abcdefghijvalue2:4:12345",
    // Missing length
    "value1::abcdefghijvalue2:5:12345",
    // Missing initial key
    ":5:abcdefghijvalue2:5:12345",
    // Missing later key
    "value1:10:abcdefghij:5:12345",
    // Multiple minidumps
    "upload_file_minidump\"; filename=\"dump\":7:easy as"
    "upload_file_minidump\"; filename=\"dump\":3:123",
    // Multiple js stacks
    "upload_file_js_stack\"; filename=\"stack\":3:abc"
    "upload_file_js_stack\"; filename=\"stack\":3:123"};
// Inputs that should fail ParseCrashLog if crash_type is kExecutableCrash.
const char* const kCrashFormatBadValuesExecutable[] = {
    // A JavaScript stack when we expect a minidump
    "upload_file_js_stack\"; filename=\"stack\":20:0123456789abcdefghij"};
// Inputs that should fail ParseCrashLog if crash_type is kJavaScriptError.
const char* const kCrashFormatBadValuesJavaScript[] = {
    // A minidump when we expect a JavaScript stack
    "upload_file_minidump\"; filename=\"dump\":3:abc"};

const char kCrashFormatWithFile[] =
    "value1:10:abcdefghijvalue2:5:12345"
    "some_file\"; filename=\"foo.txt\":15:12345\n789\n12345"
    "upload_file_minidump\"; filename=\"dump\":3:abc"
    "value3:2:ok";

// Matches the :20: in kCrashFormatWithDumpFile
const int kOutputDumpFileSize = 20;
// Matches the :15: in kCrashFormatWithDumpFile
const int kOutputOtherFileSize = 15;

const char kCrashFormatWithDumpFile[] =
    "value1:10:abcdefghij"
    "value2:5:12345"
    "some_file\"; filename=\"foo.txt\":15:12345\n789\n12345"
    "upload_file_minidump\"; filename=\"dump\":20:0123456789abcdefghij"
    "value3:2:ok";
const char kCrashFormatWithDumpFileWithEmbeddedNulBytes[] =
    "value1:10:abcdefghij"
    "value2:5:12345"
    "some_file\"; filename=\"foo.txt\":15:12\00045\n789\n12\00045"
    "upload_file_minidump\"; filename=\"dump\":20:"
    "\00012345678\000\a\bcd\x0e\x0fghij"
    "value3:2:ok";
const char kCrashFormatWithWeirdFilename[] =
    "value1:10:abcdefghij"
    "value2:5:12345"
    "dotdotfile\"; filename=\"../a.txt\":15:12345\n789\n12345"
    "upload_file_minidump\"; filename=\"dump\":20:0123456789abcdefghij"
    "value3:2:ok";
const char kCrashFormatWithJSStack[] =
    "value1:10:abcdefghij"
    "value2:5:12345"
    "some_file\"; filename=\"foo.txt\":15:12345\n789\n12345"
    "upload_file_js_stack\"; filename=\"stack\":20:0123456789abcdefghij"
    "value3:2:ok";
const char kCrashFormatWithLacrosJSStack[] =
    "value1:10:abcdefghij"
    "value2:5:12345"
    "some_file\"; filename=\"foo.txt\":15:12345\n789\n12345"
    "upload_file_js_stack\"; filename=\"stack\":20:0123456789abcdefghij"
    "prod:13:Chrome_Lacros"
    "value3:2:ok";

const char kSampleDriErrorStateEncoded[] =
    "<base64>: SXQgYXBwZWFycyB0byBiZSBzb21lIHNvcnQgb2YgZXJyb3IgZGF0YS4=";
const char kSampleDriErrorStateDecoded[] =
    "It appears to be some sort of error data.";

const char kSampleDriErrorStateEncodedLong[] =
    "<base64>: "
    "MDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwMDEyMzQ1Njc4OTAwMTIzNDU2Nzg5M"
    "DAxMjM0NTY3ODkwMDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwMDEyMzQ1Njc4OT"
    "AKMDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwMDEyMzQ1Njc4OTAwMTIzNDU2Nzg"
    "5MDAxMjM0NTY3ODkwMDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwMDEyMzQ1Njc4"
    "OTAKMDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwMDEyMzQ1Njc4OTAwMTIzNDU2N"
    "zg5MDAxMjM0NTY3ODkwMDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwMDEyMzQ1Nj"
    "c4OTAKMDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwMDEyMzQ1Njc4OTAwMTIzNDU"
    "2Nzg5MDAxMjM0NTY3ODkwMDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwMDEyMzQ1"
    "Njc4OTAKMDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwMDEyMzQ1Njc4OTAwMTIzN"
    "DU2Nzg5MDAxMjM0NTY3ODkwMDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwMDEyMz"
    "Q1Njc4OTAKMDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwMDEyMzQ1Njc4OTAwMTI"
    "zNDU2Nzg5MDAxMjM0NTY3ODkwMDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwMDEy"
    "MzQ1Njc4OTAKMDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwMDEyMzQ1Njc4OTAwM"
    "TIzNDU2Nzg5MDAxMjM0NTY3ODkwMDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwMD"
    "EyMzQ1Njc4OTAKMDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwMDEyMzQ1Njc4OTA"
    "wMTIzNDU2Nzg5MDAxMjM0NTY3ODkwMDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MDAxMjM0NTY3ODkw"
    "MDEyMzQ1Njc4OTAKMDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwMDEyMzQ1Njc4O"
    "TAwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwMDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MDAxMjM0NTY3OD"
    "kwMDEyMzQ1Njc4OTAKMDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwMDEyMzQ1Njc"
    "4OTAwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwMDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MDAxMjM0NTY3"
    "ODkwMDEyMzQ1Njc4OTAK";

constexpr char kSampleDmesg[] =
    "[   15.945022] binder: 3495:3495 ioctl 4018620d ffdc30c0 returned -22\n"
    "[   17.943062] iio iio:device1: Unable to flush sensor\n";

}  // namespace

class ChromeCollectorMock : public ChromeCollector {
 public:
  ChromeCollectorMock() : ChromeCollector(kNormalCrashSendMode) {}
  MOCK_METHOD(void, SetUpDBus, (), (override));
};

class DebugdProxyMockWithWeakPtr : public org::chromium::debugdProxyMock {
 public:
  ~DebugdProxyMockWithWeakPtr() override = default;

  base::WeakPtrFactory<DebugdProxyMockWithWeakPtr> weak_factory_{this};
};

class ChromeCollectorTest : public ::testing::Test {
 protected:
  void ExpectFileEquals(const char* golden, const FilePath& file_path) {
    std::string contents;
    EXPECT_TRUE(base::ReadFileToString(file_path, &contents));
    EXPECT_EQ(golden, contents);
  }

  // Set things up so that the call to get the DriErrorState will return the
  // indicating string. Set to "<empty>" to avoid creating a DriErrorState.
  void SetUpDriErrorStateToReturn(std::string result) {
    std::function<void(base::OnceCallback<void(const std::string&)> &&)>
        handler = [this, result](
                      base::OnceCallback<void(const std::string&)> callback) {
          task_environment_.GetMainThreadTaskRunner()->PostNonNestableTask(
              FROM_HERE, base::BindOnce(std::move(callback), result));
        };
    CHECK(debugd_proxy_mock_);
    ON_CALL(*debugd_proxy_mock_, GetLogAsync("i915_error_state", _, _, _))
        .WillByDefault(WithArgs<1>(handler));
  }

  // Set things up so that the call to get the DriErrorState will give the
  // indicated Error.
  void SetUpDriErrorStateToErrorOut(brillo::Error* error) {
    std::function<void(base::OnceCallback<void(brillo::Error*)> &&)> handler =
        [this, error](base::OnceCallback<void(brillo::Error*)> callback) {
          task_environment_.GetMainThreadTaskRunner()->PostNonNestableTask(
              FROM_HERE, base::BindOnce(std::move(callback), error));
        };
    CHECK(debugd_proxy_mock_);
    ON_CALL(*debugd_proxy_mock_, GetLogAsync("i915_error_state", _, _, _))
        .WillByDefault(WithArgs<2>(handler));
  }

  // Set things up so that the call to CallDmesgAsync will return the
  // indicating string.
  void SetUpCallDmesgToReturn(std::string result) {
    std::function<void(base::OnceCallback<void(const std::string&)> &&)>
        handler = [this, result](
                      base::OnceCallback<void(const std::string&)> callback) {
          task_environment_.GetMainThreadTaskRunner()->PostNonNestableTask(
              FROM_HERE, base::BindOnce(std::move(callback), result));
        };
    CHECK(debugd_proxy_mock_);
    ON_CALL(*debugd_proxy_mock_, CallDmesgAsync(_, _, _, _))
        .WillByDefault(WithArgs<1>(handler));
  }

  // Set things up so that the call to CallDmesgAsync will error out with the
  // indicated Error.
  void SetUpCallDmesgToErrorOut(brillo::Error* error) {
    std::function<void(base::OnceCallback<void(brillo::Error*)> &&)> handler =
        [this, error](base::OnceCallback<void(brillo::Error*)> callback) {
          task_environment_.GetMainThreadTaskRunner()->PostNonNestableTask(
              FROM_HERE, base::BindOnce(std::move(callback), error));
        };
    CHECK(debugd_proxy_mock_);
    ON_CALL(*debugd_proxy_mock_, CallDmesgAsync(_, _, _, _))
        .WillByDefault(WithArgs<2>(handler));
  }

  // Sets up the logs config so that HandleCrash will not produce a
  // chrome.txt.gz file.
  void SetUpLogsNone() {
    base::FilePath config_file =
        scoped_temp_dir_.GetPath().Append("crash_config");
    const char kConfigContents[] = "";
    ASSERT_TRUE(test_util::CreateFile(config_file, kConfigContents));
    collector_.set_log_config_path(config_file.value());
  }

  // Sets up the logs config so that HandleCrash will produce a relatively small
  // chrome.txt.gz.
  void SetUpLogsShort() {
    base::FilePath config_file =
        scoped_temp_dir_.GetPath().Append("crash_config");
    const char kConfigContents[] =
        "chrome=echo hello there\n"
        "lacros_chrome=echo welcome to lacros\n"
        "jserror=echo JavaScript has nothing to do with Java\n";
    ASSERT_TRUE(test_util::CreateFile(config_file, kConfigContents));
    collector_.set_log_config_path(config_file.value());
  }

  // Sets up the logs config so that HandleCrash will produce a relatively large
  // chrome.txt.gz -- even compressed, should be over 10K.
  void SetUpLogsLong() {
    base::FilePath config_file =
        scoped_temp_dir_.GetPath().Append("crash_config");
    const char kConfigContents[] = "chrome=seq 1 10000";
    ASSERT_TRUE(test_util::CreateFile(config_file, kConfigContents));
    collector_.set_log_config_path(config_file.value());
  }

  void Decompress(const base::FilePath& path) {
    int decompress_result = system(("gunzip " + path.value()).c_str());
    EXPECT_TRUE(WIFEXITED(decompress_result));
    EXPECT_EQ(WEXITSTATUS(decompress_result), 0);
  }

  // Returns a very long string, long enough that even compressed it should be
  // over 10KB.
  std::string GetDmesgLong() {
    std::string result;
    for (int i = 0; i < 20000; i++) {
      base::StrAppend(&result, {kSampleDmesg, base::NumberToString(i), "\n"});
    }
    return result;
  }

  // Expect that the dmesg output file exists and it has compressed contents
  // that, when uncompressed, equal kSampleDmesg. Returns the original
  // (compressed) filename in |output_dmesg_file| and the original compressed
  // size in |dmesg_log_compressed_size|.
  void ExpectSampleDmesg(base::FilePath& output_dmesg_file,
                         int64_t& dmesg_log_compressed_size) {
    EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
        test_crash_directory_, "chrome_test.*.123.dmesg.txt.gz",
        &output_dmesg_file));
    EXPECT_TRUE(
        base::GetFileSize(output_dmesg_file, &dmesg_log_compressed_size));
    Decompress(output_dmesg_file);
    base::FilePath output_dmesg_file_uncompressed =
        output_dmesg_file.RemoveFinalExtension();
    std::string dmesg_file_contents;
    EXPECT_TRUE(base::ReadFileToString(output_dmesg_file_uncompressed,
                                       &dmesg_file_contents));
    EXPECT_EQ(dmesg_file_contents, kSampleDmesg);
  }

  // Expect that the dri error state file exists and has contents equal to
  // kSampleDriErrorStateDecoded. Returns the filename in
  // |output_dri_error_file|.
  void ExpectSampleDriErrorState(base::FilePath& output_dri_error_file) {
    EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
        test_crash_directory_, "chrome_test.*.123.i915_error_state.log.xz",
        &output_dri_error_file));
    std::string dri_error_file_contents;
    EXPECT_TRUE(base::ReadFileToString(output_dri_error_file,
                                       &dri_error_file_contents));
    EXPECT_EQ(dri_error_file_contents, kSampleDriErrorStateDecoded);
  }

  // Expect that the log output file exists and it has compressed contents
  // that, when uncompressed, equal the message put there by SetUpLogsShort().
  // Returns the original (compressed) filename in |output_log| and the original
  // compressed size in |output_log_compressed_size|.
  void ExpectShortOutputLog(base::FilePath& output_log,
                            int64_t& output_log_compressed_size) {
    EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
        test_crash_directory_, "chrome_test.*.123.chrome.txt.gz", &output_log));
    EXPECT_TRUE(base::GetFileSize(output_log, &output_log_compressed_size));
    Decompress(output_log);
    base::FilePath output_log_uncompressed = output_log.RemoveFinalExtension();
    std::string output_log_contents;
    EXPECT_TRUE(
        base::ReadFileToString(output_log_uncompressed, &output_log_contents));
    EXPECT_EQ(output_log_contents, "hello there\n");
  }

  // RunLoop requires a task environment.
  base::test::SingleThreadTaskEnvironment task_environment_;

  ChromeCollectorMock collector_;
  base::FilePath test_crash_directory_;
  base::ScopedTempDir scoped_temp_dir_;

 private:
  // A properly-lifetimed org::chromium::debugdProxyMock pointer. We keep this
  // one even after passing ownership to the ChromeCollector when
  // SetUpDBus is called.
  base::WeakPtr<DebugdProxyMockWithWeakPtr> debugd_proxy_mock_;
  // The proxy mock we pass to the collector_ when SetUpDBus is called. Private
  // because this is set to nullptr when SetUpDBus is run, so calling
  // EXPECT_CALL(*debugd_proxy_mock_, ...) is dangerous. Better to use
  // debugd_proxy_mock_.
  std::unique_ptr<DebugdProxyMockWithWeakPtr> debugd_proxy_mock_owner_;

  void SetUp() override {
    std::string dummy_to_check_validity;
    ASSERT_TRUE(brillo::data_encoding::Base64Decode(
        kSampleDriErrorStateEncodedLong + strlen("<base64>: "),
        &dummy_to_check_validity));

    collector_.Initialize(false);
    brillo::ClearLog();

    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());

    test_crash_directory_ =
        scoped_temp_dir_.GetPath().Append(kTestCrashDirectory);
    ASSERT_TRUE(CreateDirectory(test_crash_directory_));
    collector_.set_crash_directory_for_test(test_crash_directory_);
    debugd_proxy_mock_owner_ = std::make_unique<DebugdProxyMockWithWeakPtr>();
    debugd_proxy_mock_ = debugd_proxy_mock_owner_->weak_factory_.GetWeakPtr();
    ON_CALL(collector_, SetUpDBus()).WillByDefault(Invoke([this]() {
      if (debugd_proxy_mock_) {
        collector_.debugd_proxy_ = std::move(debugd_proxy_mock_owner_);
      }
    }));
  }
};

TEST_F(ChromeCollectorTest, GoodValues) {
  base::ScopedTempDir scoped_temp_dir;
  ASSERT_TRUE(scoped_temp_dir.CreateUniqueTempDir());
  const FilePath& dir = scoped_temp_dir.GetPath();
  FilePath payload;
  bool is_lacros_crash;
  EXPECT_TRUE(collector_.ParseCrashLog(kCrashFormatGood, dir, "base",
                                       ChromeCollector::kExecutableCrash,
                                       &payload, &is_lacros_crash));
  EXPECT_FALSE(is_lacros_crash);
  EXPECT_EQ(payload, dir.Append("base.dmp"));
  ExpectFileEquals("abc", payload);

  // Check to see if the values made it in properly.
  std::string meta = collector_.extra_metadata_;
  EXPECT_TRUE(meta.find("value1=abcdefghij") != std::string::npos);
  EXPECT_TRUE(meta.find("value2=12345") != std::string::npos);
}

TEST_F(ChromeCollectorTest, GoodLacros) {
  base::ScopedTempDir scoped_temp_dir;
  ASSERT_TRUE(scoped_temp_dir.CreateUniqueTempDir());
  const FilePath& dir = scoped_temp_dir.GetPath();
  FilePath payload;
  bool is_lacros_crash;
  EXPECT_TRUE(collector_.ParseCrashLog(kCrashFormatGoodLacros, dir, "base",
                                       ChromeCollector::kExecutableCrash,
                                       &payload, &is_lacros_crash));
  EXPECT_TRUE(is_lacros_crash);
  EXPECT_EQ(payload, dir.Append("base.dmp"));
  ExpectFileEquals("abc", payload);

  // Check to see if the values made it in properly.
  std::string meta = collector_.extra_metadata_;
  EXPECT_TRUE(meta.find("upload_var_prod=Chrome_Lacros") != std::string::npos);
}

TEST_F(ChromeCollectorTest, ParseCrashLogNoDump) {
  base::ScopedTempDir scoped_temp_dir;
  ASSERT_TRUE(scoped_temp_dir.CreateUniqueTempDir());
  const FilePath& dir = scoped_temp_dir.GetPath();
  FilePath payload;
  bool is_lacros_crash;
  EXPECT_TRUE(collector_.ParseCrashLog(kCrashFormatNoDump, dir, "base",
                                       ChromeCollector::kExecutableCrash,
                                       &payload, &is_lacros_crash));
  EXPECT_EQ(payload.value(), "");
  EXPECT_FALSE(base::PathExists(dir.Append("base.dmp")));

  // Check to see if the values made it in properly.
  std::string meta = collector_.extra_metadata_;
  EXPECT_TRUE(meta.find("value1=abcdefghij") != std::string::npos);
  EXPECT_TRUE(meta.find("value2=12345") != std::string::npos);
}

TEST_F(ChromeCollectorTest, ParseCrashLogJSStack) {
  base::ScopedTempDir scoped_temp_dir;
  ASSERT_TRUE(scoped_temp_dir.CreateUniqueTempDir());
  const FilePath& dir = scoped_temp_dir.GetPath();
  FilePath payload;
  bool is_lacros_crash;
  EXPECT_TRUE(collector_.ParseCrashLog(kCrashFormatWithJSStack, dir, "base",
                                       ChromeCollector::kJavaScriptError,
                                       &payload, &is_lacros_crash));
  EXPECT_EQ(payload, dir.Append("base.js_stack"));
  ExpectFileEquals("0123456789abcdefghij", payload);

  // Check to see if the values made it in properly.
  std::string meta = collector_.extra_metadata_;
  EXPECT_TRUE(meta.find("value1=abcdefghij") != std::string::npos);
  EXPECT_TRUE(meta.find("value2=12345") != std::string::npos);
}

TEST_F(ChromeCollectorTest, Newlines) {
  base::ScopedTempDir scoped_temp_dir;
  ASSERT_TRUE(scoped_temp_dir.CreateUniqueTempDir());
  const FilePath& dir = scoped_temp_dir.GetPath();
  FilePath payload;
  bool is_lacros_crash;
  EXPECT_TRUE(collector_.ParseCrashLog(kCrashFormatEmbeddedNewline, dir, "base",
                                       ChromeCollector::kExecutableCrash,
                                       &payload, &is_lacros_crash));
  EXPECT_EQ(payload, dir.Append("base.dmp"));
  ExpectFileEquals("a\nc", payload);

  // Check to see if the values were escaped.
  std::string meta = collector_.extra_metadata_;
  EXPECT_TRUE(meta.find("value1=abcd\\r\\nghij") != std::string::npos);
  EXPECT_TRUE(meta.find("value2=12\\n34") != std::string::npos);
}

TEST_F(ChromeCollectorTest, BadValues) {
  base::ScopedTempDir scoped_temp_dir;
  ASSERT_TRUE(scoped_temp_dir.CreateUniqueTempDir());
  const FilePath& dir = scoped_temp_dir.GetPath();
  int test_number = 0;
  for (const char* data : kCrashFormatBadValuesCommon) {
    for (auto crash_type : {ChromeCollector::kExecutableCrash,
                            ChromeCollector::kJavaScriptError}) {
      FilePath payload;
      bool is_lacros_crash;
      EXPECT_FALSE(collector_.ParseCrashLog(
          data, dir,
          base::StrCat({"base_", base::NumberToString(test_number), "_test"}),
          crash_type, &payload, &is_lacros_crash))
          << data << " did not fail (for crash_type "
          << static_cast<int>(crash_type) << ")";
      test_number++;
    }
  }
  for (const char* data : kCrashFormatBadValuesExecutable) {
    FilePath payload;
    bool is_lacros_crash;
    EXPECT_FALSE(collector_.ParseCrashLog(
        data, dir,
        base::StrCat({"base_", base::NumberToString(test_number), "_test"}),
        ChromeCollector::kExecutableCrash, &payload, &is_lacros_crash))
        << data << " did not fail";
    test_number++;
  }
  for (const char* data : kCrashFormatBadValuesJavaScript) {
    FilePath payload;
    bool is_lacros_crash;
    EXPECT_FALSE(collector_.ParseCrashLog(
        data, dir,
        base::StrCat({"base_", base::NumberToString(test_number), "_test"}),
        ChromeCollector::kJavaScriptError, &payload, &is_lacros_crash))
        << data << " did not fail";
    test_number++;
  }
}

TEST_F(ChromeCollectorTest, File) {
  base::ScopedTempDir scoped_temp_dir;
  ASSERT_TRUE(scoped_temp_dir.CreateUniqueTempDir());
  const FilePath& dir = scoped_temp_dir.GetPath();
  FilePath payload;
  bool is_lacros_crash;
  EXPECT_TRUE(collector_.ParseCrashLog(kCrashFormatWithFile, dir, "base",
                                       ChromeCollector::kExecutableCrash,
                                       &payload, &is_lacros_crash));
  EXPECT_EQ(payload, dir.Append("base.dmp"));
  ExpectFileEquals("abc", payload);

  // Check to see if the values are still correct and that the file was
  // written with the right data.
  std::string meta = collector_.extra_metadata_;
  EXPECT_TRUE(meta.find("value1=abcdefghij") != std::string::npos);
  EXPECT_TRUE(meta.find("value2=12345") != std::string::npos);
  EXPECT_TRUE(meta.find("value3=ok") != std::string::npos);
  ExpectFileEquals("12345\n789\n12345", dir.Append("base-foo_txt.other"));
}

TEST_F(ChromeCollectorTest, HandleCrash) {
  const FilePath& dir = scoped_temp_dir_.GetPath();
  FilePath input_dump_file = dir.Append("test.dmp");
  ASSERT_TRUE(test_util::CreateFile(input_dump_file, kCrashFormatWithDumpFile));
  SetUpDriErrorStateToReturn("<empty>");
  SetUpCallDmesgToReturn("");
  SetUpLogsNone();

  FilePath log_file;
  {
    base::ScopedFILE output(
        base::CreateAndOpenTemporaryStreamInDir(dir, &log_file));
    ASSERT_TRUE(output.get());
    base::AutoReset<FILE*> auto_reset_file_ptr(&collector_.output_file_ptr_,
                                               output.get());
    EXPECT_TRUE(
        collector_.HandleCrash(input_dump_file, 123, 456, "chrome_test", -1));
  }
  ExpectFileEquals(ChromeCollector::kSuccessMagic, log_file);

  base::FilePath output_dump_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.dmp", &output_dump_file));
  std::string output_dump_file_contents;
  EXPECT_TRUE(
      base::ReadFileToString(output_dump_file, &output_dump_file_contents));
  EXPECT_EQ(output_dump_file_contents, "0123456789abcdefghij");

  base::FilePath other_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123-foo_txt.other", &other_file));
  std::string other_file_contents;
  EXPECT_TRUE(base::ReadFileToString(other_file, &other_file_contents));
  EXPECT_EQ(other_file_contents, "12345\n789\n12345");

  base::FilePath meta_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.meta", &meta_file));
  std::string meta_file_contents;
  EXPECT_TRUE(base::ReadFileToString(meta_file, &meta_file_contents));
  EXPECT_EQ(collector_.get_bytes_written(),
            meta_file_contents.size() + output_dump_file_contents.size() +
                other_file_contents.size());
  EXPECT_THAT(meta_file_contents,
              HasSubstr("payload=" + output_dump_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_file_some_file=" +
                                            other_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value1=abcdefghij"));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value2=12345"));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value3=ok"));
}

TEST_F(ChromeCollectorTest, HandleCrashWithEmbeddedNuls) {
  const FilePath& dir = scoped_temp_dir_.GetPath();
  FilePath input_dump_file = dir.Append("test.dmp");
  std::string input(kCrashFormatWithDumpFileWithEmbeddedNulBytes,
                    sizeof(kCrashFormatWithDumpFileWithEmbeddedNulBytes) - 1);
  ASSERT_TRUE(test_util::CreateFile(input_dump_file, input));
  SetUpDriErrorStateToReturn("<empty>");
  SetUpCallDmesgToReturn("");
  SetUpLogsNone();

  FilePath log_file;
  {
    base::ScopedFILE output(
        base::CreateAndOpenTemporaryStreamInDir(dir, &log_file));
    ASSERT_TRUE(output.get());
    base::AutoReset<FILE*> auto_reset_file_ptr(&collector_.output_file_ptr_,
                                               output.get());
    EXPECT_TRUE(
        collector_.HandleCrash(input_dump_file, 123, 456, "chrome_test", -1));
  }
  ExpectFileEquals(ChromeCollector::kSuccessMagic, log_file);

  base::FilePath output_dump_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.dmp", &output_dump_file));
  std::string output_dump_file_contents;
  EXPECT_TRUE(
      base::ReadFileToString(output_dump_file, &output_dump_file_contents));
  std::string expected_dump_contents("\00012345678\000\a\bcd\x0e\x0fghij", 20);
  EXPECT_EQ(output_dump_file_contents, expected_dump_contents);

  base::FilePath other_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123-foo_txt.other", &other_file));
  std::string other_file_contents;
  EXPECT_TRUE(base::ReadFileToString(other_file, &other_file_contents));
  std::string expected_other_contents("12\00045\n789\n12\00045", 15);
  EXPECT_EQ(other_file_contents, expected_other_contents);

  base::FilePath meta_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.meta", &meta_file));
  std::string meta_file_contents;
  EXPECT_TRUE(base::ReadFileToString(meta_file, &meta_file_contents));
  EXPECT_EQ(collector_.get_bytes_written(),
            meta_file_contents.size() + output_dump_file_contents.size() +
                other_file_contents.size());
  EXPECT_THAT(meta_file_contents,
              HasSubstr("payload=" + output_dump_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_file_some_file=" +
                                            other_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value1=abcdefghij"));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value2=12345"));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value3=ok"));
}

TEST_F(ChromeCollectorTest, HandleCrashWithWeirdFilename) {
  const FilePath& dir = scoped_temp_dir_.GetPath();
  FilePath input_dump_file = dir.Append("test.dmp");
  std::string input(kCrashFormatWithWeirdFilename,
                    sizeof(kCrashFormatWithWeirdFilename) - 1);
  ASSERT_TRUE(test_util::CreateFile(input_dump_file, input));
  SetUpDriErrorStateToReturn("<empty>");
  SetUpCallDmesgToReturn("");
  SetUpLogsNone();

  FilePath log_file;
  {
    base::ScopedFILE output(
        base::CreateAndOpenTemporaryStreamInDir(dir, &log_file));
    ASSERT_TRUE(output.get());
    base::AutoReset<FILE*> auto_reset_file_ptr(&collector_.output_file_ptr_,
                                               output.get());
    EXPECT_TRUE(
        collector_.HandleCrash(input_dump_file, 123, 456, "chrome_test", -1));
  }
  ExpectFileEquals(ChromeCollector::kSuccessMagic, log_file);

  base::FilePath output_dump_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.dmp", &output_dump_file));
  std::string output_dump_file_contents;
  EXPECT_TRUE(
      base::ReadFileToString(output_dump_file, &output_dump_file_contents));
  EXPECT_EQ(output_dump_file_contents, "0123456789abcdefghij");

  base::FilePath other_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123-___a_txt.other", &other_file));
  std::string other_file_contents;
  EXPECT_TRUE(base::ReadFileToString(other_file, &other_file_contents));
  EXPECT_EQ(other_file_contents, "12345\n789\n12345");

  base::FilePath meta_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.meta", &meta_file));
  std::string meta_file_contents;
  EXPECT_TRUE(base::ReadFileToString(meta_file, &meta_file_contents));
  EXPECT_EQ(collector_.get_bytes_written(),
            meta_file_contents.size() + output_dump_file_contents.size() +
                other_file_contents.size());
  EXPECT_THAT(meta_file_contents,
              HasSubstr("payload=" + output_dump_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_file_dotdotfile=" +
                                            other_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value1=abcdefghij"));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value2=12345"));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value3=ok"));
}

TEST_F(ChromeCollectorTest, HandleCrashWithLogsAndDriErrorStateAndDmesg) {
  const FilePath& dir = scoped_temp_dir_.GetPath();
  FilePath input_dump_file = dir.Append("test.dmp");
  ASSERT_TRUE(test_util::CreateFile(input_dump_file, kCrashFormatWithDumpFile));
  SetUpDriErrorStateToReturn(kSampleDriErrorStateEncoded);
  SetUpCallDmesgToReturn(kSampleDmesg);
  SetUpLogsShort();

  EXPECT_TRUE(
      collector_.HandleCrash(input_dump_file, 123, 456, "chrome_test", -1));

  base::FilePath output_dri_error_file;
  ExpectSampleDriErrorState(output_dri_error_file);

  base::FilePath output_dmesg_file;
  int64_t dmesg_log_compressed_size = 0;
  ExpectSampleDmesg(output_dmesg_file, dmesg_log_compressed_size);

  base::FilePath output_log;
  int64_t output_log_compressed_size = 0;
  ExpectShortOutputLog(output_log, output_log_compressed_size);

  base::FilePath output_dump_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.dmp", &output_dump_file));
  std::string output_dump_file_contents;
  EXPECT_TRUE(
      base::ReadFileToString(output_dump_file, &output_dump_file_contents));
  EXPECT_EQ(output_dump_file_contents, "0123456789abcdefghij");

  base::FilePath other_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123-foo_txt.other", &other_file));
  std::string other_file_contents;
  EXPECT_TRUE(base::ReadFileToString(other_file, &other_file_contents));
  EXPECT_EQ(other_file_contents, "12345\n789\n12345");

  base::FilePath meta_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.meta", &meta_file));
  std::string meta_file_contents;
  EXPECT_TRUE(base::ReadFileToString(meta_file, &meta_file_contents));
  EXPECT_EQ(collector_.get_bytes_written(),
            meta_file_contents.size() + output_log_compressed_size +
                dmesg_log_compressed_size +
                strlen(kSampleDriErrorStateDecoded) +
                other_file_contents.size() + output_dump_file_contents.size());
  EXPECT_THAT(meta_file_contents,
              HasSubstr("payload=" + output_dump_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_file_some_file=" +
                                            other_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_file_chrome.txt=" +
                                            output_log.BaseName().value()));
  EXPECT_THAT(meta_file_contents,
              HasSubstr("upload_file_i915_error_state.log.xz=" +
                        output_dri_error_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents,
              HasSubstr("upload_file_dmesg.txt=" +
                        output_dmesg_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value1=abcdefghij"));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value2=12345"));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value3=ok"));
}

TEST_F(ChromeCollectorTest, HandleCrashSkipsSupplementalFilesIfDumpFileLarge) {
  const FilePath& dir = scoped_temp_dir_.GetPath();
  FilePath input_dump_file = dir.Append("test.dmp");
  ASSERT_TRUE(test_util::CreateFile(input_dump_file, kCrashFormatWithDumpFile));
  SetUpDriErrorStateToReturn(kSampleDriErrorStateEncoded);
  SetUpCallDmesgToReturn(kSampleDmesg);
  SetUpLogsShort();
  // Make dmp file "too large"
  collector_.set_max_upload_bytes_for_test(1);
  EXPECT_TRUE(
      collector_.HandleCrash(input_dump_file, 123, 456, "chrome_test", -1));

  // Supplemental files not written.
  EXPECT_FALSE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.i915_error_state.log.xz",
      nullptr));
  EXPECT_FALSE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.chrome.txt.gz", nullptr));
  EXPECT_FALSE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.dmesg.txt.gz", nullptr));

  // .dmp file and other files in the input dump still written.
  base::FilePath output_dump_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.dmp", &output_dump_file));
  base::FilePath other_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123-foo_txt.other", &other_file));

  base::FilePath meta_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.meta", &meta_file));
  std::string meta_file_contents;
  EXPECT_TRUE(base::ReadFileToString(meta_file, &meta_file_contents));
  EXPECT_EQ(
      collector_.get_bytes_written(),
      meta_file_contents.size() + kOutputDumpFileSize + kOutputOtherFileSize);
  EXPECT_THAT(meta_file_contents,
              HasSubstr("payload=" + output_dump_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_file_some_file=" +
                                            other_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, Not(HasSubstr("upload_file_chrome.txt")));
  EXPECT_THAT(meta_file_contents,
              Not(HasSubstr("upload_file_i915_error_state.log.xz")));
  EXPECT_THAT(meta_file_contents, Not(HasSubstr("upload_file_dmesg.txt")));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value1=abcdefghij"));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value2=12345"));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value3=ok"));
}

TEST_F(ChromeCollectorTest, HandleCrashSkipsLargeLogFiles) {
  const FilePath& dir = scoped_temp_dir_.GetPath();
  FilePath input_dump_file = dir.Append("test.dmp");
  ASSERT_TRUE(test_util::CreateFile(input_dump_file, kCrashFormatWithDumpFile));
  SetUpDriErrorStateToReturn(kSampleDriErrorStateEncoded);
  SetUpCallDmesgToReturn(kSampleDmesg);
  SetUpLogsLong();
  collector_.set_max_upload_bytes_for_test(1000);
  EXPECT_TRUE(
      collector_.HandleCrash(input_dump_file, 123, 456, "chrome_test", -1));

  // Log file not written.
  EXPECT_FALSE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.chrome.txt.gz", nullptr));

  // Error state & dmesg file still written even after log file rejected.
  base::FilePath output_dri_error_file;
  ExpectSampleDriErrorState(output_dri_error_file);

  base::FilePath output_dmesg_file;
  int64_t dmesg_log_compressed_size = 0;
  ExpectSampleDmesg(output_dmesg_file, dmesg_log_compressed_size);

  // .dmp file and other files in the input dump still written.
  base::FilePath output_dump_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.dmp", &output_dump_file));
  base::FilePath other_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123-foo_txt.other", &other_file));

  base::FilePath meta_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.meta", &meta_file));
  std::string meta_file_contents;
  EXPECT_TRUE(base::ReadFileToString(meta_file, &meta_file_contents));
  EXPECT_EQ(collector_.get_bytes_written(),
            meta_file_contents.size() + kOutputDumpFileSize +
                dmesg_log_compressed_size + kOutputOtherFileSize +
                strlen(kSampleDriErrorStateDecoded));
  EXPECT_THAT(meta_file_contents,
              HasSubstr("payload=" + output_dump_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_file_some_file=" +
                                            other_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, Not(HasSubstr("upload_file_chrome.txt")));
  EXPECT_THAT(meta_file_contents,
              HasSubstr("upload_file_i915_error_state.log.xz=" +
                        output_dri_error_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents,
              HasSubstr("upload_file_dmesg.txt=" +
                        output_dmesg_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value1=abcdefghij"));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value2=12345"));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value3=ok"));
}

TEST_F(ChromeCollectorTest, HandleCrashSkipsLargeDriErrorFiles) {
  const FilePath& dir = scoped_temp_dir_.GetPath();
  FilePath input_dump_file = dir.Append("test.dmp");
  ASSERT_TRUE(test_util::CreateFile(input_dump_file, kCrashFormatWithDumpFile));
  SetUpDriErrorStateToReturn(kSampleDriErrorStateEncodedLong);
  SetUpCallDmesgToReturn(kSampleDmesg);
  SetUpLogsShort();
  collector_.set_max_upload_bytes_for_test(1000);
  EXPECT_TRUE(
      collector_.HandleCrash(input_dump_file, 123, 456, "chrome_test", -1));

  // Dri Error State file not written.
  EXPECT_FALSE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.i915_error_state.log.xz",
      nullptr));

  // Log & dmesg files still written even after Dri Error State file rejected.
  base::FilePath output_dmesg_file;
  int64_t dmesg_log_compressed_size = 0;
  ExpectSampleDmesg(output_dmesg_file, dmesg_log_compressed_size);

  base::FilePath output_log;
  int64_t output_log_compressed_size = 0;
  ExpectShortOutputLog(output_log, output_log_compressed_size);

  // .dmp file and other files in the input dump still written.
  base::FilePath output_dump_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.dmp", &output_dump_file));
  base::FilePath other_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123-foo_txt.other", &other_file));

  base::FilePath meta_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.meta", &meta_file));
  std::string meta_file_contents;
  EXPECT_TRUE(base::ReadFileToString(meta_file, &meta_file_contents));
  EXPECT_EQ(collector_.get_bytes_written(),
            meta_file_contents.size() + kOutputDumpFileSize +
                dmesg_log_compressed_size + kOutputOtherFileSize +
                output_log_compressed_size);
  EXPECT_THAT(meta_file_contents,
              HasSubstr("payload=" + output_dump_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_file_some_file=" +
                                            other_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_file_chrome.txt=" +
                                            output_log.BaseName().value()));
  EXPECT_THAT(meta_file_contents,
              Not(HasSubstr("upload_file_i915_error_state.log.xz")));
  EXPECT_THAT(meta_file_contents,
              HasSubstr("upload_file_dmesg.txt=" +
                        output_dmesg_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value1=abcdefghij"));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value2=12345"));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value3=ok"));
}

TEST_F(ChromeCollectorTest, HandleCrashSkipsLargeDmesgFiles) {
  const FilePath& dir = scoped_temp_dir_.GetPath();
  FilePath input_dump_file = dir.Append("test.dmp");
  ASSERT_TRUE(test_util::CreateFile(input_dump_file, kCrashFormatWithDumpFile));
  SetUpDriErrorStateToReturn(kSampleDriErrorStateEncoded);
  SetUpCallDmesgToReturn(GetDmesgLong());
  SetUpLogsShort();
  collector_.set_max_upload_bytes_for_test(1000);
  EXPECT_TRUE(
      collector_.HandleCrash(input_dump_file, 123, 456, "chrome_test", -1));

  // dmesg file not written.
  EXPECT_FALSE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.dmesg.txt.gz", nullptr));

  // Log & dri error files still written even after dmesg file rejected.
  base::FilePath output_dri_error_file;
  ExpectSampleDriErrorState(output_dri_error_file);

  base::FilePath output_log;
  int64_t output_log_compressed_size = 0;
  ExpectShortOutputLog(output_log, output_log_compressed_size);

  // .dmp file and other files in the input dump still written.
  base::FilePath output_dump_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.dmp", &output_dump_file));
  base::FilePath other_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123-foo_txt.other", &other_file));

  base::FilePath meta_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.meta", &meta_file));
  std::string meta_file_contents;
  EXPECT_TRUE(base::ReadFileToString(meta_file, &meta_file_contents));
  EXPECT_EQ(collector_.get_bytes_written(),
            meta_file_contents.size() + kOutputDumpFileSize +
                strlen(kSampleDriErrorStateDecoded) + kOutputOtherFileSize +
                output_log_compressed_size);
  EXPECT_THAT(meta_file_contents,
              HasSubstr("payload=" + output_dump_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_file_some_file=" +
                                            other_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_file_chrome.txt=" +
                                            output_log.BaseName().value()));
  EXPECT_THAT(meta_file_contents,
              HasSubstr("upload_file_i915_error_state.log.xz=" +
                        output_dri_error_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, Not(HasSubstr("upload_file_dmesg.txt")));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value1=abcdefghij"));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value2=12345"));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value3=ok"));
}

TEST_F(ChromeCollectorTest, HandleCrashSkipsLargeSupplementalFiles) {
  const FilePath& dir = scoped_temp_dir_.GetPath();
  FilePath input_dump_file = dir.Append("test.dmp");
  ASSERT_TRUE(test_util::CreateFile(input_dump_file, kCrashFormatWithDumpFile));
  SetUpDriErrorStateToReturn(kSampleDriErrorStateEncodedLong);
  SetUpCallDmesgToReturn(GetDmesgLong());
  SetUpLogsLong();
  collector_.set_max_upload_bytes_for_test(1000);
  EXPECT_TRUE(
      collector_.HandleCrash(input_dump_file, 123, 456, "chrome_test", -1));

  // Dri Error State file not written.
  EXPECT_FALSE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.i915_error_state.log.xz",
      nullptr));

  // dmesg file not written
  EXPECT_FALSE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.dmesg.txt.gz", nullptr));

  // Log file not written.
  EXPECT_FALSE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.chrome.txt.gz", nullptr));

  // .dmp file and other files in the input dump still written.
  base::FilePath output_dump_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.dmp", &output_dump_file));
  base::FilePath other_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123-foo_txt.other", &other_file));

  base::FilePath meta_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.meta", &meta_file));
  std::string meta_file_contents;
  EXPECT_TRUE(base::ReadFileToString(meta_file, &meta_file_contents));
  EXPECT_EQ(
      collector_.get_bytes_written(),
      meta_file_contents.size() + kOutputDumpFileSize + kOutputOtherFileSize);
  EXPECT_THAT(meta_file_contents,
              HasSubstr("payload=" + output_dump_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_file_some_file=" +
                                            other_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, Not(HasSubstr("upload_file_chrome.txt")));
  EXPECT_THAT(meta_file_contents,
              Not(HasSubstr("upload_file_i915_error_state.log.xz")));
  EXPECT_THAT(meta_file_contents, Not(HasSubstr("upload_file_dmesg.txt")));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value1=abcdefghij"));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value2=12345"));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value3=ok"));
}

TEST_F(ChromeCollectorTest, HandleDbusTimeouts) {
  const FilePath& dir = scoped_temp_dir_.GetPath();
  FilePath input_dump_file = dir.Append("test.dmp");
  ASSERT_TRUE(test_util::CreateFile(input_dump_file, kCrashFormatWithDumpFile));
  SetUpDriErrorStateToErrorOut(nullptr);
  SetUpCallDmesgToErrorOut(nullptr);
  SetUpLogsShort();
  collector_.set_max_upload_bytes_for_test(1000);
  EXPECT_TRUE(
      collector_.HandleCrash(input_dump_file, 123, 456, "chrome_test", -1));

  EXPECT_TRUE(brillo::FindLog(
      "Error retrieving DriErrorState from debugd: Call did not return"));
  EXPECT_TRUE(brillo::FindLog(
      "Error retrieving dmesg from debugd: Call did not return"));

  // Dri Error State file not written.
  EXPECT_FALSE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.i915_error_state.log.xz",
      nullptr));

  // dmesg file not written
  EXPECT_FALSE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.dmesg.txt.gz", nullptr));

  // Log file still written
  base::FilePath output_log;
  int64_t output_log_compressed_size = 0;
  ExpectShortOutputLog(output_log, output_log_compressed_size);

  // .dmp file and other files in the input dump still written.
  base::FilePath output_dump_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.dmp", &output_dump_file));
  base::FilePath other_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123-foo_txt.other", &other_file));

  base::FilePath meta_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.meta", &meta_file));
  std::string meta_file_contents;
  EXPECT_TRUE(base::ReadFileToString(meta_file, &meta_file_contents));
  EXPECT_EQ(collector_.get_bytes_written(),
            meta_file_contents.size() + kOutputDumpFileSize +
                kOutputOtherFileSize + output_log_compressed_size);
  EXPECT_THAT(meta_file_contents,
              HasSubstr("payload=" + output_dump_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_file_some_file=" +
                                            other_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_file_chrome.txt=" +
                                            output_log.BaseName().value()));
  EXPECT_THAT(meta_file_contents,
              Not(HasSubstr("upload_file_i915_error_state.log.xz")));
  EXPECT_THAT(meta_file_contents, Not(HasSubstr("upload_file_dmesg.txt")));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value1=abcdefghij"));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value2=12345"));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value3=ok"));
}

TEST_F(ChromeCollectorTest, HandleDbusErrors) {
  const FilePath& dir = scoped_temp_dir_.GetPath();
  FilePath input_dump_file = dir.Append("test.dmp");
  ASSERT_TRUE(test_util::CreateFile(input_dump_file, kCrashFormatWithDumpFile));
  brillo::ErrorPtr dir_error_state_error = brillo::Error::CreateNoLog(
      FROM_HERE, /*domain=*/"source.chromium.org", /*code=*/"EBAD",
      /*message=*/"dri_error_state retrieval failed", /*inner_error=*/nullptr);
  brillo::ErrorPtr dmesg_error = brillo::Error::CreateNoLog(
      FROM_HERE, /*domain=*/"source.chromium.org", /*code=*/"EPERM",
      /*message=*/"dmesg no permission", /*inner_error=*/nullptr);
  SetUpDriErrorStateToErrorOut(dir_error_state_error.get());
  SetUpCallDmesgToErrorOut(dmesg_error.get());
  SetUpLogsShort();
  collector_.set_max_upload_bytes_for_test(1000);
  EXPECT_TRUE(
      collector_.HandleCrash(input_dump_file, 123, 456, "chrome_test", -1));

  EXPECT_TRUE(
      brillo::FindLog("Error retrieving DriErrorState from debugd: "
                      "dri_error_state retrieval failed"));
  EXPECT_TRUE(brillo::FindLog(
      "Error retrieving dmesg from debugd: dmesg no permission"));

  // Dri Error State file not written.
  EXPECT_FALSE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.i915_error_state.log.xz",
      nullptr));

  // dmesg file not written
  EXPECT_FALSE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.dmesg.txt.gz", nullptr));

  // Log file still written
  base::FilePath output_log;
  int64_t output_log_compressed_size = 0;
  ExpectShortOutputLog(output_log, output_log_compressed_size);

  // .dmp file and other files in the input dump still written.
  base::FilePath output_dump_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.dmp", &output_dump_file));
  base::FilePath other_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123-foo_txt.other", &other_file));

  base::FilePath meta_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "chrome_test.*.123.meta", &meta_file));
  std::string meta_file_contents;
  EXPECT_TRUE(base::ReadFileToString(meta_file, &meta_file_contents));
  EXPECT_EQ(collector_.get_bytes_written(),
            meta_file_contents.size() + kOutputDumpFileSize +
                kOutputOtherFileSize + output_log_compressed_size);
  EXPECT_THAT(meta_file_contents,
              HasSubstr("payload=" + output_dump_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_file_some_file=" +
                                            other_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_file_chrome.txt=" +
                                            output_log.BaseName().value()));
  EXPECT_THAT(meta_file_contents,
              Not(HasSubstr("upload_file_i915_error_state.log.xz")));
  EXPECT_THAT(meta_file_contents, Not(HasSubstr("upload_file_dmesg.txt")));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value1=abcdefghij"));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value2=12345"));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value3=ok"));
}

TEST_F(ChromeCollectorTest, HandleCrashForJavaScript) {
  const FilePath& dir = scoped_temp_dir_.GetPath();
  FilePath input_file = dir.Append("test.jsinput");
  ASSERT_TRUE(test_util::CreateFile(input_file, kCrashFormatWithJSStack));
  SetUpLogsShort();

  int input_fd = open(input_file.value().c_str(), O_RDONLY);
  ASSERT_NE(input_fd, -1) << "open " << input_file.value() << " failed: "
                          << logging::SystemErrorCodeToString(errno);
  // HandleCrashThroughMemfd will close input_fd.
  EXPECT_TRUE(collector_.HandleCrashThroughMemfd(input_fd, 123, 456, "",
                                                 "jserror", "", -1));

  base::FilePath output_dri_error_file;
  EXPECT_FALSE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "jserror.*.123.i915_error_state.log.xz",
      &output_dri_error_file));

  base::FilePath output_log;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "jserror.*.123.chrome.txt.gz", &output_log));
  int64_t output_log_compressed_size = 0;
  EXPECT_TRUE(base::GetFileSize(output_log, &output_log_compressed_size));
  Decompress(output_log);
  base::FilePath output_log_uncompressed = output_log.RemoveFinalExtension();
  std::string output_log_contents;
  EXPECT_TRUE(
      base::ReadFileToString(output_log_uncompressed, &output_log_contents));
  EXPECT_EQ(output_log_contents, "JavaScript has nothing to do with Java\n");

  base::FilePath output_stack_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "jserror.*.123.js_stack", &output_stack_file));
  std::string output_stack_file_contents;
  EXPECT_TRUE(
      base::ReadFileToString(output_stack_file, &output_stack_file_contents));
  EXPECT_EQ(output_stack_file_contents, "0123456789abcdefghij");

  base::FilePath other_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "jserror.*.123-foo_txt.other", &other_file));
  std::string other_file_contents;
  EXPECT_TRUE(base::ReadFileToString(other_file, &other_file_contents));
  EXPECT_EQ(other_file_contents, "12345\n789\n12345");

  base::FilePath meta_file;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "jserror.*.123.meta", &meta_file));
  std::string meta_file_contents;
  EXPECT_TRUE(base::ReadFileToString(meta_file, &meta_file_contents));
  EXPECT_EQ(collector_.get_bytes_written(),
            meta_file_contents.size() + output_log_compressed_size +
                other_file_contents.size() + output_stack_file_contents.size());
  EXPECT_THAT(meta_file_contents,
              HasSubstr("payload=" + output_stack_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_file_some_file=" +
                                            other_file.BaseName().value()));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_file_chrome.txt=" +
                                            output_log.BaseName().value()));
  EXPECT_THAT(meta_file_contents,
              Not(HasSubstr("upload_file_i915_error_state.log.xz")));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value1=abcdefghij"));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value2=12345"));
  EXPECT_THAT(meta_file_contents, HasSubstr("upload_var_value3=ok"));
  EXPECT_THAT(meta_file_contents, HasSubstr("done=1"));
}

TEST_F(ChromeCollectorTest, HandleCrashForJavaScriptLacros) {
  const FilePath& dir = scoped_temp_dir_.GetPath();
  FilePath input_file = dir.Append("lacros.jsinput");
  ASSERT_TRUE(test_util::CreateFile(input_file, kCrashFormatWithLacrosJSStack));
  SetUpLogsShort();

  int input_fd = open(input_file.value().c_str(), O_RDONLY);
  ASSERT_NE(input_fd, -1) << "open " << input_file.value() << " failed: "
                          << logging::SystemErrorCodeToString(errno);
  // HandleCrashThroughMemfd will close input_fd.
  EXPECT_TRUE(collector_.HandleCrashThroughMemfd(input_fd, 123, 456, "",
                                                 "jserror", "", -1));

  base::FilePath output_dri_error_file;
  EXPECT_FALSE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "jserror.*.123.i915_error_state.log.xz",
      &output_dri_error_file));

  base::FilePath output_log;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "jserror.*.123.chrome.txt.gz", &output_log));
  int64_t output_log_compressed_size = 0;
  EXPECT_TRUE(base::GetFileSize(output_log, &output_log_compressed_size));
  Decompress(output_log);
  base::FilePath output_log_uncompressed = output_log.RemoveFinalExtension();
  std::string output_log_contents;
  EXPECT_TRUE(
      base::ReadFileToString(output_log_uncompressed, &output_log_contents));
  EXPECT_EQ(output_log_contents, "welcome to lacros\n");
}
