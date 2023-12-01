// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/crash_sender_util.h"

#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>

#include <iterator>
#include <memory>
#include <numeric>
#include <optional>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/command_line.h>
#include <base/files/file.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/hash/md5.h>
#include <base/json/json_reader.h>
#include <base/logging.h>
#include <base/strings/strcat.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/time/time.h>
#include <base/values.h>
#include <brillo/flag_helper.h>
#include <brillo/http/http_transport.h>
#include <brillo/http/http_transport_fake.h>
#include <brillo/key_value_store.h>
#include <brillo/mime_utils.h>
#include <brillo/process/process.h>
#include <brillo/syslog_logging.h>
#include <chromeos/dbus/service_constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <metrics/metrics_library_mock.h>
#include <shill/dbus-proxy-mocks.h>

#include "crash-reporter/crash_sender_base.h"
#include "crash-reporter/crash_sender_paths.h"
#include "crash-reporter/paths.h"
#include "crash-reporter/test_util.h"
#include "crash-reporter/util.h"

using ::testing::_;
using ::testing::AllOf;
using ::testing::ContainsRegex;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::ExitedWithCode;
using ::testing::Ge;
using ::testing::HasSubstr;
using ::testing::Invoke;
using ::testing::IsEmpty;
using ::testing::Le;
using ::testing::Ne;
using ::testing::Pointee;
using ::testing::Return;
using ::testing::UnorderedElementsAre;

using test_util::CreateClientIdFile;
using test_util::FakeSleep;
using test_util::kFakeClientId;

namespace util {
namespace {

constexpr char kChromeCrashLog[] = "/var/log/chrome/Crash Reports/uploads.log";

// Enum types for setting the runtime conditions.
enum BuildType { kOfficialBuild, kUnofficialBuild };
enum SessionType { kSignInMode, kGuestMode };
enum MetricsFlag { kMetricsEnabled, kMetricsDisabled };

// This is what the kConnectionState property will get set to for mocked calls
// into shill flimflam manager.
std::string* g_connection_state;

// Simple mock for Clock. We can't use SimpleTestClock in some places because
// we need Now to return different values on different calls, and we don't have
// a hook to gain control in between the Now() calls.
class MockClock : public base::Clock {
 public:
  ~MockClock() override {}
  MOCK_METHOD(base::Time, Now, (), (const override));
};

// Reply with either a 200 or a 429 status code depending on what tests need.
void MockMethodHandler(bool success,
                       std::string response_text,
                       const brillo::http::fake::ServerRequest& request,
                       brillo::http::fake::ServerResponse* response) {
  int response_code;
  if (success) {
    response_code = brillo::http::status_code::Ok;
  } else {
    // If the response is a number, let's use it. Default to error 429
    if (!base::StringToInt(response_text, &response_code)) {
      response_code = brillo::http::status_code::TooManyRequests;
    }
  }
  LOG(INFO) << "Mock HTTP request - replying with status code: "
            << response_code << ", text: " << response_text;

  response->ReplyText(response_code, response_text, brillo::mime::text::kPlain);
}

// Replaces Sender's functionality with a predefined behavior.
class MockSender : public util::Sender {
 public:
  MOCK_METHOD(std::shared_ptr<brillo::http::Transport>,
              GetTransport,
              (),
              (override));

  MockSender(bool is_success,
             std::string response_text,
             std::unique_ptr<MetricsLibraryMock> metrics_lib,
             std::unique_ptr<base::Clock> clock,
             const Sender::Options& options)
      : Sender(std::move(metrics_lib), std::move(clock), options),
        success_(is_success),
        response_(std::move(response_text)) {
    ON_CALL(*this, GetTransport)
        .WillByDefault([this]() -> std::shared_ptr<brillo::http::Transport> {
          std::shared_ptr<brillo::http::fake::Transport> fake_transport =
              std::make_shared<brillo::http::fake::Transport>();
          fake_transport->AddHandler(
              kReportUploadProdUrl, brillo::http::request_type::kPost,
              base::BindRepeating(MockMethodHandler, success_, response_));

          return fake_transport;
        });
  }

 private:
  bool success_;
  std::string response_;
};

// Parses the Chrome uploads.log file from Sender to a vector of items per line.
// Example:
//
// {"field1":"foo1","field2":"foo2"}
// {"field1":"bar1","field2":"bar2"}
//
// => [{"field1":"foo1","field2":"foo2"}, {"field1":"bar1","field2":"bar2"}]
//
std::vector<std::optional<base::Value>> ParseChromeUploadsLog(
    const std::string& contents) {
  std::vector<std::optional<base::Value>> rows;

  std::vector<std::string> lines = base::SplitString(
      contents, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  for (const auto& line : lines) {
    rows.push_back(base::JSONReader::Read(line));
  }

  return rows;
}

// Helper function for calling GetBasePartOfCrashFile() concisely for tests.
std::string GetBasePartHelper(const std::string& file_name) {
  return GetBasePartOfCrashFile(base::FilePath(file_name)).value();
}

// Creates lsb-release file with information about the build type.
bool CreateLsbReleaseFile(BuildType type) {
  std::string label = "Official build";
  if (type == kUnofficialBuild)
    label = "Test build";

  return test_util::CreateFile(paths::Get("/etc/lsb-release"),
                               "CHROMEOS_RELEASE_DESCRIPTION=" + label + "\n");
}

// Creates a file that indicates uploading of device coredumps is allowed.
bool CreateDeviceCoredumpUploadAllowedFile() {
  return test_util::CreateFile(
      paths::GetAt(paths::kCrashReporterStateDirectory,
                   paths::kDeviceCoredumpUploadAllowed),
      "");
}

// Returns file names found in |directory|.
std::vector<base::FilePath> GetFileNamesIn(const base::FilePath& directory) {
  std::vector<base::FilePath> files;
  base::FileEnumerator iter(directory, false /* recursive */,
                            base::FileEnumerator::FILES, "*");
  for (base::FilePath file = iter.Next(); !file.empty(); file = iter.Next())
    files.push_back(file);
  return files;
}

// Set the flag which indicates we are mocking crash sending, either
// successfully or as a a failure.
void SetMockCrashSending(bool success) {
  util::g_force_is_mock = true;
  util::g_force_is_mock_successful = success;
}

// Clears out the flag which indicates we're mocking crash sending.
void ClearMockCrashSending() {
  util::g_force_is_mock = false;
}

// Handles calls for getting the network state.
bool GetShillProperties(
    brillo::VariantDictionary* dict,
    brillo::ErrorPtr* error,
    int timeout_ms = dbus::ObjectProxy::TIMEOUT_USE_DEFAULT) {
  dict->emplace(shill::kConnectionStateProperty, *g_connection_state);
  return true;
}

class CrashSenderUtilTest : public testing::Test {
 protected:
  void SetUp() override {
    // Grab executable path before TearDown() can reset base::CommandLine.
    if (build_directory_ == nullptr) {
      base::FilePath my_executable_path =
          base::CommandLine::ForCurrentProcess()->GetProgram();
      build_directory_ = new base::FilePath(my_executable_path.DirName());
    }
    metrics_lib_ = std::make_unique<MetricsLibraryMock>();
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    test_dir_ = temp_dir_.GetPath();
    paths::SetPrefixForTesting(test_dir_);

    // Make sure the directory for the lock file exists.
    const base::FilePath lock_file_path =
        paths::Get(paths::kCrashSenderLockFile);
    const base::FilePath lock_file_directory = lock_file_path.DirName();
    ASSERT_TRUE(base::CreateDirectory(lock_file_directory));

    // Creates the directory where crashes will be stored, normally done by
    // Chrome
    ASSERT_TRUE(base::CreateDirectory(
        paths::Get(paths::ChromeCrashLog::Get()).DirName()));

    // We need to properly init the CommandLine object for the command line
    // parsing tests.
    base::CommandLine::Init(0, nullptr);
  }

  void TearDown() override {
    ClearMockCrashSending();
    paths::SetPrefixForTesting(base::FilePath());

    // ParseCommandLine() uses base::CommandLine via
    // brillo::FlagHelper. Reset these here to avoid side effects.
    if (base::CommandLine::InitializedForCurrentProcess())
      base::CommandLine::Reset();
    brillo::FlagHelper::ResetForTesting();
  }

  // Checks to see if a file is locked by AcquireLockFileOrDie().
  bool IsFileLocked(const base::FilePath& file_name) {
    // AcquireLockFileOrDie creates the file when it runs, so count the file
    // not existing as "not locked".
    if (!base::PathExists(file_name)) {
      return false;
    }

    // There's no portable & reliable way for a process to test its own file
    // locks, so we have to spawn another process (which won't inherit the
    // locks) to do the testing.
    CHECK(build_directory_);
    base::FilePath lock_file_tester =
        build_directory_->Append("lock_file_tester");
    std::string command = lock_file_tester.value() + " " + file_name.value();
    int test_result = system(command.c_str());
    if (WIFEXITED(test_result)) {
      if (WEXITSTATUS(test_result) == 0) {
        return true;
      }
      if (WEXITSTATUS(test_result) == 1) {
        return false;
      }
      LOG(FATAL) << "lock_file_tester failed with exit code "
                 << WEXITSTATUS(test_result);
    }
    LOG(FATAL)
        << "lock_file_tester failed before exiting; complete wait status "
        << test_result;
    return false;
  }

  // Lock the indicated file |file_name| using base::File::Lock() so that
  // AcquireLockFileOrDie() will fail to acquire it. File will be created if
  // it doesn't exist. Returns when the file is actually locked. Since locks are
  // per-process, in order to prevent this process from locking the file, we
  // have to spawn a separate process to hold the lock; the process holding the
  // lock is returned. It can be killed to release the lock.
  std::unique_ptr<brillo::Process> LockFile(const base::FilePath& file_name) {
    base::Time start_time = base::Time::Now();
    auto lock_process = std::make_unique<brillo::ProcessImpl>();
    CHECK(build_directory_);
    base::FilePath lock_file_holder =
        build_directory_->Append("hold_lock_file");
    lock_process->AddArg(lock_file_holder.value());
    lock_process->AddArg(file_name.value());
    CHECK(lock_process->Start());

    // Wait for the file to actually be locked. Don't wait forever in case the
    // subprocess fails in some way.
    base::Time stop_time = base::Time::Now() + base::Minutes(1);
    bool success = false;
    base::Time wait_start_time = base::Time::Now();
    LOG(INFO) << "Took " << wait_start_time - start_time
              << " to start subprocess";
    while (!success && base::Time::Now() < stop_time) {
      base::File lock_file(file_name, base::File::FLAG_OPEN |
                                          base::File::FLAG_READ |
                                          base::File::FLAG_WRITE);
      if (lock_file.IsValid()) {
        struct flock lock;
        lock.l_type = F_WRLCK;
        lock.l_whence = SEEK_SET;
        lock.l_start = 0;
        lock.l_len = 0;
        if (fcntl(lock_file.GetPlatformFile(), F_GETLK, &lock) == 0 &&
            lock.l_type == F_WRLCK) {
          success = true;
        }
      }

      if (!success) {
        base::PlatformThread::Sleep(base::Seconds(5));
      }
    }
    LOG(INFO) << "Took " << base::Time::Now() - wait_start_time
              << " to verify file lock";

    CHECK(success) << "Subprocess did not lock " << file_name.value();
    return lock_process;
  }

  // Creates a file at |file_path| with contents |content| and sets its access
  // and modification time to |timestamp|.
  bool CreateFile(const base::FilePath& file_path,
                  base::StringPiece content,
                  base::Time timestamp) {
    if (!test_util::CreateFile(file_path, content))
      return false;

    if (!test_util::TouchFileHelper(file_path, timestamp))
      return false;

    return true;
  }

  // Creates test crash files in |crash_directory|. Returns true on success.
  bool CreateTestCrashFiles(const base::FilePath& crash_directory) {
    const base::Time now = test_util::GetDefaultTime();
    const base::TimeDelta hour = base::Hours(1);

    // Choose timestamps so that the return value of GetMetaFiles() is sorted
    // per timestamps correctly.
    const base::Time good_meta_time = now - hour * 3;
    const base::Time absolute_meta_time = now - hour * 2;
    const base::Time recent_os_meta_time = now - hour;
    const base::Time devcore_meta_time = now;

    // These should be kept, since the payload is a known kind and exists.
    good_meta_ = crash_directory.Append("good.meta");
    good_log_ = crash_directory.Append("good.log");
    if (!CreateFile(good_meta_, "payload=good.log\ndone=1\n", good_meta_time))
      return false;
    if (!CreateFile(good_log_, "", now))
      return false;

    // These should be removed, as we shouldn't accept files outside of the
    // crash log directory.
    absolute_meta_ = crash_directory.Append("absolute.meta");
    absolute_log_ = crash_directory.Append("absolute.log");
    if (!CreateFile(absolute_meta_,
                    "payload=" + absolute_log_.value() + "\n" + "done=1\n",
                    absolute_meta_time))
      return false;
    if (!CreateFile(absolute_log_, "", now))
      return false;

    // These should be removed, since the `alreadyuploaded` file exists.
    uploaded_meta_ = crash_directory.Append("uploaded.meta");
    uploaded_log_ = crash_directory.Append("uploaded.log");
    uploaded_already_ = crash_directory.Append("uploaded.alreadyuploaded");
    if (!CreateFile(uploaded_meta_, "payload=uploaded.log\ndone=1\n",
                    good_meta_time))
      return false;
    if (!CreateFile(uploaded_log_, "", now))
      return false;
    if (!CreateFile(uploaded_already_, "", now))
      return false;

    // This should be ignored as corrupt. Payload can't be /.
    root_payload_meta_ = crash_directory.Append("root_payload.meta");
    if (!test_util::CreateFile(root_payload_meta_,
                               "payload=/\n"
                               "done=1\n"))
      return false;

    // These should be ignored, if uploading of device coredumps is not allowed.
    devcore_meta_ = crash_directory.Append("devcore.meta");
    devcore_devcore_ = crash_directory.Append("devcore.devcore");
    if (!CreateFile(devcore_meta_,
                    "payload=devcore.devcore\n"
                    "done=1\n",
                    devcore_meta_time))
      return false;
    if (!CreateFile(devcore_devcore_, "", now))
      return false;

    // These should be kept, since the payload is a known kind and exists.
    txt_meta_ = crash_directory.Append("txt.meta");
    txt_txt_ = crash_directory.Append("txt.txt");
    if (!CreateFile(txt_meta_, "payload=txt.txt\ndone=1\n", now))
      return false;
    if (!CreateFile(txt_txt_, "", now))
      return false;

    // This should be ignored, since the metadata is corrupted but the file is
    // still fairly new.
    new_corrupted_meta_ = crash_directory.Append("new_corrupted.meta");
    if (!CreateFile(new_corrupted_meta_, "foo\ndone=1\n", now))
      return false;

    // This should be removed, since metadata is corrupted.
    old_corrupted_meta_ = crash_directory.Append("old_corrupted.meta");
    if (!CreateFile(old_corrupted_meta_, "!@#$%^&*\ndone=1\n", now - hour * 1))
      return false;

    // This should be removed, since no payload info is recorded.
    empty_meta_ = crash_directory.Append("empty.meta");
    if (!CreateFile(empty_meta_, "done=1\n", now))
      return false;

    // This should be removed, since the payload file does not exist.
    nonexistent_meta_ = crash_directory.Append("nonexistent.meta");
    if (!CreateFile(nonexistent_meta_,
                    "payload=nonexistent.log\n"
                    "done=1\n",
                    now))
      return false;

    // These should be removed, since the payload is an unknown kind.
    unknown_meta_ = crash_directory.Append("unknown.meta");
    unknown_xxx_ = crash_directory.Append("unknown.xxx");
    if (!CreateFile(unknown_meta_,
                    "payload=unknown.xxx\n"
                    "done=1\n",
                    now))
      return false;
    if (!CreateFile(unknown_xxx_, "", now))
      return false;

    // This should be removed, since the meta file is old.
    old_incomplete_meta_ = crash_directory.Append("old_incomplete.meta");
    if (!CreateFile(old_incomplete_meta_, "payload=good.log\n", now))
      return false;
    if (!test_util::TouchFileHelper(old_incomplete_meta_, now - hour * 24))
      return false;

    // This should be ignored, even though the payload doesn't exist,
    // since the meta file is new.
    new_incomplete_meta_ = crash_directory.Append("new_incomplete.meta");
    if (!CreateFile(new_incomplete_meta_, "payload=nonexistent.log\n", now))
      return false;

    // This should be ignored, even though there's no payload, since the meta
    // file is new.
    new_empty_meta_ = crash_directory.Append("new_empty.meta");
    if (!CreateFile(new_empty_meta_, "", now))
      return false;

    // This should be kept since the OS timestamp is recent.
    recent_os_meta_ = crash_directory.Append("recent_os.meta");
    if (!CreateFile(recent_os_meta_,
                    base::StringPrintf(
                        "payload=recent_os.log\n"
                        "os_millis=%" PRId64 "\n"
                        "done=1\n",
                        (now - base::Time::UnixEpoch()).InMilliseconds()),
                    recent_os_meta_time)) {
      return false;
    }
    recent_os_log_ = crash_directory.Append("recent_os.log");
    if (!CreateFile(recent_os_log_, "", now))
      return false;

    // This should be removed since the OS timestamp is old.
    old_os_meta_ = crash_directory.Append("old_os.meta");
    if (!CreateFile(old_os_meta_,
                    base::StringPrintf(
                        "payload=good.log\n"
                        "os_millis=%" PRId64 "\n"
                        "done=1\n",
                        ((now - base::Time::UnixEpoch()) - base::Days(200))
                            .InMilliseconds()),
                    now)) {
      return false;
    }

    // This should not be removed since the OS timestamp is old, but lacros is
    // new.
    old_os_new_lacros_meta_ = crash_directory.Append("old_os_new_lacros.meta");
    if (!CreateFile(old_os_new_lacros_meta_,
                    base::StringPrintf(
                        "payload=good.log\n"
                        "os_millis=%" PRId64 "\n"
                        "build_time_millis=%" PRId64 "\n"
                        "done=1\n",
                        ((now - base::Time::UnixEpoch()) - base::Days(200))
                            .InMilliseconds(),
                        ((now - base::Time::UnixEpoch()) - base::Days(20))
                            .InMilliseconds()),
                    now)) {
      return false;
    }

    // This should not be removed since the OS timestamp and lacros are old.
    old_os_old_lacros_meta_ = crash_directory.Append("old_os_old_lacros.meta");
    if (!CreateFile(old_os_old_lacros_meta_,
                    base::StringPrintf(
                        "payload=good.log\n"
                        "os_millis=%" PRId64 "\n"
                        "build_time_millis=%" PRId64 "\n"
                        "done=1\n",
                        ((now - base::Time::UnixEpoch()) - base::Days(200))
                            .InMilliseconds(),
                        ((now - base::Time::UnixEpoch()) - base::Days(200))
                            .InMilliseconds()),
                    now)) {
      return false;
    }

    // Create large metadata with the size of 1MiB + 1byte.
    large_meta_ = crash_directory.Append("large.meta");
    if (!CreateFile(large_meta_, std::string(1024 * 1024 + 1, 'x'), now)) {
      return false;
    }

    loop_meta_ = crash_directory.Append("loop.meta");
    if (!CreateFile(
            loop_meta_,
            "payload=good.log\nupload_var_crash_loop_mode=true\ndone=1\n", now))
      return false;

    return true;
  }

  // Sets the runtime conditions that affect behaviors of ChooseAction().
  // Returns true on success.
  bool SetConditions(BuildType build_type,
                     SessionType session_type,
                     MetricsFlag metrics_flag) {
    return SetConditions(build_type, session_type, metrics_flag,
                         metrics_lib_.get());
  }

  // Version of SetConditions useful for tests that need to create a Sender.
  // Sender owns the MetricsLibraryInterface pointer, so metrics_lib_ is
  // usually nullptr in these tests.
  static bool SetConditions(BuildType build_type,
                            SessionType session_type,
                            MetricsFlag metrics_flag,
                            MetricsLibraryMock* metrics_lib) {
    if (!CreateLsbReleaseFile(build_type))
      return false;

    metrics_lib->set_guest_mode(session_type == kGuestMode);
    metrics_lib->set_metrics_enabled(metrics_flag == kMetricsEnabled);

    return true;
  }

  // Directory that the test executable lives in. We reset CommandLine during
  // TearDown, so we must grab this information early.
  static base::FilePath* build_directory_;
  base::AtExitManager at_exit_manager_;

  std::unique_ptr<MetricsLibraryMock> metrics_lib_;
  base::ScopedTempDir temp_dir_;
  base::FilePath test_dir_;

  base::FilePath good_meta_;
  base::FilePath good_log_;
  base::FilePath absolute_meta_;
  base::FilePath absolute_log_;
  base::FilePath uploaded_meta_;
  base::FilePath uploaded_log_;
  base::FilePath uploaded_already_;
  base::FilePath root_payload_meta_;
  base::FilePath devcore_meta_;
  base::FilePath devcore_devcore_;
  base::FilePath txt_meta_;
  base::FilePath txt_txt_;
  base::FilePath empty_meta_;
  base::FilePath new_corrupted_meta_;
  base::FilePath old_corrupted_meta_;
  base::FilePath nonexistent_meta_;
  base::FilePath unknown_meta_;
  base::FilePath unknown_xxx_;
  base::FilePath old_incomplete_meta_;
  base::FilePath new_incomplete_meta_;
  base::FilePath new_empty_meta_;
  base::FilePath recent_os_meta_;
  base::FilePath recent_os_log_;
  base::FilePath old_os_meta_;
  base::FilePath old_os_new_lacros_meta_;
  base::FilePath old_os_old_lacros_meta_;
  base::FilePath large_meta_;
  base::FilePath loop_meta_;
};

// Upon destruction, resets crash log path, log prefix and flags changed by the
// dry run mode during command line parsing.
class ScopedDryRunSettingsResetter {
 public:
  ScopedDryRunSettingsResetter() = default;
  ScopedDryRunSettingsResetter(const ScopedDryRunSettingsResetter&) = delete;
  ScopedDryRunSettingsResetter& operator=(const ScopedDryRunSettingsResetter&) =
      delete;
  ~ScopedDryRunSettingsResetter() {
    logging::SetLogPrefix(nullptr);
    brillo::SetLogFlags(brillo::GetLogFlags() & ~brillo::kLogHeader);
    paths::ChromeCrashLog::SetDryRun(false);
  }
};

base::FilePath* CrashSenderUtilTest::build_directory_ = nullptr;
using CrashSenderUtilDeathTest = CrashSenderUtilTest;

// Death tests that require parametrizing dry run mode.
class CrashSenderUtilDryRunParamDeathTest
    : public CrashSenderUtilDeathTest,
      public ::testing::WithParamInterface<bool> {
 protected:
  void SetUp() override {
    dry_run_ = GetParam();
    CrashSenderUtilDeathTest::SetUp();
  }
  bool dry_run_;
};

INSTANTIATE_TEST_SUITE_P(
    CrashSenderUtilDryRunParamDeathInstantiation,
    CrashSenderUtilDryRunParamDeathTest,
    ::testing::Bool(),
    [](const ::testing::TestParamInfo<
        CrashSenderUtilDryRunParamDeathTest::ParamType>& info) {
      std::ostringstream name;
      name << "dry_run_" << info.param;
      return name.str();
    });

}  // namespace

TEST_F(CrashSenderUtilTest, ParseCommandLine_NoFlags) {
  const char* argv[] = {"crash_sender"};
  base::CommandLine command_line(std::size(argv), argv);
  brillo::FlagHelper::GetInstance()->set_command_line_for_testing(
      &command_line);
  CommandLineFlags flags;
  ParseCommandLine(std::size(argv), argv, &flags);
  EXPECT_EQ(flags.max_spread_time.InSeconds(), kMaxSpreadTimeInSeconds);
  EXPECT_TRUE(flags.crash_directory.empty());
  EXPECT_FALSE(flags.ignore_rate_limits);
  EXPECT_FALSE(flags.ignore_hold_off_time);
  EXPECT_FALSE(flags.allow_dev_sending);
  EXPECT_FALSE(flags.ignore_pause_file);
  EXPECT_FALSE(flags.test_mode);
  EXPECT_FALSE(flags.upload_old_reports);
  EXPECT_FALSE(flags.force_upload_on_test_images);
  EXPECT_FALSE(flags.consent_already_checked_by_crash_reporter);
  EXPECT_FALSE(flags.dry_run);
  // Test here because the setting of ChromeCrashLog is done during CLI parsing.
  EXPECT_STREQ(paths::ChromeCrashLog::Get(), kChromeCrashLog);
}

TEST_F(CrashSenderUtilDeathTest, ParseCommandLine_InvalidMaxSpreadTime) {
  const char* argv[] = {"crash_sender", "--max_spread_time=-1"};
  base::CommandLine command_line(std::size(argv), argv);
  brillo::FlagHelper::GetInstance()->set_command_line_for_testing(
      &command_line);
  CommandLineFlags flags;
  EXPECT_DEATH(ParseCommandLine(std::size(argv), argv, &flags),
               "Invalid value for max spread time: -1");
}

TEST_F(CrashSenderUtilTest, ParseCommandLine_ValidMaxSpreadTime) {
  const char* argv[] = {"crash_sender", "--max_spread_time=0"};
  base::CommandLine command_line(std::size(argv), argv);
  brillo::FlagHelper::GetInstance()->set_command_line_for_testing(
      &command_line);
  CommandLineFlags flags;
  ParseCommandLine(std::size(argv), argv, &flags);
  EXPECT_EQ(base::Seconds(0), flags.max_spread_time);
  EXPECT_TRUE(flags.crash_directory.empty());
  EXPECT_FALSE(flags.ignore_rate_limits);
  EXPECT_FALSE(flags.ignore_hold_off_time);
  EXPECT_FALSE(flags.allow_dev_sending);
  EXPECT_FALSE(flags.ignore_pause_file);
  EXPECT_FALSE(flags.test_mode);
  EXPECT_FALSE(flags.upload_old_reports);
  EXPECT_FALSE(flags.force_upload_on_test_images);
  EXPECT_FALSE(flags.consent_already_checked_by_crash_reporter);
  EXPECT_FALSE(flags.dry_run);
  // Test here because the setting of ChromeCrashLog is done during CLI parsing.
  EXPECT_STREQ(paths::ChromeCrashLog::Get(), kChromeCrashLog);
}

TEST_F(CrashSenderUtilTest, ParseCommandLine_IgnoreRateLimits) {
  const char* argv[] = {"crash_sender", "--ignore_rate_limits"};
  base::CommandLine command_line(std::size(argv), argv);
  brillo::FlagHelper::GetInstance()->set_command_line_for_testing(
      &command_line);
  CommandLineFlags flags;
  ParseCommandLine(std::size(argv), argv, &flags);
  EXPECT_EQ(flags.max_spread_time.InSeconds(), kMaxSpreadTimeInSeconds);
  EXPECT_TRUE(flags.crash_directory.empty());
  EXPECT_TRUE(flags.ignore_rate_limits);
  EXPECT_FALSE(flags.ignore_hold_off_time);
  EXPECT_FALSE(flags.allow_dev_sending);
  EXPECT_FALSE(flags.ignore_pause_file);
  EXPECT_FALSE(flags.test_mode);
  EXPECT_FALSE(flags.upload_old_reports);
  EXPECT_FALSE(flags.force_upload_on_test_images);
  EXPECT_FALSE(flags.consent_already_checked_by_crash_reporter);
  EXPECT_FALSE(flags.dry_run);
  // Test here because the setting of ChromeCrashLog is done during CLI parsing.
  EXPECT_STREQ(paths::ChromeCrashLog::Get(), kChromeCrashLog);
}

TEST_F(CrashSenderUtilTest, ParseCommandLine_IgnoreHoldOffTime) {
  const char* argv[] = {"crash_sender", "--ignore_hold_off_time"};
  base::CommandLine command_line(std::size(argv), argv);
  brillo::FlagHelper::GetInstance()->set_command_line_for_testing(
      &command_line);
  CommandLineFlags flags;
  ParseCommandLine(std::size(argv), argv, &flags);
  EXPECT_EQ(flags.max_spread_time.InSeconds(), kMaxSpreadTimeInSeconds);
  EXPECT_TRUE(flags.crash_directory.empty());
  EXPECT_FALSE(flags.ignore_rate_limits);
  EXPECT_TRUE(flags.ignore_hold_off_time);
  EXPECT_FALSE(flags.allow_dev_sending);
  EXPECT_FALSE(flags.ignore_pause_file);
  EXPECT_FALSE(flags.test_mode);
  EXPECT_FALSE(flags.upload_old_reports);
  EXPECT_FALSE(flags.force_upload_on_test_images);
  EXPECT_FALSE(flags.consent_already_checked_by_crash_reporter);
  EXPECT_FALSE(flags.dry_run);
  // Test here because the setting of ChromeCrashLog is done during CLI parsing.
  EXPECT_STREQ(paths::ChromeCrashLog::Get(), kChromeCrashLog);
}

TEST_F(CrashSenderUtilTest, ParseCommandLine_CrashDirectory) {
  const char* argv[] = {"crash_sender", "--crash_directory=/tmp"};
  base::CommandLine command_line(std::size(argv), argv);
  brillo::FlagHelper::GetInstance()->set_command_line_for_testing(
      &command_line);
  CommandLineFlags flags;
  ParseCommandLine(std::size(argv), argv, &flags);
  EXPECT_EQ(flags.max_spread_time.InSeconds(), kMaxSpreadTimeInSeconds);
  EXPECT_EQ(flags.crash_directory, "/tmp");
  EXPECT_FALSE(flags.ignore_rate_limits);
  EXPECT_FALSE(flags.ignore_hold_off_time);
  EXPECT_FALSE(flags.allow_dev_sending);
  EXPECT_FALSE(flags.ignore_pause_file);
  EXPECT_FALSE(flags.test_mode);
  EXPECT_FALSE(flags.upload_old_reports);
  EXPECT_FALSE(flags.force_upload_on_test_images);
  EXPECT_FALSE(flags.consent_already_checked_by_crash_reporter);
  EXPECT_FALSE(flags.dry_run);
  // Test here because the setting of ChromeCrashLog is done during CLI parsing.
  EXPECT_STREQ(paths::ChromeCrashLog::Get(), kChromeCrashLog);
}

TEST_F(CrashSenderUtilTest, ParseCommandLine_Dev) {
  const char* argv[] = {"crash_sender", "--dev"};
  base::CommandLine command_line(std::size(argv), argv);
  brillo::FlagHelper::GetInstance()->set_command_line_for_testing(
      &command_line);
  CommandLineFlags flags;
  ParseCommandLine(std::size(argv), argv, &flags);
  EXPECT_EQ(flags.max_spread_time.InSeconds(), kMaxSpreadTimeInSeconds);
  EXPECT_TRUE(flags.crash_directory.empty());
  EXPECT_FALSE(flags.ignore_rate_limits);
  EXPECT_FALSE(flags.ignore_hold_off_time);
  EXPECT_TRUE(flags.allow_dev_sending);
  EXPECT_FALSE(flags.ignore_pause_file);
  EXPECT_FALSE(flags.test_mode);
  EXPECT_FALSE(flags.upload_old_reports);
  EXPECT_FALSE(flags.force_upload_on_test_images);
  EXPECT_FALSE(flags.consent_already_checked_by_crash_reporter);
  EXPECT_FALSE(flags.dry_run);
  // Test here because the setting of ChromeCrashLog is done during CLI parsing.
  EXPECT_STREQ(paths::ChromeCrashLog::Get(), kChromeCrashLog);
}

TEST_F(CrashSenderUtilTest, ParseCommandLine_IgnorePauseFile) {
  const char* argv[] = {"crash_sender", "--ignore_pause_file"};
  base::CommandLine command_line(std::size(argv), argv);
  brillo::FlagHelper::GetInstance()->set_command_line_for_testing(
      &command_line);
  CommandLineFlags flags;
  ParseCommandLine(std::size(argv), argv, &flags);
  EXPECT_EQ(flags.max_spread_time.InSeconds(), kMaxSpreadTimeInSeconds);
  EXPECT_TRUE(flags.crash_directory.empty());
  EXPECT_FALSE(flags.ignore_rate_limits);
  EXPECT_FALSE(flags.ignore_hold_off_time);
  EXPECT_FALSE(flags.allow_dev_sending);
  EXPECT_TRUE(flags.ignore_pause_file);
  EXPECT_FALSE(flags.test_mode);
  EXPECT_FALSE(flags.upload_old_reports);
  EXPECT_FALSE(flags.force_upload_on_test_images);
  EXPECT_FALSE(flags.consent_already_checked_by_crash_reporter);
  EXPECT_FALSE(flags.dry_run);
  // Test here because the setting of ChromeCrashLog is done during CLI parsing.
  EXPECT_STREQ(paths::ChromeCrashLog::Get(), kChromeCrashLog);
}

TEST_F(CrashSenderUtilTest, ParseCommandLine_UploadOldReports) {
  const char* argv[] = {"crash_sender", "--upload_old_reports"};
  base::CommandLine command_line(std::size(argv), argv);
  brillo::FlagHelper::GetInstance()->set_command_line_for_testing(
      &command_line);
  CommandLineFlags flags;
  ParseCommandLine(std::size(argv), argv, &flags);
  EXPECT_EQ(flags.max_spread_time.InSeconds(), kMaxSpreadTimeInSeconds);
  EXPECT_TRUE(flags.crash_directory.empty());
  EXPECT_FALSE(flags.ignore_rate_limits);
  EXPECT_FALSE(flags.ignore_hold_off_time);
  EXPECT_FALSE(flags.allow_dev_sending);
  EXPECT_FALSE(flags.ignore_pause_file);
  EXPECT_FALSE(flags.test_mode);
  EXPECT_TRUE(flags.upload_old_reports);
  EXPECT_FALSE(flags.force_upload_on_test_images);
  EXPECT_FALSE(flags.consent_already_checked_by_crash_reporter);
  EXPECT_FALSE(flags.dry_run);
  // Test here because the setting of ChromeCrashLog is done during CLI parsing.
  EXPECT_STREQ(paths::ChromeCrashLog::Get(), kChromeCrashLog);
}

TEST_F(CrashSenderUtilTest, ParseCommandLine_ForceUploadOnTestImages) {
  const char* argv[] = {"crash_sender", "--force_upload_on_test_images"};
  base::CommandLine command_line(std::size(argv), argv);
  brillo::FlagHelper::GetInstance()->set_command_line_for_testing(
      &command_line);
  CommandLineFlags flags;
  ParseCommandLine(std::size(argv), argv, &flags);
  EXPECT_EQ(flags.max_spread_time.InSeconds(), kMaxSpreadTimeInSeconds);
  EXPECT_TRUE(flags.crash_directory.empty());
  EXPECT_FALSE(flags.ignore_rate_limits);
  EXPECT_FALSE(flags.ignore_hold_off_time);
  EXPECT_FALSE(flags.allow_dev_sending);
  EXPECT_FALSE(flags.ignore_pause_file);
  EXPECT_FALSE(flags.test_mode);
  EXPECT_FALSE(flags.upload_old_reports);
  EXPECT_TRUE(flags.force_upload_on_test_images);
  EXPECT_FALSE(flags.consent_already_checked_by_crash_reporter);
  EXPECT_FALSE(flags.dry_run);
  // Test here because the setting of ChromeCrashLog is done during CLI parsing.
  EXPECT_STREQ(paths::ChromeCrashLog::Get(), kChromeCrashLog);
}

TEST_F(CrashSenderUtilDeathTest,
       ParseCommandLine_ConsentAlreadyCheckedWithEmptyDir) {
  const char* argv[] = {"crash_sender",
                        "--consent_already_checked_by_crash_reporter"};
  base::CommandLine command_line(std::size(argv), argv);
  brillo::FlagHelper::GetInstance()->set_command_line_for_testing(
      &command_line);
  CommandLineFlags flags;
  EXPECT_DEATH(ParseCommandLine(std::size(argv), argv, &flags),
               "Skipping the consent check is only valid via debugd");
}

TEST_F(CrashSenderUtilTest, ParseCommandLine_ConsentAlreadyCheckedWithDir) {
  const char* argv[] = {"crash_sender",
                        "--consent_already_checked_by_crash_reporter",
                        "--crash_directory=/tmp"};
  base::CommandLine command_line(std::size(argv), argv);
  brillo::FlagHelper::GetInstance()->set_command_line_for_testing(
      &command_line);
  CommandLineFlags flags;
  ParseCommandLine(std::size(argv), argv, &flags);
  EXPECT_EQ(flags.max_spread_time.InSeconds(), kMaxSpreadTimeInSeconds);
  EXPECT_EQ(flags.crash_directory, "/tmp");
  EXPECT_FALSE(flags.ignore_rate_limits);
  EXPECT_FALSE(flags.ignore_hold_off_time);
  EXPECT_FALSE(flags.allow_dev_sending);
  EXPECT_FALSE(flags.ignore_pause_file);
  EXPECT_FALSE(flags.test_mode);
  EXPECT_FALSE(flags.upload_old_reports);
  EXPECT_FALSE(flags.force_upload_on_test_images);
  EXPECT_TRUE(flags.consent_already_checked_by_crash_reporter);
  EXPECT_FALSE(flags.dry_run);
  // Test here because the setting of ChromeCrashLog is done during CLI parsing.
  EXPECT_STREQ(paths::ChromeCrashLog::Get(), kChromeCrashLog);
}

TEST_F(CrashSenderUtilTest, ParseCommandLine_DryRun) {
  static constexpr char kLogMessage[] = "Some sensible message";
  const char* argv[] = {"crash_sender", "--dry_run"};
  // Use ScopedLogSettingsResetter here so that dry run-specific settings can be
  // restored even if the test exits for other reasons.
  ScopedDryRunSettingsResetter scoped_log_settings_resetter;
  base::CommandLine command_line(std::size(argv), argv);
  brillo::FlagHelper::GetInstance()->set_command_line_for_testing(
      &command_line);
  CommandLineFlags flags;
  ParseCommandLine(std::size(argv), argv, &flags);
  brillo::ClearLog();
  LOG(ERROR) << kLogMessage;
  EXPECT_THAT(brillo::GetLog(),
              ContainsRegex(base::StrCat({"dryrun:.*", kLogMessage})));
  EXPECT_EQ(flags.max_spread_time.InSeconds(), kMaxSpreadTimeInSeconds);
  EXPECT_TRUE(flags.crash_directory.empty());
  EXPECT_FALSE(flags.ignore_rate_limits);
  EXPECT_FALSE(flags.ignore_hold_off_time);
  EXPECT_FALSE(flags.allow_dev_sending);
  EXPECT_FALSE(flags.ignore_pause_file);
  EXPECT_FALSE(flags.test_mode);
  EXPECT_FALSE(flags.upload_old_reports);
  EXPECT_FALSE(flags.force_upload_on_test_images);
  EXPECT_FALSE(flags.consent_already_checked_by_crash_reporter);
  EXPECT_TRUE(flags.dry_run);
  // Test here because the setting of ChromeCrashLog is done during CLI
  // parsing.
  EXPECT_STREQ(paths::ChromeCrashLog::Get(), "/dev/full");
}

TEST_F(CrashSenderUtilTest, DoesPauseFileExist) {
  EXPECT_FALSE(DoesPauseFileExist());

  ASSERT_TRUE(test_util::CreateFile(paths::Get(paths::kPauseCrashSending), ""));
  EXPECT_TRUE(DoesPauseFileExist());
}

TEST_F(CrashSenderUtilTest, GetBasePartOfCrashFile) {
  // The below are shorter than expected and shouldn't be touched
  EXPECT_EQ("foo", GetBasePartHelper("foo"));
  EXPECT_EQ("foo.1", GetBasePartHelper("foo.1"));
  EXPECT_EQ("foo.1.2", GetBasePartHelper("foo.1.2"));
  EXPECT_EQ("foo.1.2.3", GetBasePartHelper("foo.1.2.3"));

  // Parsed according to old, four-component, version
  EXPECT_EQ("foo.1.2.3", GetBasePartHelper("foo.1.2.3.4"));
  // Parsed according to new, five-component version
  EXPECT_EQ("foo.1.2.3.4", GetBasePartHelper("foo.1.2.3.4.log"));

  // Parsed according to old, four-component, version
  EXPECT_EQ("1.2.3.4", GetBasePartHelper("1.2.3.4.log.tar"));
  // Parsed according to new, five-component, version
  EXPECT_EQ("foo.1.2.3.4", GetBasePartHelper("foo.1.2.3.4.log.tar"));

  // Parsed according to old, four-component, version
  EXPECT_EQ("foo.1.2.3", GetBasePartHelper("foo.1.2.3.log.tar.gz"));
  // Parsed according to new, five-component, version
  EXPECT_EQ("foo.1.2.3.4", GetBasePartHelper("foo.1.2.3.4.log.tar.gz"));

  // Directory should be preserved.
  EXPECT_EQ("/d/1.2", GetBasePartHelper("/d/1.2"));
  EXPECT_EQ("/d/1.2.3.4", GetBasePartHelper("/d/1.2.3.4.log"));
  // Dots in directory name should not affect the function.
  EXPECT_EQ("/d.d.d.d/1.2.3.4", GetBasePartHelper("/d.d.d.d/1.2.3.4.log"));
}

TEST_F(CrashSenderUtilTest, RemoveOrphanedCrashFiles) {
  const base::FilePath crash_directory =
      paths::Get(paths::kSystemCrashDirectory);
  ASSERT_TRUE(base::CreateDirectory(crash_directory));

  const base::FilePath new_log = crash_directory.Append("0.0.0.0.0.log");
  const base::FilePath old1_log = crash_directory.Append("1.1.1.1.1.log");
  const base::FilePath old1_meta = crash_directory.Append("1.1.1.1.1.meta");
  const base::FilePath old2_log = crash_directory.Append("2.2.2.2.2.log");
  const base::FilePath old3_log = crash_directory.Append("3.3.3.3.3.log");
  const base::FilePath old4_log = crash_directory.Append("4.log");

  base::Time now = base::Time::Now();

  // new_log is new thus should not be removed.
  ASSERT_TRUE(test_util::CreateFile(new_log, ""));

  // old1_log is old but comes with the meta file thus should not be removed.
  ASSERT_TRUE(test_util::CreateFile(old1_log, ""));
  ASSERT_TRUE(test_util::CreateFile(old1_meta, ""));
  ASSERT_TRUE(test_util::TouchFileHelper(old1_log, now - base::Hours(24)));
  ASSERT_TRUE(test_util::TouchFileHelper(old1_meta, now - base::Hours(24)));

  // old2_log is old without the meta file thus should be removed.
  ASSERT_TRUE(test_util::CreateFile(old2_log, ""));
  ASSERT_TRUE(test_util::TouchFileHelper(old2_log, now - base::Hours(24)));

  // old3_log is very old without the meta file thus should be removed.
  ASSERT_TRUE(test_util::CreateFile(old3_log, ""));
  ASSERT_TRUE(test_util::TouchFileHelper(old3_log, now - base::Days(365)));

  // old4_log is misnamed, but should be removed since it's old.
  ASSERT_TRUE(test_util::CreateFile(old4_log, ""));
  ASSERT_TRUE(test_util::TouchFileHelper(old4_log, now - base::Hours(24)));

  RemoveOrphanedCrashFiles(crash_directory);

  // Check what files were removed.
  EXPECT_TRUE(base::PathExists(new_log));
  EXPECT_TRUE(base::PathExists(old1_log));
  EXPECT_TRUE(base::PathExists(old1_meta));
  EXPECT_FALSE(base::PathExists(old2_log));
  EXPECT_FALSE(base::PathExists(old3_log));
  EXPECT_FALSE(base::PathExists(old4_log));
}

TEST_F(CrashSenderUtilTest, ChooseAction) {
  ASSERT_TRUE(SetConditions(kOfficialBuild, kSignInMode, kMetricsEnabled));

  const base::FilePath crash_directory =
      paths::Get(paths::kSystemCrashDirectory);
  ASSERT_TRUE(CreateDirectory(crash_directory));
  ASSERT_TRUE(CreateTestCrashFiles(crash_directory));
  MetricsLibraryMock* raw_metrics_lib = metrics_lib_.get();

  Sender::Options options;
  Sender sender(std::move(metrics_lib_),
                std::make_unique<test_util::AdvancingClock>(), options);

  std::string reason;
  CrashInfo info;
  // The following files should be sent.
  EXPECT_CALL(*raw_metrics_lib,
              SendEnumToUMA("Platform.CrOS.CrashSenderRemoveReason", _, _))
      .Times(0);
  EXPECT_EQ(Sender::kSend, sender.ChooseAction(good_meta_, &reason, &info));
  EXPECT_EQ(Sender::kSend,
            sender.ChooseAction(recent_os_meta_, &reason, &info));
  // Verify that RemoveReason wasn't sent
  testing::Mock::VerifyAndClearExpectations(raw_metrics_lib);

  // The following file should not be sent.
  EXPECT_CALL(*raw_metrics_lib,
              SendEnumToUMA("Platform.CrOS.CrashSenderRemoveReason", _, _))
      .Times(1);
  EXPECT_EQ(Sender::kRemove,
            sender.ChooseAction(absolute_meta_, &reason, &info));
  testing::Mock::VerifyAndClearExpectations(raw_metrics_lib);

  // Basic check that the valid crash info is returned.
  std::string value;
  EXPECT_EQ(absolute_log_.value(), info.payload_file.value());
  EXPECT_EQ("log", info.payload_kind);
  EXPECT_TRUE(info.metadata.GetString("payload", &value));

  const base::FilePath processing = good_meta_.ReplaceExtension(".processing");
  // ChooseAction was successful, so it should remove the file.
  EXPECT_FALSE(base::PathExists(processing));

  // If a ".processing" file exists, the meta file shouldn't be uploaded.
  ASSERT_TRUE(test_util::CreateFile(processing, ""));

  // Following calls should be in order.
  testing::InSequence seq;
  EXPECT_CALL(
      *raw_metrics_lib,
      SendEnumToUMA("Platform.CrOS.CrashSenderRemoveReason",
                    Sender::kProcessingFileExists, Sender::kSendReasonCount));
  EXPECT_EQ(Sender::kRemove, sender.ChooseAction(good_meta_, &reason, &info));
  EXPECT_THAT(reason, HasSubstr(".processing file already exists"));
  ASSERT_TRUE(base::DeleteFile(processing));

  // The following file should be removed.
  EXPECT_CALL(
      *raw_metrics_lib,
      SendEnumToUMA("Platform.CrOS.CrashSenderRemoveReason",
                    Sender::kAlreadyUploaded, Sender::kSendReasonCount));
  EXPECT_EQ(Sender::kRemove,
            sender.ChooseAction(uploaded_meta_, &reason, &info));
  EXPECT_THAT(reason, HasSubstr("Removing already-uploaded crash"));
  EXPECT_FALSE(
      base::PathExists(uploaded_meta_.ReplaceExtension(".processing")));

  // The following files should be ignored.
  EXPECT_EQ(Sender::kIgnore,
            sender.ChooseAction(new_incomplete_meta_, &reason, &info));
  EXPECT_THAT(reason, HasSubstr("Recent incomplete metadata"));
  EXPECT_FALSE(
      base::PathExists(new_incomplete_meta_.ReplaceExtension(".processing")));

  EXPECT_EQ(Sender::kIgnore,
            sender.ChooseAction(new_empty_meta_, &reason, &info));
  EXPECT_THAT(reason, HasSubstr("Recent incomplete metadata"));
  EXPECT_FALSE(
      base::PathExists(new_empty_meta_.ReplaceExtension(".processing")));

  // Device coredump should be ignored by default.
  EXPECT_EQ(Sender::kIgnore,
            sender.ChooseAction(devcore_meta_, &reason, &info));
  EXPECT_THAT(reason, HasSubstr("Device coredump upload not allowed"));
  EXPECT_FALSE(base::PathExists(devcore_meta_.ReplaceExtension(".processing")));

  // Device coredump should be sent, if uploading is allowed.
  CreateDeviceCoredumpUploadAllowedFile();
  EXPECT_EQ(Sender::kSend, sender.ChooseAction(devcore_meta_, &reason, &info));

  // The following files should be removed.
  EXPECT_CALL(
      *raw_metrics_lib,
      SendEnumToUMA("Platform.CrOS.CrashSenderRemoveReason",
                    Sender::kPayloadUnspecified, Sender::kSendReasonCount));
  EXPECT_EQ(Sender::kRemove, sender.ChooseAction(empty_meta_, &reason, &info));
  EXPECT_THAT(reason, HasSubstr("Payload is not found"));
  EXPECT_FALSE(base::PathExists(empty_meta_.ReplaceExtension(".processing")));

  EXPECT_EQ(Sender::kIgnore,
            sender.ChooseAction(new_corrupted_meta_, &reason, &info));
  EXPECT_THAT(reason, HasSubstr("Recent incomplete metadata"));
  EXPECT_FALSE(
      base::PathExists(new_corrupted_meta_.ReplaceExtension(".processing")));

  EXPECT_CALL(
      *raw_metrics_lib,
      SendEnumToUMA("Platform.CrOS.CrashSenderRemoveReason",
                    Sender::kUnparseableMetaFile, Sender::kSendReasonCount));
  EXPECT_EQ(Sender::kRemove,
            sender.ChooseAction(old_corrupted_meta_, &reason, &info));
  EXPECT_THAT(reason, HasSubstr("Corrupted metadata"));
  EXPECT_FALSE(
      base::PathExists(old_corrupted_meta_.ReplaceExtension(".processing")));

  EXPECT_CALL(
      *raw_metrics_lib,
      SendEnumToUMA("Platform.CrOS.CrashSenderRemoveReason",
                    Sender::kPayloadNonexistent, Sender::kSendReasonCount));
  EXPECT_EQ(Sender::kRemove,
            sender.ChooseAction(nonexistent_meta_, &reason, &info));
  EXPECT_THAT(reason, HasSubstr("Missing payload"));
  EXPECT_FALSE(
      base::PathExists(nonexistent_meta_.ReplaceExtension(".processing")));

  EXPECT_CALL(
      *raw_metrics_lib,
      SendEnumToUMA("Platform.CrOS.CrashSenderRemoveReason",
                    Sender::kPayloadKindUnknown, Sender::kSendReasonCount));
  EXPECT_EQ(Sender::kRemove,
            sender.ChooseAction(unknown_meta_, &reason, &info));
  EXPECT_THAT(reason, HasSubstr("Unknown kind"));
  EXPECT_FALSE(base::PathExists(unknown_meta_.ReplaceExtension(".processing")));

  EXPECT_CALL(
      *raw_metrics_lib,
      SendEnumToUMA("Platform.CrOS.CrashSenderRemoveReason",
                    Sender::kOldIncompleteMeta, Sender::kSendReasonCount));
  EXPECT_EQ(Sender::kRemove,
            sender.ChooseAction(old_incomplete_meta_, &reason, &info));
  EXPECT_THAT(reason, HasSubstr("Removing old incomplete metadata"));
  EXPECT_FALSE(
      base::PathExists(old_incomplete_meta_.ReplaceExtension(".processing")));

  EXPECT_CALL(
      *raw_metrics_lib,
      SendEnumToUMA("Platform.CrOS.CrashSenderRemoveReason",
                    Sender::kOSVersionTooOld, Sender::kSendReasonCount));
  EXPECT_EQ(Sender::kRemove, sender.ChooseAction(old_os_meta_, &reason, &info));
  EXPECT_THAT(reason, HasSubstr("Old OS version"));
  EXPECT_FALSE(base::PathExists(old_os_meta_.ReplaceExtension(".processing")));

  EXPECT_EQ(Sender::kSend,
            sender.ChooseAction(old_os_new_lacros_meta_, &reason, &info));

  // Txt files should be sent if metrics enabled and we're using user consent.
  EXPECT_EQ(Sender::kSend, sender.ChooseAction(txt_meta_, &reason, &info));

  EXPECT_CALL(
      *raw_metrics_lib,
      SendEnumToUMA("Platform.CrOS.CrashSenderRemoveReason",
                    Sender::kLaCrosVersionTooOld, Sender::kSendReasonCount));
  EXPECT_EQ(Sender::kRemove,
            sender.ChooseAction(old_os_old_lacros_meta_, &reason, &info));
  EXPECT_THAT(reason, HasSubstr("Old LaCros version"));

  EXPECT_CALL(
      *raw_metrics_lib,
      SendEnumToUMA("Platform.CrOS.CrashSenderRemoveReason",
                    Sender::kPayloadAbsolute, Sender::kSendReasonCount));
  EXPECT_EQ(Sender::kRemove,
            sender.ChooseAction(root_payload_meta_, &reason, &info));
  EXPECT_THAT(reason, HasSubstr("payload path is absolute"));
  EXPECT_FALSE(
      base::PathExists(root_payload_meta_.ReplaceExtension(".processing")));

  EXPECT_CALL(*raw_metrics_lib,
              SendEnumToUMA("Platform.CrOS.CrashSenderRemoveReason",
                            Sender::kLargeMetaFile, Sender::kSendReasonCount));
  EXPECT_EQ(Sender::kRemove, sender.ChooseAction(large_meta_, &reason, &info));
  EXPECT_THAT(reason, HasSubstr("Metadata file is unusually large"));
  EXPECT_FALSE(base::PathExists(large_meta_.ReplaceExtension(".processing")));

  EXPECT_CALL(
      *raw_metrics_lib,
      SendEnumToUMA("Platform.CrOS.CrashSenderRemoveReason",
                    Sender::kNotOfficialImage, Sender::kSendReasonCount));
  ASSERT_TRUE(SetConditions(kUnofficialBuild, kSignInMode, kMetricsEnabled,
                            raw_metrics_lib));
  EXPECT_EQ(Sender::kRemove, sender.ChooseAction(good_meta_, &reason, &info));
  EXPECT_THAT(reason, HasSubstr("Not an official OS version"));
  EXPECT_FALSE(base::PathExists(good_meta_.ReplaceExtension(".processing")));


  // Valid crash files should be kept in the guest mode.
  ASSERT_TRUE(SetConditions(kOfficialBuild, kGuestMode, kMetricsDisabled,
                            raw_metrics_lib));
  EXPECT_EQ(Sender::kIgnore, sender.ChooseAction(good_meta_, &reason, &info));

  // Valid crash files in the system directory should be ignored if metrics are
  // disabled.
  ASSERT_TRUE(SetConditions(kOfficialBuild, kSignInMode, kMetricsDisabled,
                            raw_metrics_lib));
  EXPECT_EQ(Sender::kIgnore, sender.ChooseAction(good_meta_, &reason, &info));
  EXPECT_THAT(reason, HasSubstr("delayed for system dir"));

  // Valid crash files in the system directory should be sent if metrics are
  // enabled and we're using per-user consent.
  ASSERT_TRUE(SetConditions(kOfficialBuild, kSignInMode, kMetricsEnabled,
                            raw_metrics_lib));
  EXPECT_EQ(Sender::kSend, sender.ChooseAction(good_meta_, &reason, &info));
}

TEST_F(CrashSenderUtilTest, ChooseAction_UserDir) {
  const base::FilePath crash_directory =
      paths::Get(paths::kCryptohomeCrashDirectory).Append("fakehash");
  ASSERT_TRUE(CreateDirectory(crash_directory));
  ASSERT_TRUE(CreateTestCrashFiles(crash_directory));
  MetricsLibraryMock* raw_metrics_lib = metrics_lib_.get();

  Sender::Options options;
  Sender sender(std::move(metrics_lib_),
                std::make_unique<test_util::AdvancingClock>(), options);

  std::string reason;
  CrashInfo info;
  ASSERT_TRUE(SetConditions(kOfficialBuild, kSignInMode, kMetricsDisabled,
                            raw_metrics_lib));
  EXPECT_CALL(
      *raw_metrics_lib,
      SendEnumToUMA("Platform.CrOS.CrashSenderRemoveReason",
                    Sender::kNoMetricsConsent, Sender::kSendReasonCount));
  EXPECT_EQ(Sender::kRemove, sender.ChooseAction(good_meta_, &reason, &info));
  EXPECT_THAT(reason, HasSubstr("Crash reporting is disabled"));
  EXPECT_FALSE(base::PathExists(good_meta_.ReplaceExtension(".processing")));
}

// Test that when force_upload_on_test_images is set, we set hwtest_suite_run.
TEST_F(CrashSenderUtilTest, ChooseAction_SetsHwtestSuiteRun) {
  ASSERT_TRUE(SetConditions(kOfficialBuild, kSignInMode, kMetricsEnabled));

  const base::FilePath crash_directory =
      paths::Get(paths::kSystemCrashDirectory);
  ASSERT_TRUE(CreateDirectory(crash_directory));
  ASSERT_TRUE(CreateTestCrashFiles(crash_directory));

  Sender::Options options;
  options.force_upload_on_test_images = true;
  Sender sender(std::move(metrics_lib_),
                std::make_unique<test_util::AdvancingClock>(), options);

  std::string reason;
  CrashInfo info;
  // The file should be sent.
  EXPECT_EQ(Sender::kSend, sender.ChooseAction(good_meta_, &reason, &info));
  std::string out;
  EXPECT_EQ(info.metadata.GetString("upload_var_hwtest_suite_run", &out), true);
  EXPECT_EQ(out, "true");

  EXPECT_EQ(info.metadata.GetString("upload_var_hwtest_sender_direct", &out),
            true);
  EXPECT_EQ(out, "true");
}

// Test that when force_upload_on_test_images is unset, we don't set
// hwtest_suite_run.
TEST_F(CrashSenderUtilTest, ChooseAction_NonForceNoHwTestSuiteRun) {
  ASSERT_TRUE(SetConditions(kOfficialBuild, kSignInMode, kMetricsEnabled));

  const base::FilePath crash_directory =
      paths::Get(paths::kSystemCrashDirectory);
  ASSERT_TRUE(CreateDirectory(crash_directory));
  ASSERT_TRUE(CreateTestCrashFiles(crash_directory));

  Sender::Options options;
  Sender sender(std::move(metrics_lib_),
                std::make_unique<test_util::AdvancingClock>(), options);

  std::string reason;
  CrashInfo info;
  // The file should be sent.
  EXPECT_EQ(Sender::kSend, sender.ChooseAction(good_meta_, &reason, &info));
  std::string out;
  EXPECT_EQ(info.metadata.GetString("upload_var_hwtest_suite_run", &out),
            false);
  EXPECT_EQ(info.metadata.GetString("upload_var_hwtest_sender_direct", &out),
            false);
}

TEST_P(CrashSenderUtilDryRunParamDeathTest, ChooseActionCrash) {
  ASSERT_TRUE(SetConditions(kOfficialBuild, kSignInMode, kMetricsEnabled));

  const base::FilePath crash_directory =
      paths::Get(paths::kSystemCrashDirectory);
  ASSERT_TRUE(CreateDirectory(crash_directory));
  ASSERT_TRUE(CreateTestCrashFiles(crash_directory));

  Sender::Options options;
  options.dry_run = dry_run_;
  MockSender sender(true,   // success=true
                    "123",  // Response
                    std::move(metrics_lib_),
                    std::make_unique<test_util::AdvancingClock>(), options);

  SetMockCrashSending(true);
  sender.SetCrashDuringSendForTesting(true);

  std::string reason;
  CrashInfo info;
  EXPECT_DEATH(sender.ChooseAction(good_meta_, &reason, &info),
               "crashing as requested");

  // Normally, ChooseAction crashed so the ".processing" file should remain. But
  // under the dry run mode, ".processing" files should have never been created.
  EXPECT_THAT(base::PathExists(good_meta_.ReplaceExtension(".processing")),
              Ne(dry_run_));
}

TEST_F(CrashSenderUtilTest, ChooseActionDevMode) {
  // If we set allow_dev_sending, then the OS check will be skipped.
  ASSERT_TRUE(SetConditions(kUnofficialBuild, kSignInMode, kMetricsEnabled));

  const base::FilePath crash_directory =
      paths::Get(paths::kSystemCrashDirectory);
  ASSERT_TRUE(CreateDirectory(crash_directory));
  ASSERT_TRUE(CreateTestCrashFiles(crash_directory));

  Sender::Options options;
  options.allow_dev_sending = true;
  Sender sender(std::move(metrics_lib_),
                std::make_unique<test_util::AdvancingClock>(), options);

  std::string reason;
  CrashInfo info;

  EXPECT_EQ(Sender::kSend, sender.ChooseAction(good_meta_, &reason, &info));
  EXPECT_EQ(Sender::kSend, sender.ChooseAction(old_os_meta_, &reason, &info));
}

TEST_F(CrashSenderUtilTest, ChooseActionUploadOldReports) {
  ASSERT_TRUE(SetConditions(kOfficialBuild, kSignInMode, kMetricsEnabled));

  const base::FilePath crash_directory =
      paths::Get(paths::kSystemCrashDirectory);
  ASSERT_TRUE(CreateDirectory(crash_directory));
  ASSERT_TRUE(CreateTestCrashFiles(crash_directory));

  Sender::Options options;
  options.upload_old_reports = true;
  Sender sender(std::move(metrics_lib_),
                std::make_unique<test_util::AdvancingClock>(), options);

  std::string reason;
  CrashInfo info;

  EXPECT_EQ(Sender::kSend, sender.ChooseAction(old_os_meta_, &reason, &info));
}

TEST_F(CrashSenderUtilTest, ChooseActionDryRun) {
  // If we set dry_run, then the OS check will be skipped.
  ASSERT_TRUE(SetConditions(kUnofficialBuild, kSignInMode, kMetricsEnabled));

  const base::FilePath crash_directory =
      paths::Get(paths::kSystemCrashDirectory);
  ASSERT_TRUE(CreateDirectory(crash_directory));
  ASSERT_TRUE(CreateTestCrashFiles(crash_directory));

  Sender::Options options;
  options.dry_run = true;
  Sender sender(std::move(metrics_lib_),
                std::make_unique<test_util::AdvancingClock>(), options);

  std::string reason;
  CrashInfo info;

  EXPECT_EQ(Sender::kSend, sender.ChooseAction(good_meta_, &reason, &info));
  EXPECT_EQ(Sender::kSend, sender.ChooseAction(old_os_meta_, &reason, &info));
}

TEST_F(CrashSenderUtilTest, RemoveAndPickCrashFiles) {
  auto mock =
      std::make_unique<org::chromium::SessionManagerInterfaceProxyMock>();
  test_util::SetActiveSessions(mock.get(),
                               {{"user1", "hash1"}, {"user2", "hash2"}});
  MetricsLibraryMock* raw_metrics_lib = metrics_lib_.get();

  Sender::Options options;
  options.session_manager_proxy = mock.release();
  Sender sender(std::move(metrics_lib_),
                std::make_unique<test_util::AdvancingClock>(), options);

  ASSERT_TRUE(SetConditions(kOfficialBuild, kSignInMode, kMetricsEnabled,
                            raw_metrics_lib));

  const base::FilePath crash_directory =
      paths::Get(paths::kSystemCrashDirectory);
  ASSERT_TRUE(CreateDirectory(crash_directory));
  ASSERT_TRUE(CreateTestCrashFiles(crash_directory));

  std::vector<MetaFile> to_send;
  sender.RemoveAndPickCrashFiles(crash_directory, &to_send);

  // Check what files were removed.
  EXPECT_TRUE(base::PathExists(good_meta_));
  EXPECT_TRUE(base::PathExists(good_log_));
  EXPECT_FALSE(base::PathExists(absolute_meta_));
  EXPECT_FALSE(base::PathExists(absolute_log_));
  EXPECT_FALSE(base::PathExists(uploaded_meta_));
  EXPECT_FALSE(base::PathExists(uploaded_log_));
  EXPECT_TRUE(base::PathExists(new_incomplete_meta_));
  EXPECT_TRUE(base::PathExists(new_empty_meta_));
  EXPECT_TRUE(base::PathExists(recent_os_meta_));
  EXPECT_TRUE(base::PathExists(recent_os_log_));
  EXPECT_FALSE(base::PathExists(empty_meta_));
  EXPECT_TRUE(base::PathExists(new_corrupted_meta_));
  EXPECT_FALSE(base::PathExists(old_corrupted_meta_));
  EXPECT_FALSE(base::PathExists(nonexistent_meta_));
  EXPECT_FALSE(base::PathExists(unknown_meta_));
  EXPECT_FALSE(base::PathExists(unknown_xxx_));
  EXPECT_FALSE(base::PathExists(old_incomplete_meta_));
  EXPECT_FALSE(base::PathExists(old_os_meta_));
  EXPECT_TRUE(base::PathExists(old_os_new_lacros_meta_));
  EXPECT_FALSE(base::PathExists(old_os_old_lacros_meta_));
  EXPECT_FALSE(base::PathExists(root_payload_meta_));
  EXPECT_TRUE(base::PathExists(loop_meta_));
  // Check what files were picked for sending.
  EXPECT_EQ(5, to_send.size());
  EXPECT_EQ(good_meta_.value(), to_send[0].first.value());
  EXPECT_EQ(recent_os_meta_.value(), to_send[1].first.value());

  // Basic check that the valid crash info is returned.
  std::string value;
  EXPECT_EQ(good_log_.value(), to_send[0].second.payload_file.value());
  EXPECT_EQ("log", to_send[0].second.payload_kind);
  EXPECT_TRUE(to_send[0].second.metadata.GetString("payload", &value));

  // All crash files should be removed for an unofficial build.
  ASSERT_TRUE(CreateTestCrashFiles(crash_directory));
  ASSERT_TRUE(SetConditions(kUnofficialBuild, kSignInMode, kMetricsEnabled,
                            raw_metrics_lib));
  to_send.clear();
  sender.RemoveAndPickCrashFiles(crash_directory, &to_send);
  EXPECT_TRUE(base::IsDirectoryEmpty(crash_directory));
  EXPECT_TRUE(to_send.empty());

  // System crash files should not be removed if metrics are disabled.
  ASSERT_TRUE(CreateTestCrashFiles(crash_directory));
  ASSERT_TRUE(SetConditions(kOfficialBuild, kSignInMode, kMetricsDisabled,
                            raw_metrics_lib));
  to_send.clear();
  sender.RemoveAndPickCrashFiles(crash_directory, &to_send);
  // Directory should still contain files, since it's the *system* directory...
  EXPECT_FALSE(base::IsDirectoryEmpty(crash_directory));
  // But to_send should still be empty.
  EXPECT_TRUE(to_send.empty());

  // Valid crash files should be kept in the guest mode, thus the directory
  // won't be empty. None should be selected for sending.
  ASSERT_TRUE(CreateTestCrashFiles(crash_directory));
  ASSERT_TRUE(SetConditions(kOfficialBuild, kGuestMode, kMetricsDisabled,
                            raw_metrics_lib));
  to_send.clear();
  sender.RemoveAndPickCrashFiles(crash_directory, &to_send);
  EXPECT_FALSE(base::IsDirectoryEmpty(crash_directory));
  EXPECT_TRUE(to_send.empty());

  // devcore_meta_ should be included in to_send, if uploading of device
  // coredumps is allowed.
  ASSERT_TRUE(CreateTestCrashFiles(crash_directory));
  ASSERT_TRUE(SetConditions(kOfficialBuild, kSignInMode, kMetricsEnabled,
                            raw_metrics_lib));
  CreateDeviceCoredumpUploadAllowedFile();
  to_send.clear();
  sender.RemoveAndPickCrashFiles(crash_directory, &to_send);
  EXPECT_EQ(6, to_send.size());
  EXPECT_EQ(devcore_meta_.value(), to_send[2].first.value());
}

TEST_F(CrashSenderUtilTest, RemoveReportFiles) {
  EXPECT_CALL(*metrics_lib_,
              SendEnumToUMA("Platform.CrOS.CrashSenderRemoveReason",
                            Sender::kTotalRemoval, Sender::kSendReasonCount))
      .Times(1);

  Sender::Options options;
  Sender sender(std::move(metrics_lib_),
                std::make_unique<test_util::AdvancingClock>(), options);

  const base::FilePath crash_directory =
      paths::Get(paths::kSystemCrashDirectory);
  ASSERT_TRUE(base::CreateDirectory(crash_directory));

  const base::FilePath foo_meta = crash_directory.Append("foo.meta");
  const base::FilePath foo_log = crash_directory.Append("foo.log");
  const base::FilePath foo_dmp = crash_directory.Append("foo.dmp");
  const base::FilePath bar_log = crash_directory.Append("bar.log");

  ASSERT_TRUE(test_util::CreateFile(foo_meta, ""));
  ASSERT_TRUE(test_util::CreateFile(foo_log, ""));
  ASSERT_TRUE(test_util::CreateFile(foo_dmp, ""));
  ASSERT_TRUE(test_util::CreateFile(bar_log, ""));
  // This should remove foo.*.
  sender.RemoveReportFiles(foo_meta);
  // This should do nothing because the suffix is not ".meta".
  sender.RemoveReportFiles(bar_log);

  // Check what files were removed.
  EXPECT_FALSE(base::PathExists(foo_meta));
  EXPECT_FALSE(base::PathExists(foo_log));
  EXPECT_FALSE(base::PathExists(foo_dmp));
  EXPECT_TRUE(base::PathExists(bar_log));
}

TEST_F(CrashSenderUtilTest, RemoveReportFilesUnderDryRunMode) {
  EXPECT_CALL(*metrics_lib_,
              SendEnumToUMA("Platform.CrOS.CrashSenderRemoveReason", _, _))
      .Times(0);
  EXPECT_CALL(*metrics_lib_,
              SendCrosEventToUMA("Crash.Sender.AttemptedCrashRemoval"))
      .Times(0);
  EXPECT_CALL(*metrics_lib_,
              SendCrosEventToUMA("Crash.Sender.FailedCrashRemoval"))
      .Times(0);

  Sender::Options options;
  options.dry_run = true;
  Sender sender(std::move(metrics_lib_),
                std::make_unique<test_util::AdvancingClock>(), options);

  const base::FilePath crash_directory =
      paths::Get(paths::kSystemCrashDirectory);
  ASSERT_TRUE(base::CreateDirectory(crash_directory));
  const base::FilePath foo_meta = crash_directory.Append("foo.meta");
  ASSERT_TRUE(test_util::CreateFile(foo_meta, ""));
  // This should remove foo.* were it not under the dry run mode.
  sender.RemoveReportFiles(foo_meta);
  // The file should still exist.
  EXPECT_TRUE(base::PathExists(foo_meta));
}

TEST_F(CrashSenderUtilTest, FailRemoveReportFilesSendsMetric) {
  Sender::Options options;
  EXPECT_CALL(*metrics_lib_,
              SendEnumToUMA("Platform.CrOS.CrashSenderRemoveReason",
                            Sender::kTotalRemoval, Sender::kSendReasonCount))
      .WillOnce(Return(true));
  EXPECT_CALL(*metrics_lib_,
              SendCrosEventToUMA("Crash.Sender.AttemptedCrashRemoval"))
      .WillOnce(Return(true));
  EXPECT_CALL(*metrics_lib_,
              SendCrosEventToUMA("Crash.Sender.FailedCrashRemoval"))
      .WillOnce(Return(true));

  MockSender sender(true,   // success
                    "123",  // Response (report ID)
                    std::move(metrics_lib_),
                    std::make_unique<test_util::AdvancingClock>(), options);
  // Should return true because the channel is testimage.
  LOG(WARNING) << "Creating release track image";
  ASSERT_TRUE(test_util::CreateFile(
      paths::GetAt(paths::kEtcDirectory, paths::kLsbRelease),
      "CHROMEOS_RELEASE_TRACK=testimage-channel"));
  EXPECT_TRUE(IsTestImage());
  // Set up a crash consent file
  LOG(WARNING) << "Creating consent file";
  ASSERT_TRUE(test_util::CreateFile(
      paths::GetAt(paths::kSystemRunStateDirectory, paths::kMockConsent), ""));
  EXPECT_TRUE(util::HasMockConsent());

  const base::FilePath crash_directory =
      paths::Get(paths::kSystemCrashDirectory);
  ASSERT_FALSE(base::DirectoryExists(crash_directory));
  ASSERT_TRUE(base::CreateDirectory(crash_directory));

  const base::FilePath foo_meta = crash_directory.Append("foo.meta");
  ASSERT_TRUE(test_util::CreateFile(foo_meta, ""));
  const base::FilePath foo_log = crash_directory.Append("foo.log");
  ASSERT_TRUE(test_util::CreateFile(foo_log, ""));

  // chmod the file so RemoveReportFiles fails
  ASSERT_EQ(chmod(crash_directory.value().c_str(), 0500), 0);

  sender.RemoveReportFiles(foo_meta);

  // Clean up after ourselves
  EXPECT_EQ(chmod(crash_directory.value().c_str(), 0700), 0);
  EXPECT_TRUE(base::DeletePathRecursively(crash_directory));
}

TEST_F(CrashSenderUtilTest, GetMetaFiles) {
  const base::FilePath crash_directory =
      paths::Get(paths::kSystemCrashDirectory);
  ASSERT_TRUE(base::CreateDirectory(crash_directory));

  // Use unsorted file names, to check that GetMetaFiles() sort files by
  // timestamps, not file names.
  const base::FilePath meta_1 = crash_directory.Append("a.meta");
  const base::FilePath meta_2 = crash_directory.Append("s.meta");
  const base::FilePath meta_3 = crash_directory.Append("d.meta");
  const base::FilePath meta_4 = crash_directory.Append("f.meta");
  // This one should not appear in the result.
  const base::FilePath metal_5 = crash_directory.Append("g.metal");

  ASSERT_TRUE(test_util::CreateFile(meta_1, ""));
  ASSERT_TRUE(test_util::CreateFile(meta_2, ""));
  ASSERT_TRUE(test_util::CreateFile(meta_3, ""));
  ASSERT_TRUE(test_util::CreateFile(meta_4, ""));
  ASSERT_TRUE(test_util::CreateFile(metal_5, ""));

  // Change timestamps so that meta_1 is the newest and metal_5 is the oldest.
  base::Time now = base::Time::Now();
  ASSERT_TRUE(test_util::TouchFileHelper(meta_1, now - base::Hours(1)));
  ASSERT_TRUE(test_util::TouchFileHelper(meta_2, now - base::Hours(2)));
  ASSERT_TRUE(test_util::TouchFileHelper(meta_3, now - base::Hours(3)));
  ASSERT_TRUE(test_util::TouchFileHelper(meta_4, now - base::Hours(4)));
  ASSERT_TRUE(test_util::TouchFileHelper(metal_5, now - base::Hours(5)));

  std::vector<base::FilePath> meta_files = GetMetaFiles(crash_directory);
  ASSERT_EQ(4, meta_files.size());
  // Confirm that files are sorted in the old-to-new order.
  EXPECT_EQ(meta_4.value(), meta_files[0].value());
  EXPECT_EQ(meta_3.value(), meta_files[1].value());
  EXPECT_EQ(meta_2.value(), meta_files[2].value());
  EXPECT_EQ(meta_1.value(), meta_files[3].value());
}

TEST_F(CrashSenderUtilTest, IsTimestampNewEnough) {
  base::FilePath file;
  ASSERT_TRUE(base::CreateTemporaryFileInDir(test_dir_, &file));

  // Should be new enough as it's just created.
  ASSERT_TRUE(IsTimestampNewEnough(file));

  // Make it older than 24 hours.
  const base::Time now = base::Time::Now();
  ASSERT_TRUE(test_util::TouchFileHelper(file, now - base::Hours(25)));

  // Should be no longer new enough.
  ASSERT_FALSE(IsTimestampNewEnough(file));
}

TEST_F(CrashSenderUtilTest, IsBelowRateReachesMaxRate) {
  const int kMaxRate = 3;
  const int kMaxBytes = 50;
  const base::FilePath timestamp_dir =
      test_dir_.Append("IsBelowRateReachesMaxRate");

  EXPECT_TRUE(IsBelowRate(timestamp_dir, kMaxRate, kMaxBytes));
  RecordSendAttempt(timestamp_dir, kMaxBytes - 5);
  EXPECT_TRUE(IsBelowRate(timestamp_dir, kMaxRate, kMaxBytes));
  RecordSendAttempt(timestamp_dir, kMaxBytes - 5);
  // Exceeds max bytes; should be allowed to upload since we have not hit max
  // rate.
  EXPECT_TRUE(IsBelowRate(timestamp_dir, kMaxRate, kMaxBytes));
  RecordSendAttempt(timestamp_dir, kMaxBytes - 5);

  // Should not pass the rate + byte limit.
  EXPECT_FALSE(IsBelowRate(timestamp_dir, kMaxRate, kMaxBytes));

  // Three files should be created for tracking timestamps.
  std::vector<base::FilePath> files = GetFileNamesIn(timestamp_dir);
  ASSERT_EQ(3, files.size());

  const base::Time now = base::Time::Now();

  // Make one of them older than 24 hours.
  ASSERT_TRUE(test_util::TouchFileHelper(files[0], now - base::Hours(25)));

  // It should now pass the rate limit.
  EXPECT_TRUE(IsBelowRate(timestamp_dir, kMaxRate, kMaxBytes));
  // The old file should now be gone.
  EXPECT_TRUE(!base::PathExists(files[0]));
}

TEST_F(CrashSenderUtilTest, IsBelowRateReachesMaxBytes) {
  const int kMaxRate = 3;
  const int kMaxBytes = 100;
  const base::FilePath timestamp_dir =
      test_dir_.Append("IsBelowRateReachesMaxBytes");

  EXPECT_TRUE(IsBelowRate(timestamp_dir, kMaxRate, kMaxBytes));
  RecordSendAttempt(timestamp_dir, 50);
  EXPECT_TRUE(IsBelowRate(timestamp_dir, kMaxRate, kMaxBytes));
  RecordSendAttempt(timestamp_dir, 20);
  EXPECT_TRUE(IsBelowRate(timestamp_dir, kMaxRate, kMaxBytes));
  RecordSendAttempt(timestamp_dir, 5);
  // Exceeds max rate, but passes because it's below max bytes.
  EXPECT_TRUE(IsBelowRate(timestamp_dir, kMaxRate, kMaxBytes));
  RecordSendAttempt(timestamp_dir, 5);
  EXPECT_TRUE(IsBelowRate(timestamp_dir, kMaxRate, kMaxBytes));
  RecordSendAttempt(timestamp_dir, 20);

  // Exceeds max bytes.
  EXPECT_FALSE(IsBelowRate(timestamp_dir, kMaxRate, kMaxBytes));

  // Make one file older than 24 hours, and we should get some bandwidth
  // marked available again.
  std::vector<base::FilePath> files = GetFileNamesIn(timestamp_dir);
  ASSERT_EQ(5, files.size());
  const base::Time now = base::Time::Now();
  ASSERT_TRUE(test_util::TouchFileHelper(files[0], now - base::Hours(25)));
  EXPECT_TRUE(IsBelowRate(timestamp_dir, kMaxRate, kMaxBytes));
}

TEST_F(CrashSenderUtilTest, SortReports) {
  // Crashes from oldest to youngest will be a, b, c.
  CrashInfo crash_info_a;
  EXPECT_TRUE(base::Time::FromString("15 Nov 2018 12:45:26 GMT",
                                     &crash_info_a.last_modified));
  crash_info_a.metadata.SetString("order", "1");
  MetaFile file_a(base::FilePath("a"), std::move(crash_info_a));

  CrashInfo crash_info_b;
  EXPECT_TRUE(base::Time::FromString("7 Feb 2019 12:45:26 GMT",
                                     &crash_info_b.last_modified));
  crash_info_b.metadata.SetString("order", "2");
  MetaFile file_b(base::FilePath("b"), std::move(crash_info_b));

  CrashInfo crash_info_c;
  EXPECT_TRUE(base::Time::FromString("7 Feb 2019 12:48:26 GMT",
                                     &crash_info_c.last_modified));
  crash_info_c.metadata.SetString("order", "3");
  MetaFile file_c(base::FilePath("c"), std::move(crash_info_c));

  // Add out of order
  std::vector<MetaFile> crashes;
  crashes.emplace_back(std::move(file_c));
  crashes.emplace_back(std::move(file_b));
  crashes.emplace_back(std::move(file_a));
  SortReports(&crashes);

  ASSERT_EQ(crashes.size(), 3);

  EXPECT_EQ(crashes[0].first, base::FilePath("a"));
  std::string order_string;
  EXPECT_TRUE(crashes[0].second.metadata.GetString("order", &order_string));
  EXPECT_EQ(order_string, "1");

  EXPECT_EQ(crashes[1].first, base::FilePath("b"));
  EXPECT_TRUE(crashes[1].second.metadata.GetString("order", &order_string));
  EXPECT_EQ(order_string, "2");

  EXPECT_EQ(crashes[2].first, base::FilePath("c"));
  EXPECT_TRUE(crashes[2].second.metadata.GetString("order", &order_string));
  EXPECT_EQ(order_string, "3");
}

TEST_F(CrashSenderUtilTest, GetUserCrashDirectories) {
  auto mock =
      std::make_unique<org::chromium::SessionManagerInterfaceProxyMock>();
  test_util::SetActiveSessions(mock.get(),
                               {{"user1", "hash1"}, {"user2", "hash2"}});
  Sender::Options options;
  options.session_manager_proxy = mock.release();
  Sender sender(std::move(metrics_lib_),
                std::make_unique<test_util::AdvancingClock>(), options);

  EXPECT_THAT(
      sender.GetUserCrashDirectories(),
      UnorderedElementsAre(paths::Get("/home/user/hash1/crash"),
                           paths::Get("/home/user/hash2/crash"),
                           paths::Get("/run/daemon-store/crash/hash1"),
                           paths::Get("/run/daemon-store/crash/hash2")));
}

TEST_F(CrashSenderUtilTest, SkipConsentCheckWhenFlagIsProvided) {
  ASSERT_TRUE(SetConditions(kOfficialBuild, kSignInMode, kMetricsDisabled));

  const base::FilePath crash_directory =
      paths::Get(paths::kSystemCrashDirectory);
  ASSERT_TRUE(CreateDirectory(crash_directory));
  ASSERT_TRUE(CreateTestCrashFiles(crash_directory));

  Sender::Options options;
  options.consent_already_checked_by_crash_reporter = true;
  Sender sender(std::move(metrics_lib_),
                std::make_unique<test_util::AdvancingClock>(), options);

  std::string reason;
  CrashInfo info;

  EXPECT_EQ(Sender::kSend, sender.ChooseAction(loop_meta_, &reason, &info));
}

TEST_F(CrashSenderUtilTest, DoNotSkipConsentCheckWithoutCrashLoopMeta) {
  ASSERT_TRUE(SetConditions(kOfficialBuild, kSignInMode, kMetricsDisabled));

  const base::FilePath crash_directory =
      paths::Get(paths::kSystemCrashDirectory);
  ASSERT_TRUE(CreateDirectory(crash_directory));
  ASSERT_TRUE(CreateTestCrashFiles(crash_directory));

  Sender::Options options;
  options.consent_already_checked_by_crash_reporter = true;
  Sender sender(std::move(metrics_lib_),
                std::make_unique<test_util::AdvancingClock>(), options);

  std::string reason;
  CrashInfo info;

  // Ignore crashes without consent in the system directory in case a
  // consenting user later logs back in.
  EXPECT_EQ(Sender::kIgnore, sender.ChooseAction(good_meta_, &reason, &info));
}

enum MissingFile {
  kNone,
  kPayloadFile,
  kLogFile,
  kTextFile,
  kBinFile,
};

class CreateCrashFormDataTest
    : public CrashSenderUtilTest,
      public ::testing::WithParamInterface<std::tuple<MissingFile>> {
 protected:
  void SetUp() override {
    std::tie(missing_file_) = GetParam();
    CrashSenderUtilTest::SetUp();
  }
  MissingFile missing_file_;
};

TEST_P(CreateCrashFormDataTest, TestCreateCrashFormData) {
  const base::FilePath system_dir = paths::Get(paths::kSystemCrashDirectory);
  ASSERT_TRUE(base::CreateDirectory(system_dir));

  const base::FilePath payload_file("0.0.0.0.0.payload");
  const std::string payload_contents = "foobar_payload";
  if (missing_file_ != kPayloadFile) {
    ASSERT_TRUE(test_util::CreateFile(system_dir.Append(payload_file),
                                      payload_contents));
  }

  const base::FilePath log_file("0.0.0.0.0.log");
  const std::string log_contents = "foobar_log";
  if (missing_file_ != kLogFile) {
    ASSERT_TRUE(
        test_util::CreateFile(system_dir.Append(log_file), log_contents));
  }

  const base::FilePath text_var_file("data.txt");
  const std::string text_var_contents = "upload_text_contents";
  if (missing_file_ != kTextFile) {
    ASSERT_TRUE(test_util::CreateFile(system_dir.Append(text_var_file),
                                      text_var_contents));
  }

  const base::FilePath file_var_file("data.bin");
  const std::string file_var_contents = "upload_file_contents";
  if (missing_file_ != kBinFile) {
    ASSERT_TRUE(test_util::CreateFile(system_dir.Append(file_var_file),
                                      file_var_contents));
  }

  brillo::KeyValueStore metadata;
  metadata.SetString("exec_name", "fake_exec_name");
  metadata.SetString("ver", "fake_chromeos_ver");
  metadata.SetString("upload_var_prod", "fake_product");
  metadata.SetString("upload_var_ver", "fake_version");
  metadata.SetString("sig", "fake_sig");
  metadata.SetString("upload_var_guid", "SHOULD_NOT_BE_USED");
  metadata.SetString("upload_var_foovar", "bar");
  metadata.SetString("upload_text_footext", text_var_file.value());
  metadata.SetString("upload_file_log", log_file.value());
  metadata.SetString("upload_file_foofile", file_var_file.value());
  metadata.SetString("error_type", "fake_error");

  CrashDetails details = {
      .meta_file = base::FilePath(system_dir).Append("0.0.0.0.0.meta"),
      .payload_file = payload_file,
      .payload_kind = "fake_payload",
      .client_id = kFakeClientId,
      .metadata = metadata,
  };

  Sender::Options options;
  options.form_data_boundary = "boundary";

  Sender sender(nullptr, std::make_unique<test_util::AdvancingClock>(),
                options);

  std::unique_ptr<brillo::http::FormData> form_data =
      sender.CreateCrashFormData(details, nullptr);
  if (missing_file_ == kPayloadFile) {
    EXPECT_EQ(form_data, nullptr);
    return;
  }

  brillo::StreamPtr stream = form_data->ExtractDataStream();
  std::vector<uint8_t> data(stream->GetSize());
  ASSERT_TRUE(stream->ReadAllBlocking(data.data(), data.size(), nullptr));

  std::string expected_data = base::StrCat(
      {"--boundary\r\n"
       "Content-Disposition: form-data; name=\"exec_name\"\r\n"
       "\r\n"
       "fake_exec_name\r\n"
       "--boundary\r\n"
       "Content-Disposition: form-data; name=\"board\"\r\n"
       "\r\n"
       "undefined\r\n"
       "--boundary\r\n"
       "Content-Disposition: form-data; name=\"hwclass\"\r\n"
       "\r\n"
       "undefined\r\n"
       "--boundary\r\n"
       "Content-Disposition: form-data; name=\"prod\"\r\n"
       "\r\n"
       "fake_product\r\n"
       "--boundary\r\n"
       "Content-Disposition: form-data; name=\"ver\"\r\n"
       "\r\n"
       "fake_version\r\n"
       "--boundary\r\n"
       "Content-Disposition: form-data; name=\"sig\"\r\n"
       "\r\n"
       "fake_sig\r\n"
       "--boundary\r\n"
       "Content-Disposition: form-data; name=\"sig2\"\r\n"
       "\r\n"
       "fake_sig\r\n"
       "--boundary\r\n"
       "Content-Disposition: form-data; name=\"upload_file_fake_payload\"; "
       "filename=\"0.0.0.0.0.payload\"\r\n"
       "Content-Transfer-Encoding: binary\r\n"
       "\r\n"
       "foobar_payload\r\n",
       missing_file_ == kTextFile
           ? ""
           : "--boundary\r\n"
             "Content-Disposition: form-data; name=\"footext\"\r\n"
             "\r\n"
             "upload_text_contents\r\n",
       "--boundary\r\n"
       "Content-Disposition: form-data; name=\"foovar\"\r\n"
       "\r\n"
       "bar\r\n",
       missing_file_ == kBinFile
           ? ""
           : "--boundary\r\n"
             "Content-Disposition: form-data; name=\"foofile\"; "
             "filename=\"data.bin\"\r\n"
             "Content-Transfer-Encoding: binary\r\n"
             "\r\n"
             "upload_file_contents\r\n",
       missing_file_ == kLogFile
           ? ""
           : "--boundary\r\n"
             "Content-Disposition: form-data; name=\"log\"; "
             "filename=\"0.0.0.0.0.log\"\r\n"
             "Content-Transfer-Encoding: binary\r\n"
             "\r\n"
             "foobar_log\r\n",
       "--boundary\r\n"
       "Content-Disposition: form-data; name=\"boot_mode\"\r\n"
       "\r\n"
       "missing-crossystem\r\n"
       "--boundary\r\n"
       "Content-Disposition: form-data; name=\"error_type\"\r\n"
       "\r\n"
       "fake_error\r\n"
       "--boundary\r\n"
       "Content-Disposition: form-data; name=\"guid\"\r\n"
       "\r\n"
       "00112233445566778899aabbccddeeff\r\n"
       "--boundary--\r\n"});

  EXPECT_EQ(expected_data, std::string(data.begin(), data.end()));
}

INSTANTIATE_TEST_SUITE_P(
    CreateCrashFormDataInstantiation,
    CreateCrashFormDataTest,
    testing::Combine(
        testing::Values(kNone, kPayloadFile, kLogFile, kTextFile, kBinFile)));

class CrashSenderSendCrashesTest : public CrashSenderUtilTest,
                                   public ::testing::WithParamInterface<
                                       std::tuple<bool, int, base::TimeDelta>> {
 protected:
  // Capture cout. Reset cout to normal after the instance is destructed.
  class ScopedCoutCapture {
   public:
    ScopedCoutCapture() {
      cout_buf_ = std::cout.rdbuf();
      std::cout.rdbuf(buffer_.rdbuf());
    }

    ~ScopedCoutCapture() { std::cout.rdbuf(cout_buf_); }

    ScopedCoutCapture(const ScopedCoutCapture&) = delete;
    ScopedCoutCapture(ScopedCoutCapture&&) = delete;
    ScopedCoutCapture& operator=(const ScopedCoutCapture&) = delete;
    ScopedCoutCapture& operator=(ScopedCoutCapture&&) = delete;

    // Get the captured string.
    std::string GetString() { return buffer_.str(); }

   private:
    std::streambuf* cout_buf_;
    std::stringstream buffer_;
  };

  void SetUp() override {
    std::tie(dry_run_, max_crash_rate_, max_spread_time_) = GetParam();
    CrashSenderUtilTest::SetUp();
  }

  bool dry_run_;
  int max_crash_rate_;
  base::TimeDelta max_spread_time_;
};

TEST_P(CrashSenderSendCrashesTest, SendCrashes) {
  // Set up the mock session manager client.
  auto mock =
      std::make_unique<org::chromium::SessionManagerInterfaceProxyMock>();
  test_util::SetActiveSessions(mock.get(), {{"user", "hash"}});
  std::vector<MetaFile> crashes_to_send;

  // Establish the client ID.
  ASSERT_TRUE(CreateClientIdFile());

  // Create the system crash directory, and crash files in it.
  const base::FilePath system_dir = paths::Get(paths::kSystemCrashDirectory);
  ASSERT_TRUE(base::CreateDirectory(system_dir));
  const base::FilePath system_meta_file = system_dir.Append("0.0.0.0.0.meta");
  const base::FilePath system_log = system_dir.Append("0.0.0.0.0.log");
  const base::FilePath system_processing =
      system_dir.Append("0.0.0.0.0.processing");
  static constexpr char system_meta[] =
      "upload_var_collector=kernel\n"
      "payload=0.0.0.0.0.log\n"
      "exec_name=exec_foo\n"
      "fake_report_id=123\n"
      "upload_var_prod=foo\n"
      "done=1\n"
      "upload_var_reportTimeMillis=1000000\n";
  ASSERT_TRUE(test_util::CreateFile(system_meta_file, system_meta));
  ASSERT_TRUE(test_util::CreateFile(system_log, ""));
  CrashInfo system_info;
  EXPECT_TRUE(system_info.metadata.LoadFromString(system_meta));
  system_info.payload_file = system_log;
  system_info.payload_kind = "log";
  EXPECT_TRUE(base::Time::FromString("25 Apr 2018 1:23:44 GMT",
                                     &system_info.last_modified));
  crashes_to_send.emplace_back(system_meta_file, std::move(system_info));

  // Create a user crash directory, and crash files in it.
  const base::FilePath user_dir = paths::Get("/home/user/hash/crash");
  ASSERT_TRUE(base::CreateDirectory(user_dir));
  const base::FilePath user_meta_file = user_dir.Append("0.0.0.0.0.meta");
  const base::FilePath user_log = user_dir.Append("0.0.0.0.0.log");
  const base::FilePath user_processing =
      user_dir.Append("0.0.0.0.0.processing");
  static constexpr char user_meta[] =
      "upload_var_collector=ec\n"
      "payload=0.0.0.0.0.log\n"
      "exec_name=exec_bar\n"
      "fake_report_id=456\n"
      "upload_var_prod=bar\n"
      "done=1\n"
      "upload_var_reportTimeMillis=2000000\n";
  ASSERT_TRUE(test_util::CreateFile(user_meta_file, user_meta));
  ASSERT_TRUE(test_util::CreateFile(user_log, ""));
  CrashInfo user_info;
  EXPECT_TRUE(user_info.metadata.LoadFromString(user_meta));
  user_info.payload_file = user_log;
  user_info.payload_kind = "log";
  EXPECT_TRUE(base::Time::FromString("25 Apr 2018 1:24:01 GMT",
                                     &user_info.last_modified));
  crashes_to_send.emplace_back(user_meta_file, std::move(user_info));

  // Create another user crash in "user". This will be skipped since the max
  // crash rate will be set to 2.
  const base::FilePath user_meta_file2 = user_dir.Append("1.1.1.1.1.meta");
  const base::FilePath user_log2 = user_dir.Append("1.1.1.1.1.log");
  static constexpr char user_meta2[] =
      "upload_var_collector=collector_baz\n"
      "payload=1.1.1.1.1.log\n"
      "exec_name=exec_baz\n"
      "fake_report_id=789\n"
      "upload_var_prod=baz\n"
      "done=1\n";
  ASSERT_TRUE(test_util::CreateFile(user_meta_file2, user_meta2));
  ASSERT_TRUE(test_util::CreateFile(user_log2, ""));
  CrashInfo user_info2;
  EXPECT_TRUE(user_info2.metadata.LoadFromString(user_meta2));
  user_info2.payload_file = user_log2;
  user_info2.payload_kind = "log";
  EXPECT_TRUE(base::Time::FromString("25 Apr 2018 1:24:05 GMT",
                                     &user_info2.last_modified));
  crashes_to_send.emplace_back(user_meta_file2, std::move(user_info2));

  // Set up the conditions to emulate a device in guest mode; metrics are
  // disabled in guest mode.
  ASSERT_TRUE(SetConditions(kOfficialBuild, kGuestMode, kMetricsDisabled));
  // Keep the raw pointer, that's needed to exit from guest mode later.
  MetricsLibraryMock* raw_metrics_lib = metrics_lib_.get();

  // Set up the crash sender so that it succeeds.
  SetMockCrashSending(true);

  // Set up the sender.
  std::vector<base::TimeDelta> sleep_times;
  Sender::Options options;
  options.session_manager_proxy = mock.release();
  options.max_crash_rate = max_crash_rate_;
  // Setting max_crash_bytes to 0 will limit to the uploader to
  // max_crash_rate.
  options.max_crash_bytes = 0;
  options.sleep_function = base::BindRepeating(&FakeSleep, &sleep_times);
  options.always_write_uploads_log = true;
  options.hold_off_time = base::TimeDelta();
  options.max_spread_time = max_spread_time_;
  options.dry_run = dry_run_;
  MockSender sender(true /*success*/,
                    "123",  // upload_id
                    std::move(metrics_lib_),
                    std::make_unique<test_util::AdvancingClock>(), options);

  // Send crashes.
  EXPECT_CALL(
      *raw_metrics_lib,
      SendEnumToUMA("Platform.CrOS.CrashSenderRemoveReason",
                    Sender::kFinishedUploading, Sender::kSendReasonCount))
      .Times(0);

  sender.SendCrashes(crashes_to_send);
  testing::Mock::VerifyAndClearExpectations(raw_metrics_lib);

  // We shouldn't be processing any crashes still.
  EXPECT_FALSE(base::PathExists(system_processing));
  EXPECT_FALSE(base::PathExists(user_processing));

  // The Chrome uploads.log file shouldn't exist because we had nothing to
  // upload, but we will have slept once until we determined we shouldn't be
  // doing uploads.
  EXPECT_FALSE(base::PathExists(paths::Get(paths::ChromeCrashLog::Get())));
  EXPECT_EQ(1, sleep_times.size());
  sleep_times.clear();

  // Exit from guest mode/re-enable metrics, and send crashes again.
  LOG(INFO) << "Reenabling metrics to send crashes again";
  raw_metrics_lib->set_guest_mode(false);
  raw_metrics_lib->set_metrics_enabled(true);

  // expected UMA sending count.
  // max_crash_rate_ times because there are max_crash_rate_ valid crashes to
  // send.
  const int expected_uma_send_count = dry_run_ ? 0 : max_crash_rate_;
  EXPECT_CALL(
      *raw_metrics_lib,
      SendEnumToUMA("Platform.CrOS.CrashSenderRemoveReason",
                    Sender::kFinishedUploading, Sender::kSendReasonCount))
      .Times(expected_uma_send_count);
  EXPECT_CALL(*raw_metrics_lib,
              SendEnumToUMA("Platform.CrOS.CrashSenderRemoveReason",
                            Sender::kTotalRemoval, Sender::kSendReasonCount))
      .Times(expected_uma_send_count);

  // uploads.log content
  std::string contents;
  if (dry_run_) {
    ScopedCoutCapture cout_capture;
    sender.SendCrashes(crashes_to_send);
    contents = cout_capture.GetString();
  } else {
    sender.SendCrashes(crashes_to_send);
    if (max_crash_rate_ > 0) {
      ASSERT_TRUE(base::ReadFileToString(
          paths::Get(paths::ChromeCrashLog::Get()), &contents));
    } else {
      // No log file, contents remain empty.
      EXPECT_FALSE(base::PathExists(paths::Get(paths::ChromeCrashLog::Get())));
    }
  }

  // We shouldn't be processing any crashes still.
  EXPECT_FALSE(base::PathExists(system_processing));
  EXPECT_FALSE(base::PathExists(user_processing));

  // Examine the upload log from crash_sender.
  std::vector<std::optional<base::Value>> rows =
      ParseChromeUploadsLog(contents);

  const char* expected_upload_id;
  int expected_sleep_times;
  if (dry_run_) {
    // No rate limiting in dry run mode.
    ASSERT_EQ(3, rows.size());
    expected_upload_id = "";
    // Under the dry run mode, spread time should be always zero. Given that
    // hold off time is zero, sleep time should always be zero.
    for (const auto& sleep_time : sleep_times) {
      EXPECT_EQ(sleep_time, base::TimeDelta());
    }
    expected_sleep_times = 3;
  } else {
    // Should only contain max_crash_rate results, since max_crash_rate is set
    // to max_crash_rate_. FakeSleep should be called max_crash_rate_ + 1 times
    // since we sleep before we check the crash rate.
    ASSERT_EQ(max_crash_rate_, rows.size());
    expected_upload_id = "123";
    // When it's not under the dry run mode, spread time should be always
    // between 0 and max_spread_time_. Given that hold off time is zero, sleep
    // time should always be in the same range.
    for (const auto& sleep_time : sleep_times) {
      EXPECT_THAT(sleep_time,
                  AllOf(Ge(base::TimeDelta()), Le(max_spread_time_)));
    }
    expected_sleep_times = max_crash_rate_ + 1;
  }
  EXPECT_EQ(expected_sleep_times, sleep_times.size());

  // Each line of the uploads.log file is "{"upload_time":<value>,"upload_id":
  // <value>,"local_id":<value>,"capture_time":<value>,"state":<value>,"source":
  // <value>}".
  if (max_crash_rate_ >= 1 || dry_run_) {
    // The first run should be for the meta file in the system directory.
    std::optional<base::Value> row = std::move(rows[0]);
    ASSERT_TRUE(row.has_value() && row->is_dict());
    auto dict = std::move(row->GetDict());
    ASSERT_EQ(8, dict.size());
    EXPECT_TRUE(dict.Find("upload_time"));
    EXPECT_THAT(dict.FindString("upload_id"), Pointee(Eq(expected_upload_id)));
    EXPECT_THAT(dict.FindString("local_id"), Pointee(Eq("foo")));
    EXPECT_THAT(dict.FindString("capture_time"), Pointee(Eq("1000")));
    EXPECT_EQ(3, dict.FindInt("state"));
    EXPECT_THAT(dict.FindString("source"), Pointee(Eq("exec_foo")));
    EXPECT_THAT(dict.FindString("fatal_crash_type"), Pointee(Eq("kernel")));
    EXPECT_THAT(dict.FindString("path_hash"),
                Pointee(Eq(base::MD5String(system_meta_file.value()))));
  }

  if (max_crash_rate_ >= 2 || dry_run_) {
    // The second run should be for the meta file in the "user" directory.
    std::optional<base::Value> row = std::move(rows[1]);
    ASSERT_TRUE(row.has_value() && row->is_dict());
    auto dict = std::move(row->GetDict());
    ASSERT_EQ(8, dict.size());
    EXPECT_TRUE(dict.Find("upload_time"));
    EXPECT_THAT(
        dict.FindString("upload_id"),
        Pointee(Eq(expected_upload_id)));  // This is the value we set before
    EXPECT_THAT(dict.FindString("local_id"), Pointee(Eq("bar")));
    EXPECT_THAT(dict.FindString("capture_time"), Pointee(Eq("2000")));
    EXPECT_EQ(3, dict.FindInt("state"));
    EXPECT_THAT(dict.FindString("source"), Pointee(Eq("REDACTED")));
    EXPECT_THAT(dict.FindString("fatal_crash_type"), Pointee(Eq("ec")));
    EXPECT_THAT(dict.FindString("path_hash"),
                Pointee(Eq(base::MD5String(user_meta_file.value()))));
  }

  // We don't have a test with max_crash_rate_ >= 3. However, had there been
  // one, this if-block should only take effect when max_crash_rate_ >= 3.
  if (max_crash_rate_ >= 3 || dry_run_) {
    std::optional<base::Value> row = std::move(rows[2]);
    ASSERT_TRUE(row.has_value() && row->is_dict());
    auto dict = std::move(row->GetDict());
    ASSERT_EQ(6, dict.size());
    EXPECT_TRUE(dict.Find("upload_time"));
    EXPECT_THAT(dict.FindString("upload_id"),
                Pointee(Eq("")));  // This is empty
    EXPECT_THAT(dict.FindString("local_id"), Pointee(Eq("baz")));
    EXPECT_FALSE(dict.Find("capture_time"));
    EXPECT_EQ(3, dict.FindInt("state"));
    EXPECT_THAT(dict.FindString("source"), Pointee(Eq("REDACTED")));
    EXPECT_THAT(dict.FindString("path_hash"),
                Pointee(Eq(base::MD5String(user_meta_file2.value()))));
  }

  // The crash files should be kept in dry run mode and removed otherwise.
  EXPECT_THAT(base::PathExists(system_meta_file),
              Eq(dry_run_ || max_crash_rate_ < 1));
  EXPECT_THAT(base::PathExists(system_log),
              Eq(dry_run_ || max_crash_rate_ < 1));
  EXPECT_THAT(base::PathExists(user_meta_file),
              Eq(dry_run_ || max_crash_rate_ < 2));
  EXPECT_THAT(base::PathExists(user_log), Eq(dry_run_ || max_crash_rate_ < 2));

  // The following should be kept since the crash report was not uploaded.
  EXPECT_TRUE(base::PathExists(user_meta_file2));
  EXPECT_TRUE(base::PathExists(user_log2));
}

// Notes on the combination of parameters:
//
// When max_spread_time=0:
// - dry_run=true, max_crash_rate=0 is essential because as long as additional
//   files (max_crash_rate > 1) are allowed to be uploaded, dry run mode won't
//   consume the allowance, thus IsBelowRate always returns true. Therefore,
//   dry_run=true, max_crash_rate=1,2 won't be able to reveal a (broken) dry run
//   mode that depends on rate limiting.
// - dry_run=true, max_crash_rate=1,2 ensures dry run mode works correctly under
//   normal circumstances, i.e., max_crash_rate>0.
// - dry_run=false, max_crash_rate=0,1,2 ensures the correct order of upload
//   (system first, then user).
//
// When max_spread_time=5:
// - dry_run=true, max_crash_rate=0,1,2 ensures that crash_sender under the dry
//   run mode ignores max_spread_time.
// - dry_run=false, max_crash_rate=0,1,2 ensures that crash_sender not under the
//   dry run mode respects max_spread_time.
INSTANTIATE_TEST_SUITE_P(
    CrashSenderSendCrashesInstantiation,
    CrashSenderSendCrashesTest,
    testing::Combine(
        /*dry_run=*/testing::Bool(),
        /*max_crash_rate=*/
        testing::Values(0,   // No upload
                        1,   // Upload the system crash only
                        2),  // upload the user crash only
        /*max_spread_time=*/
        testing::Values(base::TimeDelta(), base::Seconds(5))),
    [](const ::testing::TestParamInfo<CrashSenderSendCrashesTest::ParamType>&
           info) {
      std::ostringstream name;
      name << "dry_run_" << std::get<0>(info.param) << "_max_crash_rate_"
           << std::get<1>(info.param) << "_max_spread_time_"
           << std::get<2>(info.param).InSeconds();
      return name.str();
    });

TEST_F(CrashSenderUtilTest, SendCrashes_DontSendUnderDryRunMode) {
  // Set up the mock session manager client.
  auto mock =
      std::make_unique<org::chromium::SessionManagerInterfaceProxyMock>();
  test_util::SetActiveSessions(mock.get(), {{"user", "hash"}});

  // Establish the client ID.
  ASSERT_TRUE(CreateClientIdFile());

  // Create the system crash directory, and crash files in it.
  const base::FilePath crash_directory =
      paths::Get(paths::kSystemCrashDirectory);
  ASSERT_TRUE(CreateDirectory(crash_directory));
  ASSERT_TRUE(CreateTestCrashFiles(crash_directory));

  // Set up the crash sender so that it succeeds.
  SetMockCrashSending(true);

  // No crash sender removal reason UMA counts.
  EXPECT_CALL(*metrics_lib_,
              SendEnumToUMA("Platform.CrOS.CrashSenderRemoveReason", _, _))
      .Times(0);

  // Set up the sender.
  std::vector<base::TimeDelta> sleep_times;
  Sender::Options options;
  options.session_manager_proxy = mock.release();
  options.max_crash_rate = 2;
  // Setting max_crash_bytes to 0 will limit to the uploader to
  // max_crash_rate.
  options.max_crash_bytes = 0;
  options.sleep_function = base::BindRepeating(&FakeSleep, &sleep_times);
  options.always_write_uploads_log = true;
  options.dry_run = true;
  MockSender sender(true /*success*/,
                    "123",  // upload_id
                    std::move(metrics_lib_),
                    std::make_unique<test_util::AdvancingClock>(), options);
  std::vector<MetaFile> crashes_to_send;
  sender.RemoveAndPickCrashFiles(crash_directory, &crashes_to_send);
  ASSERT_FALSE(crashes_to_send.empty());  // ensure at least one crash to send
  // Nothing should be sent
  EXPECT_CALL(sender, GetTransport()).Times(0);

  sender.SendCrashes(crashes_to_send);
}

TEST_F(CrashSenderUtilTest, SendCrashes_TooManyRequests) {
  // Set up the mock session manager client.
  auto mock =
      std::make_unique<org::chromium::SessionManagerInterfaceProxyMock>();
  test_util::SetActiveSessions(mock.get(), {{"user", "hash"}});
  std::vector<MetaFile> crashes_to_send;

  // Establish the client ID.
  ASSERT_TRUE(CreateClientIdFile());

  // Create a user crash directory, and crash files in it.
  const base::FilePath user_dir = paths::Get("/home/user/hash/crash");
  ASSERT_TRUE(base::CreateDirectory(user_dir));
  const base::FilePath user_meta_file = user_dir.Append("0.0.0.0.0.meta");
  const base::FilePath user_log = user_dir.Append("0.0.0.0.0.log");
  const base::FilePath user_processing =
      user_dir.Append("0.0.0.0.0.processing");
  const char user_meta[] =
      "payload=0.0.0.0.0.log\n"
      "exec_name=exec_bar\n"
      "fake_report_id=456\n"
      "upload_var_prod=bar\n"
      "done=1\n"
      "upload_var_reportTimeMillis=2000000\n";
  ASSERT_TRUE(test_util::CreateFile(user_meta_file, user_meta));
  ASSERT_TRUE(test_util::CreateFile(user_log, ""));
  CrashInfo user_info;
  EXPECT_TRUE(user_info.metadata.LoadFromString(user_meta));
  user_info.payload_file = user_log;
  user_info.payload_kind = "log";
  EXPECT_TRUE(base::Time::FromString("25 Apr 2018 1:24:01 GMT",
                                     &user_info.last_modified));
  crashes_to_send.emplace_back(user_meta_file, std::move(user_info));

  // Set up the conditions to emulate a device with metrics enabled.
  ASSERT_TRUE(SetConditions(kOfficialBuild, kSignInMode, kMetricsEnabled));
  // Keep the raw pointer, that's needed to exit from guest mode later.
  MetricsLibraryMock* raw_metrics_lib = metrics_lib_.get();

  // Set up the crash sender so that it succeeds.
  SetMockCrashSending(true);

  // Set up the sender.
  std::vector<base::TimeDelta> sleep_times;
  Sender::Options options;
  options.session_manager_proxy = mock.release();
  options.max_crash_rate = 2;
  // Setting max_crash_bytes to 0 will limit to the uploader to
  // max_crash_rate.
  options.max_crash_bytes = 0;
  options.sleep_function = base::BindRepeating(&FakeSleep, &sleep_times);
  options.always_write_uploads_log = true;
  MockSender sender(false,                // success=false
                    "Too Many Requests",  // Response
                    std::move(metrics_lib_),
                    std::make_unique<test_util::AdvancingClock>(), options);

  // Send crashes.
  EXPECT_CALL(*raw_metrics_lib,
              SendCrosEventToUMA("Crash.Sender.AttemptedCrashRemoval"))
      .WillOnce(Return(true));
  EXPECT_CALL(*raw_metrics_lib,
              SendCrosEventToUMA("Crash.Sender.FailedCrashRemoval"))
      .Times(0);  // We don't expect it to record failure
  EXPECT_CALL(*raw_metrics_lib,
              SendEnumToUMA("Platform.CrOS.CrashSenderRemoveReason",
                            Sender::kTotalRemoval, Sender::kSendReasonCount))
      .Times(1);  // Record as if we did all of the uploads
  EXPECT_CALL(*raw_metrics_lib,
              SendEnumToUMA("Platform.CrOS.CrashSenderRemoveReason",
                            Sender::kTooManyRequests, Sender::kSendReasonCount))
      .Times(1);  // We should be removing the Crash after being throttled

  sender.SendCrashes(crashes_to_send);

  // We shouldn't be processing any crashes still.
  EXPECT_FALSE(base::PathExists(user_processing));
}

TEST_F(CrashSenderUtilTest, SendCrashes_DroppedDueToThrottling) {
  // Set up the mock session manager client.
  auto mock =
      std::make_unique<org::chromium::SessionManagerInterfaceProxyMock>();
  test_util::SetActiveSessions(mock.get(), {{"user", "hash"}});
  std::vector<MetaFile> crashes_to_send;

  // Establish the client ID.
  ASSERT_TRUE(CreateClientIdFile());

  // Create a user crash directory, and crash files in it.
  const base::FilePath user_dir = paths::Get("/home/user/hash/crash");
  ASSERT_TRUE(base::CreateDirectory(user_dir));
  const base::FilePath user_meta_file = user_dir.Append("0.0.0.0.0.meta");
  const base::FilePath user_log = user_dir.Append("0.0.0.0.0.log");
  const base::FilePath user_processing =
      user_dir.Append("0.0.0.0.0.processing");
  const char user_meta[] =
      "payload=0.0.0.0.0.log\n"
      "exec_name=exec_bar\n"
      "fake_report_id=456\n"
      "upload_var_prod=bar\n"
      "done=1\n"
      "upload_var_reportTimeMillis=2000000\n";
  ASSERT_TRUE(test_util::CreateFile(user_meta_file, user_meta));
  ASSERT_TRUE(test_util::CreateFile(user_log, ""));
  CrashInfo user_info;
  EXPECT_TRUE(user_info.metadata.LoadFromString(user_meta));
  user_info.payload_file = user_log;
  user_info.payload_kind = "log";
  EXPECT_TRUE(base::Time::FromString("25 Apr 2018 1:24:01 GMT",
                                     &user_info.last_modified));
  crashes_to_send.emplace_back(user_meta_file, std::move(user_info));

  // Set up the conditions to emulate a device with metrics enabled.
  ASSERT_TRUE(SetConditions(kOfficialBuild, kSignInMode, kMetricsEnabled));
  // Keep the raw pointer, that's needed to exit from guest mode later.
  MetricsLibraryMock* raw_metrics_lib = metrics_lib_.get();

  // Set up the crash sender so that it succeeds.
  SetMockCrashSending(true);

  // Set up the sender.
  std::vector<base::TimeDelta> sleep_times;
  Sender::Options options;
  options.session_manager_proxy = mock.release();
  options.max_crash_rate = 2;
  // Setting max_crash_bytes to 0 will limit to the uploader to
  // max_crash_rate.
  options.max_crash_bytes = 0;
  options.sleep_function = base::BindRepeating(&FakeSleep, &sleep_times);
  options.always_write_uploads_log = true;
  MockSender sender(true,                // success=false
                    "0000000000000001",  // Response
                    std::move(metrics_lib_),
                    std::make_unique<test_util::AdvancingClock>(), options);

  // Send crashes.
  EXPECT_CALL(
      *raw_metrics_lib,
      SendEnumToUMA("Platform.CrOS.CrashSenderRemoveReason",
                    Sender::kFinishedUploading, Sender::kSendReasonCount))
      .Times(1);
  EXPECT_CALL(*raw_metrics_lib,
              SendEnumToUMA("Platform.CrOS.CrashSenderRemoveReason",
                            Sender::kTotalRemoval, Sender::kSendReasonCount))
      .Times(1);

  sender.SendCrashes(crashes_to_send);
  testing::Mock::VerifyAndClearExpectations(raw_metrics_lib);

  // We shouldn't be processing any crashes still.
  EXPECT_FALSE(base::PathExists(user_processing));
  EXPECT_FALSE(base::PathExists(user_meta_file));
  // Verify we recognized the crash report was dropped due to throttling.
  ASSERT_TRUE(brillo::FindLog("dropped due to crash report upload throttling"));
}

TEST_F(CrashSenderUtilTest, SendCrashes_Fail) {
  // Set up the mock session manager client.
  auto mock =
      std::make_unique<org::chromium::SessionManagerInterfaceProxyMock>();
  test_util::SetActiveSessions(mock.get(), {{"user", "hash"}});
  std::vector<MetaFile> crashes_to_send;

  // Create the system crash directory, and crash files in it.
  const base::FilePath system_dir = paths::Get(paths::kSystemCrashDirectory);
  ASSERT_TRUE(base::CreateDirectory(system_dir));
  const base::FilePath system_meta_file = system_dir.Append("0.0.0.0.0.meta");
  const base::FilePath system_log = system_dir.Append("0.0.0.0.0.log");
  const base::FilePath system_processing =
      system_dir.Append("0.0.0.0.0.processing");
  const char system_meta[] =
      "payload=0.0.0.0.0.log\n"
      "done=1\n";
  ASSERT_TRUE(test_util::CreateFile(system_meta_file, system_meta));
  ASSERT_TRUE(test_util::CreateFile(system_log, ""));
  CrashInfo system_info;
  EXPECT_TRUE(system_info.metadata.LoadFromString(system_meta));
  system_info.payload_file = system_log;
  system_info.payload_kind = "log";
  EXPECT_TRUE(base::Time::FromString("25 Apr 2018 1:23:44 GMT",
                                     &system_info.last_modified));
  crashes_to_send.emplace_back(system_meta_file, std::move(system_info));

  ASSERT_TRUE(SetConditions(kOfficialBuild, kSignInMode, kMetricsEnabled));

  // Set up the crash sender so that it fails.
  SetMockCrashSending(false);

  // Set up the sender.
  std::vector<base::TimeDelta> sleep_times;
  Sender::Options options;
  options.session_manager_proxy = mock.release();
  options.max_crash_rate = 2;
  options.sleep_function = base::BindRepeating(&FakeSleep, &sleep_times);
  options.always_write_uploads_log = true;
  MockSender sender(false,  // success=false
                    "500",  // Response code
                    std::move(metrics_lib_),
                    std::make_unique<test_util::AdvancingClock>(), options);

  sender.SendCrashes(crashes_to_send);

  // We shouldn't be processing the crash still -- sending failed, but didn't
  // crash.
  EXPECT_FALSE(base::PathExists(system_processing));

  // The followings should be kept since the crash report was not uploaded.
  EXPECT_TRUE(base::PathExists(system_meta_file));
  EXPECT_TRUE(base::PathExists(system_log));

  // The Chrome uploads.log file shouldn't exist because we had nothing to
  // report.
  EXPECT_FALSE(base::PathExists(paths::Get(paths::ChromeCrashLog::Get())));
}

// Verify behavior when SendCrashes itself crashes.
TEST_P(CrashSenderUtilDryRunParamDeathTest, SendCrashesCrash) {
  // Set up the mock session manager client.
  auto mock =
      std::make_unique<org::chromium::SessionManagerInterfaceProxyMock>();
  test_util::SetActiveSessions(mock.get(), {{"user", "hash"}});
  std::vector<MetaFile> crashes_to_send;

  // Create the system crash directory, and crash files in it.
  const base::FilePath system_dir = paths::Get(paths::kSystemCrashDirectory);
  ASSERT_TRUE(base::CreateDirectory(system_dir));
  const base::FilePath system_meta_file = system_dir.Append("0.0.0.0.0.meta");
  const base::FilePath system_log = system_dir.Append("0.0.0.0.0.log");
  const base::FilePath system_processing =
      system_dir.Append("0.0.0.0.0.processing");
  const char system_meta[] =
      "payload=0.0.0.0.0.log\n"
      "done=1\n";
  ASSERT_TRUE(test_util::CreateFile(system_meta_file, system_meta));
  ASSERT_TRUE(test_util::CreateFile(system_log, ""));
  CrashInfo system_info;
  EXPECT_TRUE(system_info.metadata.LoadFromString(system_meta));
  system_info.payload_file = system_log;
  system_info.payload_kind = "log";
  EXPECT_TRUE(base::Time::FromString("25 Apr 2018 1:23:44 GMT",
                                     &system_info.last_modified));
  crashes_to_send.emplace_back(system_meta_file, std::move(system_info));

  ASSERT_TRUE(SetConditions(kOfficialBuild, kSignInMode, kMetricsEnabled));

  std::vector<base::TimeDelta> sleep_times;
  Sender::Options options;
  options.session_manager_proxy = mock.release();
  options.max_crash_rate = 2;
  options.sleep_function = base::BindRepeating(&FakeSleep, &sleep_times);
  options.always_write_uploads_log = true;
  options.dry_run = dry_run_;
  MockSender sender(true,                 // success=true
                    "Too Many Requests",  // Response
                    std::move(metrics_lib_),
                    std::make_unique<test_util::AdvancingClock>(), options);

  SetMockCrashSending(true);
  sender.SetCrashDuringSendForTesting(true);
  EXPECT_DEATH(sender.SendCrashes(crashes_to_send), "crashing as requested");

  // We crashed, so the ".processing" file should still exist if not under dry
  // run mode. Under the dry run mode, the ".processing" file should never be
  // created.
  EXPECT_THAT(base::PathExists(system_processing), Ne(dry_run_));
}

class CrashSenderGetFatalCrashTypeTest
    : public ::testing::TestWithParam<
          std::tuple<std::optional<std::string>, std::optional<std::string>>> {
 protected:
  void SetUp() override {
    std::tie(collector_, fatal_crash_type_) = GetParam();
  }

  std::optional<std::string> collector_;
  std::optional<std::string> fatal_crash_type_;
};

TEST_P(CrashSenderGetFatalCrashTypeTest, GetFatalCrashType) {
  brillo::KeyValueStore metadata;
  if (collector_.has_value()) {
    metadata.SetString("upload_var_collector", collector_.value());
  }
  // Add some random fields
  metadata.SetString("exec_name", "fake_exec_name");
  metadata.SetString("ver", "fake_chromeos_ver");
  metadata.SetString("upload_var_prod", "fake_product");
  metadata.SetString("upload_var_ver", "fake_version");
  CrashDetails details = {
      // Add some other random fields
      .payload_kind = "fake_payload",
      .client_id = kFakeClientId,

      .metadata = metadata,
  };
  EXPECT_EQ(GetFatalCrashType(details), fatal_crash_type_);
}

INSTANTIATE_TEST_SUITE_P(
    CrashSenderGetFatalCrashTypeInstantiation,
    CrashSenderGetFatalCrashTypeTest,
    testing::Values(
        CrashSenderGetFatalCrashTypeTest::ParamType(std::nullopt, std::nullopt),
        CrashSenderGetFatalCrashTypeTest::ParamType("cool_collector",
                                                    std::nullopt),
        CrashSenderGetFatalCrashTypeTest::ParamType("kernel", "kernel"),
        CrashSenderGetFatalCrashTypeTest::ParamType("ec", "ec")),
    [](const ::testing::TestParamInfo<
        CrashSenderGetFatalCrashTypeTest::ParamType>& info) {
      std::ostringstream name;
      auto collector = std::get<0>(info.param);
      auto fatal_crash_type = std::get<1>(info.param);
      name << "collector_"
           << (collector.has_value() ? collector.value() : "absent")
           << "_crash_type_"
           << (fatal_crash_type.has_value() ? fatal_crash_type.value()
                                            : "absent");
      return name.str();
    });

TEST_F(CrashSenderUtilTest, LockFile) {
  auto clock = std::make_unique<MockClock>();
  base::Time start_time;
  ASSERT_TRUE(base::Time::FromUTCString("2019-04-20 13:53", &start_time));
  // Called twice -- once to get start time, once to see if we're already
  // past the start time + 5 minutes
  EXPECT_CALL(*clock, Now()).Times(2).WillRepeatedly(Return(start_time));
  std::vector<base::TimeDelta> sleep_times;
  Sender::Options options;
  options.sleep_function = base::BindRepeating(&FakeSleep, &sleep_times);
  Sender sender(std::move(metrics_lib_), std::move(clock), options);

  EXPECT_FALSE(IsFileLocked(paths::Get(paths::kCrashSenderLockFile)));
  base::File lock(sender.AcquireLockFileOrDie());
  EXPECT_TRUE(IsFileLocked(paths::Get(paths::kCrashSenderLockFile)));
  // Should not have slept acquiring lock since the file was unlocked.
  EXPECT_THAT(sleep_times, IsEmpty());
}

TEST_F(CrashSenderUtilTest, LockFileTriesAgainIfFirstAttemptFails) {
  base::FilePath lock_file_path = paths::Get(paths::kCrashSenderLockFile);
  auto lock_process = LockFile(lock_file_path);

  auto clock = std::make_unique<MockClock>();
  base::Time start_time;
  ASSERT_TRUE(base::Time::FromUTCString("2019-04-20 13:53", &start_time));

  // Make AcquireLockFileOrDie sleep several times, and then unlock the file.
  EXPECT_CALL(*clock, Now())
      .WillOnce(Return(start_time))
      .WillOnce(Return(start_time))
      .WillOnce(Return(start_time + base::Minutes(1)))
      .WillOnce(Return(start_time + base::Minutes(2)))
      .WillOnce(Return(start_time + base::Minutes(3)))
      .WillOnce(Invoke([&lock_process, start_time]() {
        lock_process->Kill(SIGKILL, 10);
        lock_process->Wait();
        return start_time + base::Minutes(4);
      }));
  std::vector<base::TimeDelta> sleep_times;
  Sender::Options options;
  options.sleep_function = base::BindRepeating(&FakeSleep, &sleep_times);
  Sender sender(std::move(metrics_lib_), std::move(clock), options);

  base::File lock(sender.AcquireLockFileOrDie());
  EXPECT_TRUE(IsFileLocked(lock_file_path));
  EXPECT_EQ(sleep_times.size(), 4);
}

TEST_F(CrashSenderUtilTest, LockFileTriesOneLastTimeAfterTimeout) {
  base::FilePath lock_file_path = paths::Get(paths::kCrashSenderLockFile);
  auto lock_process = LockFile(lock_file_path);

  auto clock = std::make_unique<MockClock>();
  base::Time start_time;
  ASSERT_TRUE(base::Time::FromUTCString("2019-04-20 13:53", &start_time));

  // Make AcquireLockFileOrDie sleep enough that the loop exits, then unlock
  // the file.
  EXPECT_CALL(*clock, Now())
      .WillOnce(Return(start_time))
      .WillOnce(Return(start_time))
      .WillOnce(Return(start_time + base::Minutes(1)))
      .WillOnce(Return(start_time + base::Minutes(2)))
      .WillOnce(Return(start_time + base::Minutes(3)))
      .WillOnce(Return(start_time + base::Minutes(4)))
      .WillOnce(Invoke([&lock_process, start_time]() {
        lock_process->Kill(SIGKILL, 10);
        lock_process->Wait();
        return start_time + base::Minutes(6);
      }));
  std::vector<base::TimeDelta> sleep_times;
  Sender::Options options;
  options.sleep_function = base::BindRepeating(&FakeSleep, &sleep_times);
  Sender sender(std::move(metrics_lib_), std::move(clock), options);

  base::File lock(sender.AcquireLockFileOrDie());
  EXPECT_TRUE(IsFileLocked(lock_file_path));
  EXPECT_EQ(sleep_times.size(), 5);
}

TEST_F(CrashSenderUtilDeathTest, LockFileDiesIfFileIsLocked) {
  std::vector<base::TimeDelta> sleep_times;
  Sender::Options options;
  options.sleep_function = base::BindRepeating(&FakeSleep, &sleep_times);
  options.log_extra_times = true;
  Sender sender(std::move(metrics_lib_),
                std::make_unique<test_util::AdvancingClock>(), options);
  // Lock in parent...
  base::File lock(sender.AcquireLockFileOrDie());
  EXPECT_TRUE(IsFileLocked(paths::Get(paths::kCrashSenderLockFile)));
  // ... so lock in child spawned by EXPECT_EXIT should fail
  base::Time start_time = base::Time::Now();
  LOG(INFO) << "About to launch AcquireLockFileOrDie(): " << base::Time::Now();
  EXPECT_EXIT(sender.AcquireLockFileOrDie(), ExitedWithCode(EXIT_FAILURE),
              "Failed to acquire a lock");
  LOG(INFO) << "AcquireLockFileOrDie took " << base::Time::Now() - start_time
            << "; time is " << base::Time::Now();
}

class IsNetworkOnlineTest : public CrashSenderUtilTest {
 public:
  void TestIsNetworkOnline(std::string connection_state,
                           bool get_properties_retval,
                           bool expected_result);
};

void IsNetworkOnlineTest::TestIsNetworkOnline(std::string connection_state,
                                              bool get_properties_retval,
                                              bool expected_result) {
  g_connection_state = &connection_state;
  // Set up the shill flimflam manager client.
  auto mock = std::make_unique<org::chromium::flimflam::ManagerProxyMock>();
  EXPECT_CALL(*mock, GetProperties(_, _, _))
      .WillOnce(
          DoAll(Invoke(&GetShillProperties), Return(get_properties_retval)));

  Sender::Options options;
  options.shill_proxy = mock.release();
  Sender sender(std::move(metrics_lib_),
                std::make_unique<test_util::AdvancingClock>(), options);
  EXPECT_EQ(sender.IsNetworkOnline(), expected_result);
}

TEST_F(IsNetworkOnlineTest, Online) {
  TestIsNetworkOnline("online", true, true);
}

TEST_F(IsNetworkOnlineTest, Offline) {
  TestIsNetworkOnline("offline", true, false);
}

TEST_F(IsNetworkOnlineTest, Fail) {
  TestIsNetworkOnline("", false, true);
}

}  // namespace util
