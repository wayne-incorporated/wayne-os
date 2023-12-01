// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/command_line.h>
#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/test/task_environment.h>
#include <base/test/test_timeouts.h>
#include <debugd/dbus-proxy-mocks.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <gmock/gmock.h>
#include <session_manager/dbus-proxy-mocks.h>

#include "crash-reporter/chrome_collector.h"
#include "crash-reporter/paths.h"
#include "crash-reporter/test_util.h"

namespace {

using ::testing::_;
using ::testing::WithArgs;

class Environment {
 public:
  Environment() {
    // Disable logging per instructions.
    logging::SetMinLogLevel(logging::LOGGING_FATAL);

    // Needed for TestTimeouts::Initialize(). We don't have access to the real
    // command-line, and even if we did, it's not clear we would want to use it.
    const char* const kFakeCommandLine[] = {"chrome_collector_fuzzer"};
    base::CommandLine::Init(std::size(kFakeCommandLine), kFakeCommandLine);

    // Needed for SingleThreadTaskEnvironment.
    TestTimeouts::Initialize();
  }
};

class ChromeCollectorForFuzzing : public ChromeCollector {
 public:
  explicit ChromeCollectorForFuzzing(CrashSendingMode crash_sending_mode,
                                     std::string user_name,
                                     std::string user_hash,
                                     std::string dri_error_state,
                                     std::string dmesg_result)
      : ChromeCollector(crash_sending_mode),
        user_name_(std::move(user_name)),
        user_hash_(std::move(user_hash)),
        dri_error_state_(std::move(dri_error_state)),
        dmesg_result_(std::move(dmesg_result)) {}

  void SetUpDBus() override {
    // Mock out all DBus calls so (a) we don't actually call DBus and (b) we
    // don't CHECK fail when the DBus calls fail.
    auto session_manager_mock =
        std::make_unique<org::chromium::SessionManagerInterfaceProxyMock>();
    test_util::SetActiveSessions(session_manager_mock.get(),
                                 {{user_name_, user_hash_}});
    session_manager_proxy_ = std::move(session_manager_mock);

    auto proxy_mock = std::make_unique<org::chromium::debugdProxyMock>();
    std::function<void(base::OnceCallback<void(const std::string&)> &&)>
        handler_dri_error_state =
            [this](base::OnceCallback<void(const std::string&)> callback) {
              task_environment_.GetMainThreadTaskRunner()->PostNonNestableTask(
                  FROM_HERE,
                  base::BindOnce(std::move(callback), dri_error_state_));
            };
    ON_CALL(*proxy_mock, GetLogAsync("i915_error_state", _, _, _))
        .WillByDefault(WithArgs<1>(handler_dri_error_state));

    std::function<void(base::OnceCallback<void(const std::string&)> &&)>
        handler_dmesg =
            [this](base::OnceCallback<void(const std::string&)> callback) {
              task_environment_.GetMainThreadTaskRunner()->PostNonNestableTask(
                  FROM_HERE,
                  base::BindOnce(std::move(callback), dmesg_result_));
            };
    ON_CALL(*proxy_mock, CallDmesgAsync(_, _, _, _))
        .WillByDefault(WithArgs<1>(handler_dmesg));

    debugd_proxy_ = std::move(proxy_mock);
  }

 private:
  // RunLoop requires a task environment.
  base::test::SingleThreadTaskEnvironment task_environment_;
  // Results from the fake RetrieveActiveSessions call
  const std::string user_name_;
  const std::string user_hash_;
  // Results for the fake GetLogAsync call
  const std::string dri_error_state_;
  // Results for the fake CallDmesgAsync call
  const std::string dmesg_result_;
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  // Put all files into a per-run temp directory.
  base::ScopedTempDir temp_dir;
  CHECK(temp_dir.CreateUniqueTempDir());
  base::FilePath test_dir = temp_dir.GetPath();
  paths::SetPrefixForTesting(test_dir);

  FuzzedDataProvider provider(data, size);
  // Force daemon store on or off, since fuzzers should not have
  // non-deterministic behavior.
  bool use_daemon_store = provider.ConsumeBool();

  // Exactly one of exe_name and non_exe_error_key can be set or we CHECK fail.
  std::string exe_name;
  std::string non_exe_error_key;
  if (provider.ConsumeBool()) {
    exe_name = provider.ConsumeRandomLengthString();
    if (exe_name.empty()) {
      return 0;  // Or we'll CHECK-fail. Fuzzers shouldn't exit on any input.
    }
  } else {
    non_exe_error_key = provider.ConsumeRandomLengthString();
    if (non_exe_error_key.empty()) {
      return 0;  // Or we'll CHECK-fail. Fuzzers shouldn't exit on any input.
    }
  }

  // pid and uid must be >= 0 Or we'll CHECK-fail. Fuzzers shouldn't exit on any
  // input.
  pid_t pid = provider.ConsumeIntegralInRange(
      (pid_t)0, std::numeric_limits<pid_t>::max());
  uid_t uid = provider.ConsumeIntegralInRange(
      (uid_t)0, std::numeric_limits<uid_t>::max());
  std::string user_name = provider.ConsumeRandomLengthString();
  std::string user_hash = provider.ConsumeRandomLengthString();
  // If the user_hash looks like an absolute directory path,
  // GetDaemonStoreCrashDirectories will CHECK fail when calling
  // base::FilePath::Append().
  base::FilePath user_hash_path(user_hash);
  if (user_hash_path.IsAbsolute()) {
    return 0;
  }

  // If the user_hash_path uses "..", the fuzzer can "escape" from the temp
  // directory and overwrite random files.
  if (user_hash_path.ReferencesParent()) {
    return 0;
  }

  std::string dri_error_state = provider.ConsumeRandomLengthString();
  std::string dmesg_result = provider.ConsumeRandomLengthString();

  // Despite the Memfd in the name of HandleCrashThroughMemfd, we can pass a
  // file handle to a normal file. memfd isn't supported by QEMU so better to
  // just use normal files here.
  base::FilePath test_input_path = test_dir.Append("test_input");
  std::string input = provider.ConsumeRemainingBytesAsString();
  base::WriteFile(test_input_path, input.c_str(), input.length());
  base::File test_input(test_input_path,
                        base::File::FLAG_OPEN | base::File::FLAG_READ);
  if (!test_input.IsValid()) {
    return 0;
  }

  // Empty because otherwise we CHECK-fail if this isn't a test image.
  const std::string kEmptyDumpDir;

  int32_t signal = provider.ConsumeIntegral<int32_t>();

  // kNormalCrashSendMode -- This makes it much simpler to mock out the DBus
  // calls, and we're not fuzzing the crash loop logic.
  ChromeCollectorForFuzzing collector(
      CrashCollector::kNormalCrashSendMode, std::move(user_name),
      std::move(user_hash), std::move(dri_error_state),
      std::move(dmesg_result));
  collector.Initialize(false);
  collector.force_daemon_store_for_testing(use_daemon_store);
  collector.HandleCrashThroughMemfd(test_input.TakePlatformFile(), pid, uid,
                                    exe_name, non_exe_error_key, kEmptyDumpDir,
                                    signal);
  return 0;
}
