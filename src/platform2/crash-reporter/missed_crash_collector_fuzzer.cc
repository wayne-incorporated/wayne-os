// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdio.h>

#include <string>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <session_manager/dbus-proxy-mocks.h>

#include "crash-reporter/missed_crash_collector.h"
#include "crash-reporter/paths.h"
#include "crash-reporter/test_util.h"

class Environment {
 public:
  Environment() {
    // Disable logging per instructions.
    logging::SetMinLogLevel(logging::LOGGING_FATAL);
  }
};

class MissedCrashCollectorForFuzzing : public MissedCrashCollector {
 public:
  explicit MissedCrashCollectorForFuzzing(std::string user_name,
                                          std::string user_hash)
      : user_name_(std::move(user_name)), user_hash_(std::move(user_hash)) {}

  void SetUpDBus() override {
    // Mock out all DBus calls so (a) we don't actually call DBus and (b) we
    // don't CHECK fail when the DBus calls fail.
    auto mock =
        std::make_unique<org::chromium::SessionManagerInterfaceProxyMock>();
    test_util::SetActiveSessions(mock.get(), {{user_name_, user_hash_}});
    session_manager_proxy_ = std::move(mock);
  }

 private:
  // Results from the fake RetrieveActiveSessions call
  const std::string user_name_;
  const std::string user_hash_;
};

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

  const int kArbitraryMaxNameLength = 4096;
  std::string user_name =
      provider.ConsumeRandomLengthString(kArbitraryMaxNameLength);
  std::string user_hash =
      provider.ConsumeRandomLengthString(kArbitraryMaxNameLength);
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

  std::string input = provider.ConsumeRemainingBytesAsString();
  FILE* file = fmemopen(input.data(), input.size(), "r");
  if (!file) {
    return 0;
  }

  MissedCrashCollectorForFuzzing collector(std::move(user_name),
                                           std::move(user_hash));
  collector.set_input_file_for_testing(file);
  collector.force_daemon_store_for_testing(use_daemon_store);
  collector.Collect(/*pid=*/111,
                    /*recent_miss_count=*/222,
                    /*recent_match_count=*/333,
                    /*pending_miss_count=*/444);

  fclose(file);

  return 0;
}
