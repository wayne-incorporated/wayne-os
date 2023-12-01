// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstddef>
#include <cstdint>

#include <string>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/time/time.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "crash-reporter/crash_sender_util.h"
#include "crash-reporter/paths.h"
#include "crash-reporter/test_util.h"
#include "metrics/metrics_library_mock.h"

namespace {
class Environment {
 public:
  Environment() {
    // Disable logging per instructions.
    logging::SetMinLogLevel(logging::LOGGING_FATAL);
    // Don't ever actually upload anything!
    util::g_force_is_mock = true;
  }
};

// Ignore calls to sleep inside crash_sender.
void IgnoreSleep(base::TimeDelta duration) {}

// Creates a file with a random name and random contents. File will always be
// located in or below |test_dir|.
void CreateRandomFile(base::StringPiece suffix,
                      const base::FilePath& test_dir,
                      FuzzedDataProvider* provider) {
  const int kArbitraryMaxFileNameLength = 50;
  base::FilePath file_name(
      provider->ConsumeRandomLengthString(kArbitraryMaxFileNameLength));
  if (!suffix.empty()) {
    file_name = file_name.AddExtension(suffix);
  }
  if (file_name.IsAbsolute()) {
    return;  // Or Append() will check-fail. Fuzzers should not exit.
  }
  base::FilePath file_path = test_dir.Append(file_name);
  // Don't allow the fuzzer to write to random directories outside the
  // test directory.
  if (!test_dir.IsParent(file_path)) {
    return;
  }
  const int kArbitraryMaxFileSize = 5000;
  std::string content =
      provider->ConsumeRandomLengthString(kArbitraryMaxFileSize);

  base::CreateDirectory(file_path.DirName());
  base::WriteFile(file_path, content.c_str(), content.length());
}

// Make the lock file. If we don't make the lock file's directory,
// AcquireLockFileOrDie() will fatal-error. If a fuzzer turns the lock file into
// a directory, we'll also die. Get in ahead of the fuzzer and make sure it's a
// normal file.
void MakeLockFile() {
  base::FilePath lock_file_path = paths::Get(paths::kCrashSenderLockFile);
  base::FilePath lock_file_dir = lock_file_path.DirName();
  CHECK(base::CreateDirectory(lock_file_dir));
  CHECK_GE(base::WriteFile(lock_file_path, "", 0), 0);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  // Put all files into a per-run temp directory.
  base::ScopedTempDir temp_dir;
  CHECK(temp_dir.CreateUniqueTempDir());
  base::FilePath test_dir = temp_dir.GetPath();
  paths::SetPrefixForTesting(test_dir);
  MakeLockFile();

  FuzzedDataProvider provider(data, size);

  auto metrics_lib = std::make_unique<MetricsLibraryMock>();
  bool always_write_uploads_log = provider.ConsumeBool();
  metrics_lib->set_metrics_enabled(provider.ConsumeBool());
  metrics_lib->set_guest_mode(provider.ConsumeBool());
  bool allow_dev_sending = provider.ConsumeBool();
  util::g_force_is_mock_successful = provider.ConsumeBool();

  // Create the actual meta file.
  CreateRandomFile(".meta", test_dir, &provider);

  // Create some files that can be referenced by the meta as a payload and such.
  for (int related_files = provider.ConsumeIntegralInRange(0, 5);
       related_files > 0; --related_files) {
    // Ignoring errors; if we get illegal names, we should just keep going.
    CreateRandomFile("", test_dir, &provider);
  }

  util::Sender::Options options;
  options.max_spread_time = base::TimeDelta();
  options.hold_off_time = base::TimeDelta();
  options.allow_dev_sending = allow_dev_sending;
  options.always_write_uploads_log = always_write_uploads_log;
  options.sleep_function = base::BindRepeating(&IgnoreSleep);

  // The remaining lines are basically a condensed version of crash_sender.cc's
  // RunChildMain.
  util::Sender sender(std::move(metrics_lib),
                      std::make_unique<test_util::AdvancingClock>(), options);
  std::vector<util::MetaFile> reports_to_send;
  util::RemoveOrphanedCrashFiles(test_dir);
  sender.RemoveAndPickCrashFiles(test_dir, &reports_to_send);
  util::SortReports(&reports_to_send);

  sender.SendCrashes(reports_to_send);

  return 0;
}
