// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdlib.h>
#include <sys/capability.h>
#include <sys/mount.h>  // for MS_SLAVE
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <limits>
#include <memory>

#include <base/at_exit.h>
#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_piece.h>
#include <base/time/default_clock.h>
#include <brillo/array_utils.h>
#include <brillo/syslog_logging.h>
#include <libminijail.h>
#include <metrics/metrics_library.h>
#include <scoped_minijail.h>

#include "crash-reporter/crash_sender_paths.h"
#include "crash-reporter/crash_sender_util.h"
#include "crash-reporter/paths.h"
#include "crash-reporter/util.h"

namespace {

// Does the CLI contain the dry run flag?
bool IsDryRun(int argc, const char* argv[]) {
  static constexpr base::StringPiece kDryRunFlag("--dry_run");

  for (int i = 1; i < argc; ++i) {
    if (kDryRunFlag == argv[i]) {
      return true;
    }
  }

  return false;
}

// Sets up the minijail sandbox.
//
// crash_sender currently needs to run as root:
// - System crash reports in /var/spool/crash are owned by root.
// - User crash reports in /home/chronos/ are owned by chronos.
//
// crash_sender needs network access in order to upload things.
//
void SetUpSandbox(struct minijail* jail) {
  // Keep CAP_DAC_OVERRIDE in order to access non-root paths.
  // Keep CAP_FOWNER to be able to delete files in sticky-bit directories.
  // TODO(crbug.com/782243) Remove CAP_FOWNER once crash_sender can run with
  // non-root uids.
  minijail_use_caps(jail,
                    CAP_TO_MASK(CAP_DAC_OVERRIDE) | CAP_TO_MASK(CAP_FOWNER));
  // Set ambient capabilities because crash_sender runs other programs.
  // TODO(satorux): Remove this once the code is entirely C++.
  minijail_set_ambient_caps(jail);
  minijail_no_new_privs(jail);
  minijail_namespace_ipc(jail);
  minijail_namespace_pids(jail);
  minijail_remount_proc_readonly(jail);
  minijail_namespace_vfs(jail);
  // Remount mounts as MS_SLAVE to prevent crash_reporter from holding on to
  // mounts that might be unmounted in the root mount namespace.
  minijail_remount_mode(jail, MS_SLAVE);
  minijail_mount_tmp(jail);
  minijail_namespace_uts(jail);
  minijail_forward_signals(jail);
}

// Sets up the minijail sandbox for dry run in addition to the standard ones. It
// bind-mounts as read-only directories that we know crash_sender shouldn't
// write under the dry run mode.
void SetUpSandboxForDryRun(struct minijail* jail) {
  static constexpr auto kReadOnlyDirs = brillo::make_array<const char*>(
      // Prevent modifying crash meta file directories
      paths::kFallbackUserCrashDirectory, paths::kCryptohomeCrashDirectory,
      paths::kSystemCrashDirectory,
      // Prevent UMA reporting
      "/var/lib");
  for (const char* dir : kReadOnlyDirs) {
    if (!base::PathExists(base::FilePath(dir))) {
      // Some of the dirs may not exist and we don't bind-mount it if it
      // doesn't exist. This suppresses noisy warnings from minijail:
      //
      // WARNING crash_sender[10928]:
      // libminijail[10928]: realpath(/home/chronos/crash) failed: No such file
      // or directory
      // WARNING crash_sender[10928]: libminijail[10928]: path
      // '/home/chronos/crash' is not a canonical path
      // WARNING crash_sender[10928]: libminijail[10928]: src
      // '/home/chronos/crash' is not a valid bind mount path
      //
      // We don't use `base::DirectoryExists` because, if the path exists and is
      // not a directory, likely something's wrong.
      continue;
    }
    minijail_bind(jail, dir, dir, /*writable=*/0);
  }
}

// Runs the main function for the child process.
int RunChildMain(int argc, const char* argv[]) {
  util::CommandLineFlags flags;
  util::ParseCommandLine(argc, argv, &flags);

  if (util::DoesPauseFileExist() && !flags.ignore_pause_file) {
    LOG(INFO) << "Exiting early due to " << paths::kPauseCrashSending;
    return EXIT_FAILURE;
  }

  auto clock = std::make_unique<base::DefaultClock>();

  if (flags.test_mode) {
    LOG(INFO) << "--test_mode present; will not actually upload to server.";
  } else if (flags.allow_dev_sending) {
    LOG(INFO) << "--dev flag present, ignore image checks and uploading "
              << "crashes to staging server at go/crash-staging";
  } else if (flags.dry_run) {
    LOG(INFO) << "--dry_run flag present, ignore image checks and will not "
              << "actually upload to server.";
  } else {
    // Normal mode (not test, not dev, not dry run).
    if (util::IsTestImage() && !flags.force_upload_on_test_images) {
      LOG(INFO) << "Exiting early due to test image.";
      return EXIT_FAILURE;
    }
  }

  auto metrics_lib = std::make_unique<MetricsLibrary>();
  util::Sender::Options options;
  options.max_spread_time = flags.max_spread_time;
  if (flags.ignore_rate_limits) {
    options.max_crash_rate = std::numeric_limits<int>::max();
    options.max_crash_bytes = std::numeric_limits<int>::max();
  }
  if (flags.ignore_hold_off_time) {
    options.hold_off_time = base::Seconds(0);
  }
  options.allow_dev_sending = flags.allow_dev_sending;
  options.test_mode = flags.test_mode;
  options.upload_old_reports = flags.upload_old_reports;
  options.force_upload_on_test_images = flags.force_upload_on_test_images;
  options.consent_already_checked_by_crash_reporter =
      flags.consent_already_checked_by_crash_reporter;
  options.dry_run = flags.dry_run;
  util::Sender sender(std::move(metrics_lib), std::move(clock), options);

  // If you add sigificant code past this point, consider updating
  // crash_sender_fuzzer.cc as well.

  // Get all reports we might want to send, and then choose the more important
  // report out of all the directories to send first.
  std::vector<base::FilePath> crash_directories;
  if (flags.crash_directory.empty()) {
    crash_directories = sender.GetUserCrashDirectories();
    crash_directories.push_back(paths::Get(paths::kSystemCrashDirectory));
    crash_directories.push_back(paths::Get(paths::kFallbackUserCrashDirectory));
  } else {
    crash_directories.push_back(base::FilePath(flags.crash_directory));
  }

  std::vector<util::MetaFile> reports_to_send;

  base::File lock_file(sender.AcquireLockFileOrDie());
  for (const auto& directory : crash_directories) {
    if (!flags.dry_run) {
      util::RemoveOrphanedCrashFiles(directory);
    }
    sender.RemoveAndPickCrashFiles(directory, &reports_to_send);
  }
  lock_file.Close();

  util::SortReports(&reports_to_send);
  sender.SendCrashes(reports_to_send);

  return EXIT_SUCCESS;
}

// Cleans up. This function runs in the parent process (not sandboxed), hence
// should be very minimal. No need to delete temporary files manually in /tmp,
// that's a unique tmpfs provided by minijail, that'll automatically go away
// when the child process is terminated.
void CleanUp(void*) {
  util::RecordCrashDone();
}

}  // namespace

int main(int argc, const char* argv[]) {
  // Log to syslog (/var/log/messages), and stderr if stdin is a tty.
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);
  // Register the cleanup function to be called at exit.
  base::AtExitManager at_exit_manager;
  base::AtExitManager::RegisterCallback(&CleanUp, nullptr);

  // Set up a sandbox, and jail the child process.
  ScopedMinijail jail(minijail_new());
  SetUpSandbox(jail.get());
  if (IsDryRun(argc, argv)) {
    SetUpSandboxForDryRun(jail.get());
  }
  const pid_t pid = minijail_fork(jail.get());

  if (pid == 0)
    return RunChildMain(argc, argv);

  // We rely on the child handling its own exit status, and a non-zero status
  // isn't necessarily a bug (e.g. if mocked out that way).  Only warn for an
  // internal error.
  const int status = minijail_wait(jail.get());
  LOG_IF(ERROR, status < 0)
      << "Child process " << pid << " did not finish cleanly: " << status;
  return status;
}
