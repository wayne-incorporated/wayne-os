// Copyright 2010 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/unclean_shutdown_collector.h"

#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/files/safe_fd.h>
#include <brillo/process/process.h>
#include <brillo/strings/string_utils.h>

using base::FilePath;
using brillo::SafeFD;

namespace {

const char kOsRelease[] = "/etc/os-release";

const char kUncleanShutdownFile[] =
    "/var/lib/crash_reporter/pending_clean_shutdown";

// Files created by power manager used for crash reporting.
const char kPowerdTracePath[] = "/var/lib/power_manager";
// Presence of this file indicates that the system was suspended
const char kPowerdSuspended[] = "powerd_suspended";

bool SafelyDeleteFile(FilePath file_path) {
  auto root_res = SafeFD::Root();
  if (SafeFD::IsError(root_res.second)) {
    LOG(ERROR) << "Failed to open root: " << static_cast<int>(root_res.second);
    return false;
  }
  auto dir_res = root_res.first.OpenExistingDir(file_path.DirName());
  if (SafeFD::IsError(dir_res.second)) {
    if (dir_res.second == SafeFD::Error::kDoesNotExist) {
      return true;
    }
    LOG(ERROR) << "Failed to open " << file_path.DirName() << ": "
               << static_cast<int>(dir_res.second);
    return false;
  }
  auto unlink_result = dir_res.first.Unlink(file_path.BaseName().value());
  if (SafeFD::IsError(unlink_result) &&
      unlink_result != SafeFD::Error::kDoesNotExist &&
      !(unlink_result == SafeFD::Error::kIOError && errno == ENOENT)) {
    // Don't fail if the file didn't exist; that's fine.
    LOG(ERROR) << "Failed to delete file " << file_path.value() << ": "
               << static_cast<int>(unlink_result);
    return false;
  }
  return true;
}

bool SafelyCopyFile(FilePath source, FilePath dest) {
  // We cannot use SafeFD because the permissions on /var/lib/crash_reporter/
  // are 0700 but the permissions on the lsb-release / os-release files are
  // 0644. SafeFD expects consistent permissions, and will fail otherwise.
  int source_parent_fd;
  if (!ValidatePathAndOpen(source.DirName(), &source_parent_fd)) {
    LOG(ERROR) << "Failed to open " << source.DirName();
    return false;
  }
  base::ScopedFD scoped_source_parent(source_parent_fd);
  int source_fd =
      HANDLE_EINTR(openat(source_parent_fd, source.BaseName().value().c_str(),
                          O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  if (source_fd < 0) {
    PLOG(ERROR) << "Failed to open " << source;
    return false;
  }
  base::File source_file(source_fd);

  int dest_parent_fd;
  if (!ValidatePathAndOpen(dest.DirName(), &dest_parent_fd)) {
    LOG(ERROR) << "Failed to open " << dest.DirName();
    return false;
  }
  base::ScopedFD scoped_dest_parent(dest_parent_fd);
  // We need O_TRUNC so that any existing larger files are deleted, rather than
  // partially overwritten.
  int dest_fd = HANDLE_EINTR(
      openat(dest_parent_fd, dest.BaseName().value().c_str(),
             O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0644));
  if (dest_fd < 0) {
    PLOG(ERROR) << "Failed to open " << dest;
    return false;
  }
  base::File dest_file(dest_fd);

  return base::CopyFileContents(source_file, dest_file);
}

}  // namespace


UncleanShutdownCollector::UncleanShutdownCollector()
    : CrashCollector("unclean_shutdown"),
      unclean_shutdown_file_(kUncleanShutdownFile),
      powerd_trace_path_(kPowerdTracePath),
      powerd_suspended_file_(powerd_trace_path_.Append(kPowerdSuspended)),
      os_release_path_(kOsRelease) {}

UncleanShutdownCollector::~UncleanShutdownCollector() {}

bool UncleanShutdownCollector::Enable() {
  auto root_res = SafeFD::Root();
  if (SafeFD::IsError(root_res.second)) {
    LOG(ERROR) << "Failed to open root: " << static_cast<int>(root_res.second);
    return false;
  }
  FilePath file_path(unclean_shutdown_file_);
  auto file_res = root_res.first.MakeFile(file_path, 0700);
  if (SafeFD::IsError(file_res.second)) {
    LOG(ERROR) << "Unable to create shutdown check file: "
               << static_cast<int>(file_res.second);
    return false;
  }
  return true;
}

bool UncleanShutdownCollector::DeleteUncleanShutdownFiles() {
  if (!SafelyDeleteFile(FilePath(unclean_shutdown_file_))) {
    return false;
  }
  // Delete power manager state file if it exists.
  if (!SafelyDeleteFile(powerd_suspended_file_)) {
    return false;
  }
  return true;
}

bool UncleanShutdownCollector::Collect() {
  FilePath unclean_file_path(unclean_shutdown_file_);
  if (!base::PathExists(unclean_file_path)) {
    return false;
  }
  LOG(WARNING) << "Last shutdown was not clean";
  if (DeadBatteryCausedUncleanShutdown()) {
    DeleteUncleanShutdownFiles();
    return false;
  }
  // EC reboots also cause AP reboots, so log the EC uptime to help correlate
  // them.
  LogEcUptime();
  DeleteUncleanShutdownFiles();

  return true;
}

bool UncleanShutdownCollector::Disable() {
  LOG(INFO) << "Clean shutdown signalled";
  return DeleteUncleanShutdownFiles();
}

bool UncleanShutdownCollector::SaveVersionData() {
  FilePath crash_directory(crash_reporter_state_path_);
  FilePath saved_lsb_release = crash_directory.Append(lsb_release_.BaseName());
  if (!SafelyCopyFile(lsb_release_, saved_lsb_release)) {
    LOG(ERROR) << "Failed to copy " << lsb_release_.value() << " to "
               << saved_lsb_release.value();
    return false;
  }

  FilePath saved_os_release =
      crash_directory.Append(os_release_path_.BaseName());
  if (!SafelyCopyFile(os_release_path_, saved_os_release)) {
    LOG(ERROR) << "Failed to copy " << os_release_path_.value() << " to "
               << saved_os_release.value();
    return false;
  }

  // TODO(bmgordon): When crash_sender reads from os-release.d, copy it also.

  return true;
}

bool UncleanShutdownCollector::DeadBatteryCausedUncleanShutdown() {
  // Check for case of battery running out while suspended.
  if (base::PathExists(powerd_suspended_file_)) {
    LOG(INFO) << "Unclean shutdown occurred while suspended. Not counting "
              << "toward unclean shutdown statistic.";
    return true;
  }
  return false;
}

void UncleanShutdownCollector::LogEcUptime() {
  const char kEcToolPath[] = "/usr/sbin/ectool";

  if (!base::PathExists(base::FilePath(kEcToolPath))) {
    LOG(INFO) << "ectool unavailable: '" << kEcToolPath << "'";
    return;
  }

  brillo::ProcessImpl ectool;
  ectool.AddArg(kEcToolPath);
  // Get info about how long the EC has been running and the most recent AP
  // resets.
  ectool.AddArg("uptimeinfo");
  // Combine stdout and stderr.
  ectool.RedirectOutputToMemory(/*combine_stdout_and_stderr=*/true);

  const int result = ectool.Run();
  std::string uptimeinfo_output = ectool.GetOutputString(STDOUT_FILENO);
  if (result != 0) {
    LOG(ERROR) << "Failed to run ectool. Error: '" << result << "'";
    return;
  }

  // LOG() converts newlines to "#012", logging all the output to a single line.
  // This is difficult to read, so instead log each line of the ectool output
  // separately to keep things human-readable.
  std::vector<std::string> uptimeinfo_strings =
      brillo::string_utils::Split(uptimeinfo_output, "\n", true, true);
  for (const std::string& uptimeinfo_line : uptimeinfo_strings) {
    LOG(INFO) << "[ectool uptimeinfo] " << uptimeinfo_line;
  }
}
