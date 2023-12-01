// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/crash_sender_tool.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory>

#include <base/check.h>
#include <base/files/file.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/dbus/exported_property_set.h>

#include "debugd/src/error_utils.h"
#include "debugd/src/process_with_id.h"

namespace debugd {
namespace {
constexpr char kErrorIOError[] = "org.chromium.debugd.error.IOError";
}  // namespace

constexpr char CrashSenderTool::kErrorBadFileName[];

void CrashSenderTool::UploadCrashes() {
  RunCrashSender(false /* ignore_hold_off_time */,
                 base::FilePath("") /* crash_directory */,
                 false /* consent_already_checked_by_crash_reporter */);
}

bool CrashSenderTool::UploadSingleCrash(
    const std::vector<std::tuple<std::string, base::ScopedFD>>& in_files,
    brillo::ErrorPtr* error,
    bool consent_already_checked_by_crash_reporter) {
  // debugd runs in a non-root mount namespace and mounts a new tmpfs on /tmp
  // inside the namespace, so this should be invisible to all other processes
  // and not written to disk.
  //
  // *It is a privacy violation* if these files are visible to non-root
  // processes or are written unencrypted to disk!
  base::FilePath crash_directory("/tmp/crash");
  crash_directory = crash_directory.AddExtension(
      base::NumberToString(next_crash_directory_id_));
  next_crash_directory_id_++;

  // We need to be sure to clean up the tmp directory to avoid leaking
  // resources.
  base::ScopedTempDir crash_directory_holder;
  if (!crash_directory_holder.Set(crash_directory)) {
    DEBUGD_ADD_ERROR(error, kErrorIOError, "Create directory failed");
    return false;
  }

  for (const auto& in_file_tuple : in_files) {
    base::FilePath file_name(std::get<0>(in_file_tuple));
    const base::ScopedFD& file_descriptor = std::get<1>(in_file_tuple);

    // Sanitize file names to ensure a bad actor cannot ask us to write to
    // arbitrary files. crash_reporter should only send us the base file name,
    // so if it's not just a base file name, it's not from crash_reporter.
    // Also check for "..", "/", and "."
    if (file_name != file_name.BaseName() || file_name.ReferencesParent() ||
        file_name.IsAbsolute() ||
        file_name.value() == base::FilePath::kCurrentDirectory) {
      DEBUGD_ADD_ERROR(error, kErrorBadFileName, "Bad File Name");
      return false;
    }

    // Copy contents of file_descriptor to a new file named file_name inside
    // crash_directory.
    base::FilePath file_path = crash_directory.Append(file_name);
    base::File new_file(file_path,
                        base::File::FLAG_CREATE | base::File::FLAG_WRITE);
    if (!new_file.IsValid()) {
      LOG(WARNING) << "Error creating file " << file_path.value() << ": "
                   << base::File::ErrorToString(new_file.error_details());
      continue;
    }

    if (lseek(file_descriptor.get(), SEEK_SET, 0) == static_cast<off_t>(-1)) {
      PLOG(WARNING) << "lseek failed";
    }
    const int kBufferSize = 1 << 16;
    std::unique_ptr<char[]> buf(new char[kBufferSize]);
    ssize_t len;
    while ((len = HANDLE_EINTR(
                read(file_descriptor.get(), buf.get(), kBufferSize))) > 0) {
      if (!new_file.WriteAtCurrentPos(buf.get(), len)) {
        LOG(WARNING) << "Error writing to file " << file_path.value() << ": "
                     << base::File::ErrorToString(new_file.error_details());
        break;
      }
    }

    if (len < 0) {
      PLOG(WARNING) << "Failed to read from passed file descriptor";
    }

    // Ensure data is visible to crash_sender.
    new_file.Flush();
  }

  // Since crash_sender jails itself, it won't actually see our /tmp/crash.###
  // directory. Instead, open the directory and pass the /proc path to the
  // directory file descriptor as the crash directory.
  base::ScopedFD crash_directory_fd(
      HANDLE_EINTR(open(crash_directory.value().c_str(), O_RDONLY)));
  if (!crash_directory_fd.is_valid()) {
    DEBUGD_ADD_ERROR(error, kErrorIOError, "Open directory failed");
    return false;
  }

  base::FilePath munged_crash_directory("/proc/self/fd");
  munged_crash_directory = munged_crash_directory.Append(
      base::NumberToString(crash_directory_fd.get()));

  const bool ignore_hold_off_time = true;  // We already flushed all the files.
  RunCrashSender(ignore_hold_off_time, munged_crash_directory,
                 consent_already_checked_by_crash_reporter);

  return true;
}

void CrashSenderTool::RunCrashSender(
    bool ignore_hold_off_time,
    const base::FilePath& crash_directory,
    bool consent_already_checked_by_crash_reporter) {
  // 'crash_sender' requires accessing user mounts to upload user crashes.
  ProcessWithId* p =
      CreateProcess(false /* sandboxed */, true /* access_root_mount_ns */);
  p->AddArg("/sbin/crash_sender");
  // This is being invoked directly by the user. Override some of the limits
  // we normally use to avoid interfering with user tasks.
  p->AddArg("--max_spread_time=0");
  p->AddArg("--ignore_rate_limits");

  if (ignore_hold_off_time) {
    p->AddArg("--ignore_hold_off_time");
  }

  if (!crash_directory.empty()) {
    p->AddArg("--crash_directory=" + crash_directory.value());
  }

  if (test_mode_) {
    p->AddArg("--test_mode");
  }

  if (consent_already_checked_by_crash_reporter) {
    p->AddArg("--consent_already_checked_by_crash_reporter");
  }

  p->Run();
}

void CrashSenderTool::SetTestMode(bool mode) {
  test_mode_ = mode;
  LOG(INFO) << "CrashSenderTestMode set to " << std::boolalpha << test_mode_;
}

}  // namespace debugd
