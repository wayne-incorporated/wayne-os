// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/mount_point.h"

#include <utility>

#include <base/check.h>
#include <base/containers/contains.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>

#include "cros-disks/platform.h"
#include "cros-disks/quote.h"

namespace cros_disks {

std::unique_ptr<MountPoint> MountPoint::CreateUnmounted(
    MountPointData data, const Platform* const platform) {
  std::unique_ptr<MountPoint> mount_point =
      std::make_unique<MountPoint>(std::move(data), platform);
  mount_point->is_mounted_ = false;
  return mount_point;
}

std::unique_ptr<MountPoint> MountPoint::Mount(MountPointData data,
                                              const Platform* const platform,
                                              MountError* const error) {
  DCHECK(error);
  *error = platform->Mount(data.source, data.mount_path.value(),
                           data.filesystem_type, data.flags, data.data);

  if (*error != MountError::kSuccess) {
    return nullptr;
  }

  return std::make_unique<MountPoint>(std::move(data), platform);
}

MountPoint::MountPoint(MountPointData data, const Platform* platform)
    : data_(std::move(data)), platform_(platform) {
  DCHECK(!path().empty());
}

MountError MountPoint::Unmount() {
  MountError error = MountError::kPathNotMounted;

  if (is_mounted_) {
    // To prevent the umount() syscall from blocking for too long (b/258344222),
    // request the FUSE process termination if this process is "safe" to kill.
    if (process_ && is_read_only())
      process_->KillPidNamespace();

    error = platform_->Unmount(data_.mount_path, data_.filesystem_type);
    if (error == MountError::kSuccess || error == MountError::kPathNotMounted) {
      is_mounted_ = false;

      if (eject_)
        std::move(eject_).Run();
    }
  }

  process_.reset();

  if (launcher_exit_callback_) {
    DCHECK_EQ(MountError::kInProgress, data_.error);
    data_.error = MountError::kCancelled;
    std::move(launcher_exit_callback_).Run(MountError::kCancelled);
  }

  if (!is_mounted_ && must_remove_dir_ &&
      platform_->RemoveEmptyDirectory(data_.mount_path.value())) {
    must_remove_dir_ = false;
  }

  return error;
}

MountError MountPoint::Remount(bool read_only) {
  if (!is_mounted_)
    return MountError::kPathNotMounted;

  uint64_t flags = data_.flags;
  if (read_only) {
    flags |= MS_RDONLY;
  } else {
    flags &= ~MS_RDONLY;
  }

  const MountError error =
      platform_->Mount(data_.source, data_.mount_path.value(),
                       data_.filesystem_type, flags | MS_REMOUNT, data_.data);
  if (error == MountError::kSuccess)
    data_.flags = flags;

  return error;
}

MountError MountPoint::ConvertLauncherExitCodeToMountError(
    const int exit_code) const {
  if (exit_code == 0)
    return MountError::kSuccess;

  if (base::Contains(password_needed_exit_codes_, exit_code))
    return MountError::kNeedPassword;

  return MountError::kMountProgramFailed;
}

void MountPoint::OnLauncherExit(const int exit_code) {
  // Record the FUSE launcher's exit code in Metrics.
  if (metrics_ && !metrics_name_.empty())
    metrics_->RecordFuseMounterErrorCode(metrics_name_, exit_code);

  DCHECK_EQ(MountError::kInProgress, data_.error);
  data_.error = ConvertLauncherExitCodeToMountError(exit_code);
  DCHECK_NE(MountError::kInProgress, data_.error);

  if (exit_code != 0 && process_ && !LOG_IS_ON(INFO)) {
    for (const auto& s : process_->GetCapturedOutput()) {
      LOG(ERROR) << process_->GetProgramName() << "[" << process_->pid()
                 << "]: " << s;
    }
  }

  if (launcher_exit_callback_)
    std::move(launcher_exit_callback_).Run(data_.error);
}

bool MountPoint::ParseProgressMessage(base::StringPiece message,
                                      int* const percent) {
  if (message.empty() || message.back() != '%')
    return false;

  // |message| ends with a percent sign '%'
  message.remove_suffix(1);

  // Extract the number before the percent sign.
  base::StringPiece::size_type i = message.size();
  while (i > 0 && base::IsAsciiDigit(message[i - 1]))
    i--;
  message.remove_prefix(i);

  DCHECK(percent);
  return base::StringToInt(message, percent) && *percent >= 0 &&
         *percent <= 100;
}

void MountPoint::OnProgress(const base::StringPiece message) {
  int percent;
  if (!ParseProgressMessage(message, &percent))
    return;

  progress_percent_ = percent;
  if (progress_callback_)
    progress_callback_.Run(this);
}

void MountPoint::SetProcess(std::unique_ptr<Process> process,
                            Metrics* const metrics,
                            std::string metrics_name,
                            std::vector<int> password_needed_exit_codes) {
  DCHECK(!process_);
  process_ = std::move(process);
  DCHECK(process_);

  DCHECK(!metrics_);
  metrics_ = metrics;
  DCHECK(metrics_name_.empty());
  metrics_name_ = std::move(metrics_name);

  password_needed_exit_codes_ = std::move(password_needed_exit_codes);

  DCHECK_EQ(MountError::kSuccess, data_.error);
  data_.error = MountError::kInProgress;

  process_->SetLauncherExitCallback(
      base::BindOnce(&MountPoint::OnLauncherExit, GetWeakPtr()));
  process_->SetOutputCallback(
      base::BindRepeating(&MountPoint::OnProgress, GetWeakPtr()));
}

}  // namespace cros_disks
