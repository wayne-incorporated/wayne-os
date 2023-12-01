// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Implements cros-disks::MountManager. See mount-manager.h for details.

#include "cros-disks/mount_manager.h"

#include <sys/mount.h>
#include <unistd.h>

#include <algorithm>
#include <unordered_set>
#include <utility>

#include <base/check.h>
#include <base/containers/contains.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <brillo/process/process_reaper.h>

#include "cros-disks/mount_options.h"
#include "cros-disks/platform.h"
#include "cros-disks/quote.h"
#include "cros-disks/uri.h"

namespace cros_disks {
namespace {

// Permissions to set on the mount root directory (u+rwx,og+rx).
const mode_t kMountRootDirectoryPermissions =
    S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
// Maximum number of trials on creating a mount directory using
// Platform::CreateOrReuseEmptyDirectoryWithFallback().
// A value of 100 seems reasonable and enough to handle directory name
// collisions under common scenarios.
const unsigned kMaxNumMountTrials = 100;

}  // namespace

MountManager::MountManager(const std::string& mount_root,
                           Platform* platform,
                           Metrics* metrics,
                           brillo::ProcessReaper* process_reaper)
    : mount_root_(base::FilePath(mount_root)),
      platform_(platform),
      metrics_(metrics),
      process_reaper_(process_reaper) {
  CHECK(!mount_root_.empty()) << "Invalid mount root directory";
  CHECK(mount_root_.IsAbsolute()) << "Mount root not absolute path";
  CHECK(platform_) << "Invalid platform object";
  CHECK(metrics_) << "Invalid metrics object";
}

MountManager::~MountManager() {
  // UnmountAll() should be called from a derived class instead of this base
  // class as UnmountAll() can be overridden.
  DCHECK(mount_points_.empty());
}

bool MountManager::Initialize() {
  return platform_->CreateDirectory(mount_root_.value()) &&
         platform_->SetOwnership(mount_root_.value(), getuid(), getgid()) &&
         platform_->SetPermissions(mount_root_.value(),
                                   kMountRootDirectoryPermissions) &&
         platform_->CleanUpStaleMountPoints(mount_root_.value());
}

void MountManager::StartSession() {}

void MountManager::StopSession() {
  UnmountAll();
}

void MountManager::Mount(const std::string& source,
                         const std::string& filesystem_type,
                         std::vector<std::string> options,
                         MountCallback mount_callback,
                         ProgressCallback progress_callback) {
  DCHECK(mount_callback);

  // Source is not necessary a path, but if it is let's resolve it to
  // some real underlying object.
  std::string real_path;
  if (Uri::IsUri(source) || !ResolvePath(source, &real_path)) {
    real_path = source;
  }

  if (real_path.empty()) {
    LOG(ERROR) << "Cannot mount an invalid path: " << redact(source);
    std::move(mount_callback)
        .Run(filesystem_type, "", MountError::kInvalidArgument, false);
    return;
  }

  if (RemoveParamsEqualTo(&options, "remount")) {
    // Remount an already-mounted drive.
    std::string mount_path;
    bool read_only = false;
    const MountError error =
        Remount(real_path, filesystem_type, std::move(options), &mount_path,
                &read_only);
    return std::move(mount_callback)
        .Run(filesystem_type, mount_path, error, read_only);
  }

  // Mount a new drive.
  MountNewSource(real_path, filesystem_type, std::move(options),
                 std::move(mount_callback), std::move(progress_callback));
}

MountError MountManager::Remount(const std::string& source,
                                 const std::string& /*filesystem_type*/,
                                 const std::vector<std::string>& options,
                                 std::string* const mount_path,
                                 bool* const read_only) {
  MountPoint* const mount_point = FindMountBySource(source);
  if (!mount_point) {
    LOG(WARNING) << "Not currently mounted: " << quote(source);
    return MountError::kPathNotMounted;
  }

  // Perform the underlying mount operation.
  if (const MountError error = mount_point->Remount(IsReadOnlyMount(options));
      error != MountError::kSuccess) {
    LOG(ERROR) << "Cannot remount " << quote(source) << ": " << error;
    return error;
  }

  *mount_path = mount_point->path().value();

  DCHECK_NE(read_only, nullptr);
  *read_only = mount_point->is_read_only();

  LOG(INFO) << "Remounted " << quote(source) << " on " << quote(*mount_path);
  return MountError::kSuccess;
}

void MountManager::MountNewSource(const std::string& source,
                                  const std::string& filesystem_type,
                                  std::vector<std::string> options,
                                  MountCallback mount_callback,
                                  ProgressCallback progress_callback) {
  DCHECK(mount_callback);

  if (const MountPoint* const mp = FindMountBySource(source)) {
    LOG(ERROR) << "Already mounted: " << redact(source)
               << " is already mounted as " << mp->fstype() << " "
               << redact(mp->path());
    return std::move(mount_callback)
        .Run(mp->fstype(), mp->path().value(), mp->error(), mp->is_read_only());
  }

  // Extract the mount label string from the passed options.
  std::string label;
  if (const base::StringPiece key = "mountlabel";
      GetParamValue(options, key, &label))
    RemoveParamsWithSameName(&options, key);

  // Create a directory and set up its ownership/permissions for mounting
  // the source path. If an error occurs, ShouldReserveMountPathOnError()
  // is not called to reserve the mount path as a reserved mount path still
  // requires a proper mount directory.
  base::FilePath mount_path;
  if (const MountError error =
          CreateMountPathForSource(source, label, &mount_path);
      error != MountError::kSuccess)
    return std::move(mount_callback).Run(filesystem_type, "", error, false);

  // Perform the underlying mount operation. If an error occurs,
  // ShouldReserveMountPathOnError() is called to check if the mount path
  // should be reserved.
  MountError error = MountError::kUnknownError;
  std::unique_ptr<MountPoint> mount_point =
      DoMount(source, filesystem_type, std::move(options), mount_path, &error);

  // Check for both mount_point and error here, since there might be (incorrect)
  // mounters that return no MountPoint and no error (crbug.com/1317877 and
  // crbug.com/1317878).
  if (!mount_point || error != MountError::kSuccess) {
    if (error == MountError::kSuccess) {
      LOG(ERROR) << "Mounter for " << filesystem_type << " " << redact(source)
                 << " returned no MountPoint and no error";
      error = MountError::kUnknownError;
    } else if (mount_point) {
      LOG(ERROR) << "Mounter for " << filesystem_type << " " << redact(source)
                 << " returned both a mount point and " << error;
      mount_point.reset();
    }

    if (!ShouldReserveMountPathOnError(error)) {
      platform_->RemoveEmptyDirectory(mount_path.value());
      return std::move(mount_callback).Run(filesystem_type, "", error, false);
    }

    DCHECK(!mount_point);
    // Create dummy mount point to associate with the mount path.
    mount_point = MountPoint::CreateUnmounted(
        {.mount_path = mount_path, .source = source, .error = error},
        platform_);
    LOG(INFO) << "Reserved mount path " << quote(mount_path) << " for "
              << quote(source);
  }

  DCHECK(mount_point);
  DCHECK_EQ(mount_point->path(), mount_path);

  // For some mounters, the string stored in |mount_point->source()| is
  // different from |source|.
  mount_point->SetSource(source, GetMountSourceType());

  if (const Process* const process = mount_point->process()) {
    // There is a FUSE process to monitor.
    process_reaper_->WatchForChild(
        FROM_HERE, process->pid(),
        base::BindOnce(&MountManager::OnSandboxedProcessExit,
                       base::Unretained(this), process->GetProgramName(),
                       mount_path, mount_point->fstype(),
                       mount_point->GetWeakPtr()));

    DCHECK(mount_callback);
    mount_point->SetLauncherExitCallback(base::BindOnce(
        &MountManager::OnLauncherExit, base::Unretained(this),
        std::move(mount_callback), mount_path, mount_point->GetWeakPtr()));
    mount_point->SetProgressCallback(std::move(progress_callback));
  } else {
    // There is no FUSE process.
    std::move(mount_callback)
        .Run(mount_point->fstype(), mount_path.value(), error,
             mount_point->is_read_only());
  }

  VLOG(1) << "Mounted " << redact(mount_point->source()) << " as "
          << mount_point->fstype() << " " << redact(mount_point->path());
  mount_points_.push_back(std::move(mount_point));
}

void MountManager::OnLauncherExit(
    MountCallback mount_callback,
    const base::FilePath& mount_path,
    const base::WeakPtr<const MountPoint> mount_point,
    const MountError error) {
  DCHECK(mount_callback);
  std::move(mount_callback)
      .Run(mount_point ? mount_point->fstype() : "", mount_path.value(), error,
           mount_point ? mount_point->is_read_only() : false);

  if (!mount_point)
    return;

  DCHECK_EQ(mount_path, mount_point->path());
  DCHECK_EQ(error, mount_point->error());
  DCHECK_NE(MountError::kInProgress, error);

  if (error != MountError::kSuccess)
    RemoveMount(mount_point.get());
}

MountError MountManager::Unmount(const std::string& path) {
  // Look for a matching mount point, either by source path or by mount path.
  MountPoint* const mount_point =
      FindMountBySource(path) ?: FindMountByMountPath(base::FilePath(path));
  if (!mount_point)
    return MountError::kPathNotMounted;

  if (const MountError error = mount_point->Unmount();
      mount_point->is_mounted())
    return error;

  RemoveMount(mount_point);
  return MountError::kSuccess;
}

void MountManager::UnmountAll() {
  mount_points_.clear();
}

bool MountManager::ResolvePath(const std::string& path,
                               std::string* real_path) {
  return platform_->GetRealPath(path, real_path);
}

MountPoint* MountManager::FindMountBySource(const std::string& source) const {
  for (const auto& mount_point : mount_points_) {
    DCHECK(mount_point);
    if (mount_point->source() == source)
      return mount_point.get();
  }
  return nullptr;
}

MountPoint* MountManager::FindMountByMountPath(
    const base::FilePath& path) const {
  for (const auto& mount_point : mount_points_) {
    DCHECK(mount_point);
    if (mount_point->path() == path)
      return mount_point.get();
  }
  return nullptr;
}

bool MountManager::RemoveMount(const MountPoint* const mount_point) {
  for (auto it = mount_points_.cbegin(); it != mount_points_.cend(); ++it) {
    if (it->get() == mount_point) {
      mount_points_.erase(it);
      return true;
    }
  }
  return false;
}

void MountManager::OnSandboxedProcessExit(
    const std::string& program_name,
    const base::FilePath& mount_path,
    const std::string& filesystem_type,
    const base::WeakPtr<MountPoint> mount_point,
    const siginfo_t& info) {
  DCHECK_EQ(SIGCHLD, info.si_signo);
  if (info.si_code != CLD_EXITED) {
    LOG(ERROR) << "Sandbox of FUSE program " << quote(program_name) << " for "
               << filesystem_type << " " << redact(mount_path)
               << " was killed by signal " << info.si_status << ": "
               << strsignal(info.si_status);
  } else if (mount_point) {
    LOG(ERROR) << "FUSE program " << quote(program_name) << " for "
               << filesystem_type << " " << redact(mount_path)
               << " finished unexpectedly with "
               << Process::ExitCode(info.si_status);

    if (metrics_)
      metrics_->RecordDaemonError(program_name, info.si_status);
  } else if (info.si_status) {
    LOG(ERROR) << "FUSE program " << quote(program_name) << " for "
               << filesystem_type << " " << redact(mount_path)
               << " finished with " << Process::ExitCode(info.si_status);
  } else {
    LOG(INFO) << "FUSE program " << quote(program_name) << " for "
              << filesystem_type << " " << redact(mount_path)
              << " finished normally";
  }

  if (!mount_point) {
    VLOG(1) << "Mount point " << filesystem_type << " " << redact(mount_path)
            << " was already removed";
    return;
  }

  DCHECK_EQ(mount_path, mount_point->path());
  RemoveMount(mount_point.get());
}

MountError MountManager::CreateMountPathForSource(const std::string& source,
                                                  const std::string& label,
                                                  base::FilePath* mount_path) {
  DCHECK(mount_path);
  DCHECK(mount_path->empty());

  *mount_path = base::FilePath(SuggestMountPath(source));
  if (!label.empty()) {
    // Replace the basename(|actual_mount_path|) with |label|.
    *mount_path = mount_path->DirName().Append(label);
  }

  if (!IsValidMountPath(*mount_path)) {
    LOG(ERROR) << "Mount path " << quote(*mount_path) << " is invalid";
    return MountError::kInvalidPath;
  }

  std::unordered_set<std::string> reserved_paths;
  reserved_paths.reserve(mount_points_.size());
  for (const auto& mount_point : mount_points_) {
    reserved_paths.insert(mount_point->path().value());
  }

  std::string path = mount_path->value();
  if (!platform_->CreateOrReuseEmptyDirectoryWithFallback(
          &path, kMaxNumMountTrials, reserved_paths)) {
    LOG(ERROR) << "Cannot create directory " << quote(*mount_path)
               << " to mount " << quote(source);
    return MountError::kDirectoryCreationFailed;
  }

  *mount_path = base::FilePath(path);
  return MountError::kSuccess;
}

std::vector<const MountPoint*> MountManager::GetMountPoints() const {
  std::vector<const MountPoint*> mount_points;
  mount_points.reserve(mount_points_.size());
  for (const std::unique_ptr<MountPoint>& mount_point : mount_points_) {
    DCHECK(mount_point);
    DCHECK_EQ(mount_point->source_type(), GetMountSourceType());
    mount_points.push_back(mount_point.get());
  }
  return mount_points;
}

bool MountManager::ShouldReserveMountPathOnError(MountError error) const {
  return false;
}

bool MountManager::IsPathImmediateChildOfParent(const base::FilePath& path,
                                                const base::FilePath& parent) {
  std::vector<std::string> path_components =
      path.StripTrailingSeparators().GetComponents();
  std::vector<std::string> parent_components =
      parent.StripTrailingSeparators().GetComponents();
  if (path_components.size() != parent_components.size() + 1)
    return false;

  if (path_components.back() == base::FilePath::kCurrentDirectory ||
      path_components.back() == base::FilePath::kParentDirectory) {
    return false;
  }

  return std::equal(parent_components.begin(), parent_components.end(),
                    path_components.begin());
}

bool MountManager::IsValidMountPath(const base::FilePath& mount_path) const {
  return IsPathImmediateChildOfParent(mount_path, mount_root_);
}

}  // namespace cros_disks
