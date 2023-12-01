// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_MOUNT_POINT_H_
#define CROS_DISKS_MOUNT_POINT_H_

#include <sys/mount.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest_prod.h>

#include "cros-disks/metrics.h"
#include "cros-disks/process.h"

namespace cros_disks {

// Holds information about a mount point.
struct MountPointData {
  // Mount point path.
  base::FilePath mount_path;
  // Source description used to mount.
  std::string source;
  // Source type.
  MountSourceType source_type = MOUNT_SOURCE_INVALID;
  // Filesystem type of the mount.
  std::string filesystem_type;
  // Flags of the mount point.
  uint64_t flags = 0;
  // Additional data passed during mount.
  std::string data;
  // Error state associated to this mount point.
  MountError error = MountError::kSuccess;
};

class Platform;

// Class representing a mount created by a mounter.
class MountPoint final {
 public:
  // Creates a MountPoint that is not actually mounted.
  static std::unique_ptr<MountPoint> CreateUnmounted(
      MountPointData data, const Platform* platform = nullptr);

  // Mounts a mount point. Returns a null pointer and sets *error in case of
  // error.
  static std::unique_ptr<MountPoint> Mount(MountPointData data,
                                           const Platform* platform,
                                           MountError* error);

  explicit MountPoint(MountPointData data, const Platform* platform = nullptr);

  MountPoint(const MountPoint&) = delete;
  MountPoint& operator=(const MountPoint&) = delete;

  // Unmounts the mount point as a last resort, but as it's unable to handle
  // errors an explicit call to Unmount() is the better alternative.
  ~MountPoint() { Unmount(); }

  base::WeakPtr<MountPoint> GetWeakPtr() { return weak_factory_.GetWeakPtr(); }

  // Unmounts right now.
  MountError Unmount();

  // Remount with specified ro/rw.
  MountError Remount(bool read_only);

  // Associates a Process object to this MountPoint.
  void SetProcess(std::unique_ptr<Process> process,
                  Metrics* const metrics,
                  std::string metrics_name,
                  std::vector<int> password_needed_exit_codes);

  // Sets the eject action, that will be called when this mount point is
  // successfully unmounted.
  void SetEject(base::OnceClosure eject) {
    DCHECK(!eject_);
    eject_ = std::move(eject);
    DCHECK(eject_);
  }

  // Callback called when the FUSE 'launcher' process finished.
  using LauncherExitCallback = base::OnceCallback<void(MountError)>;
  void SetLauncherExitCallback(LauncherExitCallback callback) {
    DCHECK(!launcher_exit_callback_);
    launcher_exit_callback_ = std::move(callback);
    DCHECK(launcher_exit_callback_);
  }

  // Callback called when the FUSE 'launcher' process is signaling progress.
  using ProgressCallback = base::RepeatingCallback<void(const MountPoint*)>;
  void SetProgressCallback(ProgressCallback callback) {
    progress_callback_ = std::move(callback);
  }

  // Sets the source and source type.
  void SetSource(std::string source, MountSourceType source_type) {
    data_.source = std::move(source);
    DCHECK_EQ(MOUNT_SOURCE_INVALID, data_.source_type);
    data_.source_type = source_type;
    DCHECK_NE(MOUNT_SOURCE_INVALID, data_.source_type);
  }

  const base::FilePath& path() const { return data_.mount_path; }
  const std::string& source() const { return data_.source; }
  MountSourceType source_type() const { return data_.source_type; }
  const std::string& fstype() const { return data_.filesystem_type; }
  uint64_t flags() const { return data_.flags; }
  const std::string& data() const { return data_.data; }
  MountError error() const { return data_.error; }
  bool is_read_only() const { return (data_.flags & MS_RDONLY) != 0; }
  bool is_mounted() const { return is_mounted_; }
  Process* process() const { return process_.get(); }
  int progress_percent() const { return progress_percent_; }

 private:
  // Converts the FUSE launcher's exit code into a MountErrorType.
  MountError ConvertLauncherExitCodeToMountError(int exit_code) const;

  // Called when the 'launcher' process finished.
  void OnLauncherExit(int exit_code);

  // Called every time the 'launcher' process prints a (potential) progress
  // message.
  void OnProgress(base::StringPiece message);

  // Parses a (potential) progress message. Returns true if the message was
  // correctly parsed. Stores the progress percentage into |*percent|.
  // A progress message is considered valid if:
  // 1. It ends with a percent sign %
  // 2. The percent sign is preceded by at least one digit.
  // 3. The sequence of digits before the percent sign form a number between 0
  //    and 100 (included).
  static bool ParseProgressMessage(base::StringPiece message, int* percent);

  // Mount point data.
  MountPointData data_;

  // Pointer to Platform implementation.
  const Platform* const platform_;

  // Process object holding the FUSE processes associated to this MountPoint.
  std::unique_ptr<Process> process_;

  // Eject action called after successfully unmounting this mount point.
  base::OnceClosure eject_;

  // Metrics object and name used to record the FUSE launcher exit code.
  Metrics* metrics_ = nullptr;
  std::string metrics_name_;

  // Set of FUSE launcher exit codes that are interpreted as
  // MountError::kNeedPassword.
  std::vector<int> password_needed_exit_codes_;

  // Callback called when the FUSE 'launcher' process finished.
  LauncherExitCallback launcher_exit_callback_;

  // Progress percent.
  int progress_percent_ = 0;

  // Callback called when the FUSE 'launcher' process reports progress.
  ProgressCallback progress_callback_;

  // Is this mount point actually mounted?
  bool is_mounted_ = true;

  // Should the mount point directory be eventually removed?
  bool must_remove_dir_ = platform_ != nullptr;

  base::WeakPtrFactory<MountPoint> weak_factory_{this};

  FRIEND_TEST(MountPointTest, ParseProgressMessage);
  FRIEND_TEST(MountPointTest, ProgressCallback);
};

}  // namespace cros_disks

#endif  // CROS_DISKS_MOUNT_POINT_H_
