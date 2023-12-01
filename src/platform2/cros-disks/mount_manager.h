// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Defines cros-disks::MountManager, which is a base class for implementing
// the filesystem mounting service used by CrosDisksServer. It is further
// subclassed to provide the mounting service for particular types of
// filesystem.

#ifndef CROS_DISKS_MOUNT_MANAGER_H_
#define CROS_DISKS_MOUNT_MANAGER_H_

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <sys/wait.h>

#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest_prod.h>

#include "cros-disks/mount_point.h"

namespace brillo {
class ProcessReaper;
}  // namespace brillo

namespace cros_disks {

class Metrics;
class Platform;

// A base class for managing mounted filesystems of certain kinds.
// It provides template methods for mounting and unmounting filesystems.
// A derived class implements pure virtual methods CanMount, DoMount, and
// SuggestMountPath to provide specific operations for supporting certain kinds
// of filesystem.
class MountManager {
 public:
  // Constructor that takes a mount root directory, an object for providing
  // platform service, and an object for collecting UMA metrics. The mount
  // root directory |mount_root| must be a non-empty path string, but it is
  // OK if the directory does not exist. Both |platform| and |metrics| must
  // be a valid object. An instance of this class does not take ownership
  // of the |platform| and |metrics| object, and thus expects these objects
  // to exist until its destruction. No actual operation is performed at
  // construction. Initialization is performed when Initializes() is called.
  MountManager(const std::string& mount_root,
               Platform* platform,
               Metrics* metrics,
               brillo::ProcessReaper* process_reaper);
  MountManager(const MountManager&) = delete;
  MountManager& operator=(const MountManager&) = delete;

  // Destructor that performs no specific operations and does not unmount
  // any mounted or reserved mount paths. A derived class should override
  // the destructor to perform appropriate cleanup, such as unmounting
  // mounted filesystems.
  virtual ~MountManager();

  // Initializes the mount manager. Returns true on success.
  // It must be called only once before other methods are called.
  // This base class provides a default implementation that creates the
  // mount root directory. A derived class can override this method to
  // perform any necessary initialization.
  virtual bool Initialize();

  // Starts a session. This method is called in response to a
  // SessionStateChanged event from the Chromium OS session manager.
  void StartSession();

  // Stops a session. This method is called in response to a SessionStateChanged
  // event from the Chromium OS session manager.
  void StopSession();

  // Implemented by a derived class to return true if it supports mounting
  // |source|.
  virtual bool CanMount(const std::string& source) const = 0;

  // Implemented by a derived class to return the type of mount sources
  // it supports.
  virtual MountSourceType GetMountSourceType() const = 0;

  // Callback called when the mount operation succeeds or fails.
  using MountCallback = base::OnceCallback<void(const std::string& fs_type,
                                                const std::string& mount_path,
                                                MountError error,
                                                bool read_only)>;

  // Callback called when the FUSE 'launcher' process is signaling progress.
  using ProgressCallback = MountPoint::ProgressCallback;

  // Mounts |source| as |filesystem_type| with |options|. If "remount"
  // option exists in |options|, attempts to remount |source| to the mount
  // path which it's currently mounted to. Otherwise, attempts to mount a new
  // source. When mounting a new source, |SuggestMountPath()| is called to
  // obtain a suggested mount path. If an error occurs and
  // |ShouldReserveMountPathOnError()| returns true for that type of error, the
  // mount path is reserved and |mount_path| is set to the reserved mount path.
  // On completion or on error, |mount_callback| is called.
  void Mount(const std::string& source,
             const std::string& filesystem_type,
             std::vector<std::string> options,
             MountCallback mount_callback,
             ProgressCallback progress_callback = {});

  // Unmounts |path|, which can be a source path or a mount path. If the mount
  // path is reserved during Mount(), this method releases the reserved mount
  // path.
  MountError Unmount(const std::string& path);

  // Unmounts all mounted paths.
  virtual void UnmountAll();

  // Gets the mount points owned by this mount manager.
  std::vector<const MountPoint*> GetMountPoints() const;

 protected:
  MountPoint* FindMountBySource(const std::string& source) const;
  MountPoint* FindMountByMountPath(const base::FilePath& path) const;
  bool RemoveMount(const MountPoint* mount_point);

  // The base class calls Platform::GetRealPath(), derived classes can override
  // it.
  virtual bool ResolvePath(const std::string& path, std::string* real_path);

  // Mounts |source| as |filesystem_type| with |options|.
  void MountNewSource(const std::string& source,
                      const std::string& filesystem_type,
                      std::vector<std::string> options,
                      MountCallback mount_callback,
                      ProgressCallback progress_callback);

  // Remounts |source| on |mount_path| as |filesystem_type| with |options|.
  MountError Remount(const std::string& source,
                     const std::string& filesystem_type,
                     const std::vector<std::string>& options,
                     std::string* mount_path,
                     bool* read_only);

  // Implemented by a derived class to mount |source| to |mount_path| as
  // |filesystem_type| with |options|. An implementation may append their own
  // mount options to |options|. On success, an implementation MUST set |error|
  // to MountError::kSuccess and return a non-null MountPoint. On failure,
  // |error| must be set to an appropriate error code and nullptr is returned.
  virtual std::unique_ptr<MountPoint> DoMount(
      const std::string& source,
      const std::string& filesystem_type,
      const std::vector<std::string>& options,
      const base::FilePath& mount_path,
      MountError* error) = 0;

  // Returns a suggested mount path for |source|.
  virtual std::string SuggestMountPath(const std::string& source) const = 0;

  // Returns true if the manager should reserve a mount path if the mount
  // operation returns a particular type of error. The default implementation
  // returns false on any error. A derived class should override this method
  // if it needs to reserve mount paths on certain types of error.
  virtual bool ShouldReserveMountPathOnError(MountError error_type) const;

  // Returns true if |path| is an immediate child of |parent|, i.e.
  // |path| is an immediate file or directory under |parent|.
  static bool IsPathImmediateChildOfParent(const base::FilePath& path,
                                           const base::FilePath& parent);

  // Returns true if |mount_path| is a valid mount path, which should be an
  // immediate child of the mount root specified by |mount_root_|. The check
  // performed by this method takes the simplest approach and does not first try
  // to canonicalize |mount_path|, resolve symlinks or determine the absolute
  // path of |mount_path|, so a legitimate mount path may be deemed as invalid.
  // But we don't consider these cases as part of the use cases of cros-disks.
  bool IsValidMountPath(const base::FilePath& mount_path) const;

  // Returns the root directory under which mount directories are created.
  const base::FilePath& mount_root() const { return mount_root_; }

  // Returns an object that provides platform service.
  Platform* platform() const { return platform_; }

  // Returns an object that collects UMA metrics.
  Metrics* metrics() const { return metrics_; }

  // Returns an object that monitors children processes.
  brillo::ProcessReaper* process_reaper() const { return process_reaper_; }

 private:
  // Prepares empty directory to mount into. If |mount_path| contains a path
  // it may be used, but not necessarily. Returns the status of the operation
  // and if successful - fills |mount_path|.
  MountError CreateMountPathForSource(const std::string& source,
                                      const std::string& label,
                                      base::FilePath* mount_path);

  // Called when the FUSE launcher process finishes.
  void OnLauncherExit(MountCallback mount_callback,
                      const base::FilePath& mount_path,
                      base::WeakPtr<const MountPoint> mount_point,
                      MountError error);

  // Called when the sandbox holding a FUSE process finishes.
  void OnSandboxedProcessExit(const std::string& program_name,
                              const base::FilePath& mount_path,
                              const std::string& filesystem_type,
                              const base::WeakPtr<MountPoint> mount_point,
                              const siginfo_t& info);

  // The root directory under which mount directories are created.
  const base::FilePath mount_root_;

  // An object that provides platform service.
  Platform* const platform_;

  // An object that collects UMA metrics.
  Metrics* const metrics_;

  // Object that monitors children processes.
  brillo::ProcessReaper* const process_reaper_;

  // Mount points, in no particular order.
  std::vector<std::unique_ptr<MountPoint>> mount_points_;

  friend class MountManagerUnderTest;

  FRIEND_TEST(MountManagerTest, ExtractMountLabelFromOptions);
  FRIEND_TEST(MountManagerTest, ExtractMountLabelFromOptionsWithNoMountLabel);
  FRIEND_TEST(MountManagerTest, ExtractMountLabelFromOptionsWithTwoMountLabels);
  FRIEND_TEST(MountManagerTest, IsPathImmediateChildOfParent);
  FRIEND_TEST(MountManagerTest, IsValidMountPath);
};

}  // namespace cros_disks

#endif  // CROS_DISKS_MOUNT_MANAGER_H_
