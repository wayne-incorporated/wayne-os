// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_CONTAINER_APPFUSE_APPFUSE_MOUNT_H_
#define ARC_CONTAINER_APPFUSE_APPFUSE_MOUNT_H_

#include <stdint.h>
#include <sys/types.h>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/memory/weak_ptr.h>

#include "arc/container/appfuse/data_filter.h"

namespace arc {
namespace appfuse {

// AppfuseMount represents a mountpoint for each appfuse mount.
class AppfuseMount {
 public:
  class Delegate {
   public:
    virtual ~Delegate() = default;

    // Called when this mount stops functioning because of an error.
    virtual void OnAppfuseMountAborted(AppfuseMount* mount) = 0;
  };

  AppfuseMount(const base::FilePath& mount_root,
               uid_t uid,
               int mount_id,
               Delegate* delegate);
  AppfuseMount(const AppfuseMount&) = delete;
  AppfuseMount& operator=(const AppfuseMount&) = delete;

  ~AppfuseMount();

  uid_t uid() const { return uid_; }
  int mount_id() const { return mount_id_; }

  // Mounts an appfuse file system and returns the filtered /dev/fuse FD
  // associated with the mounted appfuse file system.
  base::ScopedFD Mount();

  // Unmounts the appfuse file system and returns true on success.
  bool Unmount();

  // Opens a file in the appfuse file system.
  base::ScopedFD OpenFile(int file_id, int flags);

 private:
  void OnDataFilterStopped();

  const base::FilePath mount_root_;
  const uid_t uid_;
  const int mount_id_;
  Delegate* const delegate_;
  const base::FilePath mount_point_;

  DataFilter data_filter_;

  base::WeakPtrFactory<AppfuseMount> weak_ptr_factory_;
};

}  // namespace appfuse
}  // namespace arc

#endif  // ARC_CONTAINER_APPFUSE_APPFUSE_MOUNT_H_
