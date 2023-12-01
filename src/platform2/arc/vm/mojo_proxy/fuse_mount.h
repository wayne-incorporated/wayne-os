// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_MOJO_PROXY_FUSE_MOUNT_H_
#define ARC_VM_MOJO_PROXY_FUSE_MOUNT_H_

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_path.h>

struct fuse_chan;
struct fuse_session;
struct fuse_lowlevel_ops;

namespace arc {

// FuseMount mounts a FUSE file system on the specified path and dispatches
// incoming requests to the specified operation handler functions.
// FuseMount must be destroyed on the same thread where it was created.
class FuseMount {
 public:
  FuseMount(const base::FilePath& mount_path, const std::string& name);
  ~FuseMount();
  FuseMount(const FuseMount&) = delete;
  FuseMount& operator=(const FuseMount&) = delete;

  // Mounts and initializes the FUSE file system.
  bool Init(int argc,
            char* argv[],
            const struct fuse_lowlevel_ops& operations,
            void* private_data);

 private:
  // Handles incoming commands.
  void OnChannelReadable();

  const base::FilePath mount_path_;
  const std::string name_;

  struct fuse_chan* channel_ = nullptr;
  struct fuse_session* session_ = nullptr;
  std::vector<char> buf_;

  std::unique_ptr<base::FileDescriptorWatcher::Controller> watcher_;
};

}  // namespace arc

#endif  // ARC_VM_MOJO_PROXY_FUSE_MOUNT_H_
