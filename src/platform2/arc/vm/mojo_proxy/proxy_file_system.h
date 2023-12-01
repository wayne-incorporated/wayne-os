// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_MOJO_PROXY_PROXY_FILE_SYSTEM_H_
#define ARC_VM_MOJO_PROXY_PROXY_FILE_SYSTEM_H_

#include <fuse/fuse.h>
#include <fuse/fuse_lowlevel.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <map>
#include <memory>
#include <optional>
#include <string>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/functional/callback.h>
#include <base/memory/ref_counted.h>
#include <base/synchronization/lock.h>

#include "arc/vm/mojo_proxy/mojo_proxy.h"

namespace base {
class TaskRunner;
}  // namespace base

namespace arc {

class FuseMount;

// FUSE implementation to support regular file descriptor passing.
// This is designed to be used only in the host side.
class ProxyFileSystem {
 public:
  class Delegate {
   public:
    virtual ~Delegate() = default;

    using PreadCallback = MojoProxy::PreadCallback;
    using PwriteCallback = MojoProxy::PwriteCallback;
    using FstatCallback = MojoProxy::FstatCallback;
    using FtruncateCallback = MojoProxy::FtruncateCallback;

    // Implement these methods to handle file operation requests.
    virtual void Pread(int64_t handle,
                       uint64_t count,
                       uint64_t offset,
                       PreadCallback callback) = 0;
    virtual void Pwrite(int64_t handle,
                        std::string blbo,
                        uint64_t offset,
                        PwriteCallback callback) = 0;
    virtual void Close(int64_t handle) = 0;
    virtual void Fstat(int64_t handle, FstatCallback callback) = 0;
    virtual void Ftruncate(int64_t handle,
                           int64_t length,
                           FtruncateCallback callback) = 0;
  };
  // |mount_path| is the path to the mount point.
  ProxyFileSystem(Delegate* delegate,
                  scoped_refptr<base::TaskRunner> delegate_task_runner,
                  const base::FilePath& mount_path);
  ~ProxyFileSystem();

  ProxyFileSystem(const ProxyFileSystem&) = delete;
  ProxyFileSystem& operator=(const ProxyFileSystem&) = delete;

  // Initializes this object.
  bool Init();

  // Implementation of the fuse operation callbacks.
  void Lookup(fuse_req_t req, fuse_ino_t parent, const char* name);
  void GetAttr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi);
  void SetAttr(fuse_req_t req,
               fuse_ino_t ino,
               struct stat* attr,
               int to_set,
               struct fuse_file_info* fi);
  void Open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi);
  void Read(fuse_req_t req,
            fuse_ino_t ino,
            size_t size,
            off_t off,
            struct fuse_file_info* fi);
  void Write(fuse_req_t req,
             fuse_ino_t ino,
             const char* buf,
             size_t size,
             off_t off,
             struct fuse_file_info* fi);
  void Release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi);
  void ReadDir(fuse_req_t req,
               fuse_ino_t ino,
               size_t size,
               off_t off,
               struct fuse_file_info* fi);

  // Registers the given |handle| to the file system, then returns the file
  // descriptor corresponding to the registered file.
  // Operations for the returned file descriptor will be directed to the
  // fuse operation implementation declared above.
  base::ScopedFD RegisterHandle(int64_t handle, int32_t flags);

 private:
  // Helper to operate GetAttr(). Called on the |delegate_task_runner_|.
  void GetAttrInternal(fuse_req_t req, int64_t handle, struct stat stat);

  // Helper to operate SetAttr(). Called on the |delegate_task_runner_|.
  void SetAttrInternal(fuse_req_t req, int64_t handle, struct stat stat);

  // Helper to operate Read(). Called on the |delegate_task_runner_|.
  void ReadInternal(fuse_req_t req, int64_t handle, size_t size, off_t off);

  // Helper to operate Write(). Called on the |delegate_task_runner_|.
  void WriteInternal(fuse_req_t req,
                     int64_t handle,
                     std::string blob,
                     off_t off);

  // Returns the state of the given inode.
  // If not registered, std::nullopt is returned.
  struct State {
    int64_t handle = 0;
    bool is_open = false;
  };
  std::optional<State> GetState(fuse_ino_t inode);

  Delegate* const delegate_;
  scoped_refptr<base::TaskRunner> delegate_task_runner_;
  const base::FilePath mount_path_;

  std::unique_ptr<FuseMount> fuse_mount_;

  std::map<fuse_ino_t, State> inode_to_state_ GUARDED_BY(inode_lock_);
  fuse_ino_t next_inode_ GUARDED_BY(inode_lock_) =
      2;  // 1 is reserved for the root directory.
  base::Lock inode_lock_;

  scoped_refptr<base::TaskRunner> init_task_runner_;
};

}  // namespace arc

#endif  // ARC_VM_MOJO_PROXY_PROXY_FILE_SYSTEM_H_
