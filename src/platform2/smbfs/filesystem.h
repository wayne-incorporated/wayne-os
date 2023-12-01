// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBFS_FILESYSTEM_H_
#define SMBFS_FILESYSTEM_H_

#include <fuse_lowlevel.h>

#include <memory>
#include <optional>
#include <string>

#include "smbfs/request.h"

namespace smbfs {

// Base class for FUSE filesystems. Functions not overridden will respond to
// requests with the ENOSYS error.
class Filesystem {
 public:
  virtual ~Filesystem();

  virtual void StatFs(std::unique_ptr<StatFsRequest> request, fuse_ino_t inode);
  virtual void Lookup(std::unique_ptr<EntryRequest> request,
                      fuse_ino_t parent_inode,
                      const std::string& name);
  virtual void Forget(fuse_ino_t inode, uint64_t count);
  virtual void GetAttr(std::unique_ptr<AttrRequest> request, fuse_ino_t inode);
  virtual void SetAttr(std::unique_ptr<AttrRequest> request,
                       fuse_ino_t inode,
                       std::optional<uint64_t> file_handle,
                       const struct stat& attr,
                       int to_set);

  // File operations.
  virtual void Open(std::unique_ptr<OpenRequest> request,
                    fuse_ino_t inode,
                    int flags);
  virtual void Create(std::unique_ptr<CreateRequest> request,
                      fuse_ino_t parent_inode,
                      const std::string& name,
                      mode_t mode,
                      int flags);
  virtual void Read(std::unique_ptr<BufRequest> request,
                    fuse_ino_t inode,
                    uint64_t file_handle,
                    size_t size,
                    off_t offset);
  virtual void Write(std::unique_ptr<WriteRequest> request,
                     fuse_ino_t inode,
                     uint64_t file_handle,
                     const char* buf,
                     size_t size,
                     off_t offset);
  virtual void Release(std::unique_ptr<SimpleRequest> request,
                       fuse_ino_t inode,
                       uint64_t file_handle);
  virtual void Rename(std::unique_ptr<SimpleRequest> request,
                      fuse_ino_t old_parent_inode,
                      const std::string& old_name,
                      fuse_ino_t new_parent_inode,
                      const std::string& new_name);
  virtual void Unlink(std::unique_ptr<SimpleRequest> request,
                      fuse_ino_t parent_inode,
                      const std::string& name);

  // Directory operations.
  virtual void OpenDir(std::unique_ptr<OpenRequest> request,
                       fuse_ino_t inode,
                       int flags);
  virtual void ReadDir(std::unique_ptr<DirentryRequest> request,
                       fuse_ino_t inode,
                       uint64_t file_handle,
                       off_t offset);
  virtual void ReleaseDir(std::unique_ptr<SimpleRequest> request,
                          fuse_ino_t inode,
                          uint64_t file_handle);
  virtual void MkDir(std::unique_ptr<EntryRequest> request,
                     fuse_ino_t parent_inode,
                     const std::string& name,
                     mode_t mode);
  virtual void RmDir(std::unique_ptr<SimpleRequest> request,
                     fuse_ino_t parent_inode,
                     const std::string& name);

 protected:
  Filesystem();
  Filesystem(const Filesystem&) = delete;
  Filesystem& operator=(const Filesystem&) = delete;
};

}  // namespace smbfs

#endif  // SMBFS_FILESYSTEM_H_
