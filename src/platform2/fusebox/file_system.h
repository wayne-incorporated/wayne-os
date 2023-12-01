// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FUSEBOX_FILE_SYSTEM_H_
#define FUSEBOX_FILE_SYSTEM_H_

#include <memory>

#include "fusebox/fuse_request.h"

// FileSystem interface to process Kernel FUSE requests.

namespace fusebox {

class FileSystem {
 public:
  FileSystem();
  FileSystem(const FileSystem&) = delete;
  FileSystem& operator=(const FileSystem&) = delete;
  virtual ~FileSystem();

  // FUSE lowlevel API: see <fuse_lowlevel.h> for API details.

  virtual void Init(void* userdata, struct fuse_conn_info* conn);

  virtual void Destroy(void* userdata);

  virtual void Lookup(std::unique_ptr<EntryRequest> request,
                      ino_t parent,
                      const char* name);

  virtual void Forget(std::unique_ptr<NoneRequest> request,
                      ino_t ino,
                      uint64_t nlookup);

  virtual void ForgetMulti(std::unique_ptr<NoneRequest> request,
                           size_t count,
                           fuse_forget_data* forgets);

  virtual void GetFsattr(std::unique_ptr<FsattrRequest> request);

  virtual void GetAttr(std::unique_ptr<AttrRequest> request, ino_t ino);

  virtual void SetAttr(std::unique_ptr<AttrRequest> request,
                       ino_t ino,
                       struct stat* attr,
                       int to_set);

  virtual void MkDir(std::unique_ptr<EntryRequest> request,
                     ino_t parent,
                     const char* name,
                     mode_t mode);

  virtual void Unlink(std::unique_ptr<OkRequest> request,
                      ino_t parent,
                      const char* name);

  virtual void RmDir(std::unique_ptr<OkRequest> request,
                     ino_t parent,
                     const char* name);

  virtual void Rename(std::unique_ptr<OkRequest> request,
                      ino_t parent,
                      const char* name,
                      ino_t new_parent,
                      const char* new_name);

  virtual void Open(std::unique_ptr<OpenRequest> request, ino_t ino);

  virtual void Read(std::unique_ptr<BufferRequest> request,
                    ino_t ino,
                    size_t size,
                    off_t off);

  virtual void Write(std::unique_ptr<WriteRequest> request,
                     ino_t ino,
                     const char* buf,
                     size_t size,
                     off_t off);

  virtual void Release(std::unique_ptr<OkRequest> request, ino_t ino);

  virtual void OpenDir(std::unique_ptr<OpenRequest> request, ino_t ino);

  virtual void ReadDir(std::unique_ptr<DirEntryRequest> request,
                       ino_t ino,
                       off_t off);

  virtual void ReleaseDir(std::unique_ptr<OkRequest> request, ino_t ino);

  virtual void Create(std::unique_ptr<CreateRequest> request,
                      ino_t parent,
                      const char* name,
                      mode_t mode);

  static fuse_lowlevel_ops FuseOps();
};

}  // namespace fusebox

#endif  // FUSEBOX_FILE_SYSTEM_H_
