// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbfs/filesystem.h"

#include <errno.h>

#include <optional>

namespace smbfs {

Filesystem::Filesystem() = default;

Filesystem::~Filesystem() = default;

void Filesystem::StatFs(std::unique_ptr<StatFsRequest> request,
                        fuse_ino_t inode) {
  request->ReplyError(ENOSYS);
}

void Filesystem::Lookup(std::unique_ptr<EntryRequest> request,
                        fuse_ino_t parent_inode,
                        const std::string& name) {
  request->ReplyError(ENOSYS);
}

void Filesystem::Forget(fuse_ino_t inode, uint64_t count) {}

void Filesystem::GetAttr(std::unique_ptr<AttrRequest> request,
                         fuse_ino_t inode) {
  request->ReplyError(ENOSYS);
}

void Filesystem::SetAttr(std::unique_ptr<AttrRequest> request,
                         fuse_ino_t inode,
                         std::optional<uint64_t> file_handle,
                         const struct stat& attr,
                         int to_set) {
  request->ReplyError(ENOSYS);
}

void Filesystem::Open(std::unique_ptr<OpenRequest> request,
                      fuse_ino_t inode,
                      int flags) {
  request->ReplyError(ENOSYS);
}

void Filesystem::Create(std::unique_ptr<CreateRequest> request,
                        fuse_ino_t parent_inode,
                        const std::string& name,
                        mode_t mode,
                        int flags) {
  request->ReplyError(ENOSYS);
}

void Filesystem::Read(std::unique_ptr<BufRequest> request,
                      fuse_ino_t inode,
                      uint64_t file_handle,
                      size_t size,
                      off_t offset) {
  request->ReplyError(ENOSYS);
}

void Filesystem::Write(std::unique_ptr<WriteRequest> request,
                       fuse_ino_t inode,
                       uint64_t file_handle,
                       const char* buf,
                       size_t size,
                       off_t offset) {
  request->ReplyError(ENOSYS);
}

void Filesystem::Release(std::unique_ptr<SimpleRequest> request,
                         fuse_ino_t inode,
                         uint64_t file_handle) {
  request->ReplyError(ENOSYS);
}

void Filesystem::Rename(std::unique_ptr<SimpleRequest> request,
                        fuse_ino_t old_parent_inode,
                        const std::string& old_name,
                        fuse_ino_t new_parent_inode,
                        const std::string& new_name) {
  request->ReplyError(ENOSYS);
}

void Filesystem::Unlink(std::unique_ptr<SimpleRequest> request,
                        fuse_ino_t parent_inode,
                        const std::string& name) {
  request->ReplyError(ENOSYS);
}

void Filesystem::OpenDir(std::unique_ptr<OpenRequest> request,
                         fuse_ino_t inode,
                         int flags) {
  request->ReplyError(ENOSYS);
}

void Filesystem::ReadDir(std::unique_ptr<DirentryRequest> request,
                         fuse_ino_t inode,
                         uint64_t file_handle,
                         off_t offset) {
  request->ReplyError(ENOSYS);
}

void Filesystem::ReleaseDir(std::unique_ptr<SimpleRequest> request,
                            fuse_ino_t inode,
                            uint64_t file_handle) {
  request->ReplyError(ENOSYS);
}

void Filesystem::MkDir(std::unique_ptr<EntryRequest> request,
                       fuse_ino_t parent_inode,
                       const std::string& name,
                       mode_t mode) {
  request->ReplyError(ENOSYS);
}

void Filesystem::RmDir(std::unique_ptr<SimpleRequest> request,
                       fuse_ino_t parent_inode,
                       const std::string& name) {
  request->ReplyError(ENOSYS);
}

}  // namespace smbfs
