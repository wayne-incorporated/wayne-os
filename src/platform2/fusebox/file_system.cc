// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "fusebox/file_system.h"

namespace fusebox {

FileSystem::FileSystem() = default;

FileSystem::~FileSystem() = default;

inline void FuseNotImplemented(FuseRequest* req) {
  req && !req->IsInterrupted() && req->ReplyError(ENOSYS);
}

void FileSystem::Init(void* userdata, struct fuse_conn_info* conn) {
  FuseNotImplemented(nullptr);
}

void FileSystem::Destroy(void* userdata) {
  FuseNotImplemented(nullptr);
}

void FileSystem::Lookup(std::unique_ptr<EntryRequest> request,
                        ino_t parent,
                        const char* name) {
  FuseNotImplemented(request.get());
}

void FileSystem::Forget(std::unique_ptr<NoneRequest> request,
                        ino_t ino,
                        uint64_t nlookup) {
  FuseNotImplemented(request.get());
}

void FileSystem::ForgetMulti(std::unique_ptr<NoneRequest> request,
                             size_t count,
                             fuse_forget_data* forgets) {
  FuseNotImplemented(request.get());
}

void FileSystem::GetFsattr(std::unique_ptr<FsattrRequest> request) {
  FuseNotImplemented(request.get());
}

void FileSystem::GetAttr(std::unique_ptr<AttrRequest> request, ino_t ino) {
  FuseNotImplemented(request.get());
}

void FileSystem::SetAttr(std::unique_ptr<AttrRequest> request,
                         ino_t ino,
                         struct stat* attr,
                         int to_set) {
  FuseNotImplemented(request.get());
}

void FileSystem::MkDir(std::unique_ptr<EntryRequest> request,
                       ino_t parent,
                       const char* name,
                       mode_t mode) {
  FuseNotImplemented(request.get());
}

void FileSystem::Unlink(std::unique_ptr<OkRequest> request,
                        ino_t parent,
                        const char* name) {
  FuseNotImplemented(request.get());
}

void FileSystem::RmDir(std::unique_ptr<OkRequest> request,
                       ino_t parent,
                       const char* name) {
  FuseNotImplemented(request.get());
}

void FileSystem::Rename(std::unique_ptr<OkRequest> request,
                        ino_t parent,
                        const char* name,
                        ino_t new_parent,
                        const char* new_name) {
  FuseNotImplemented(request.get());
}

void FileSystem::Open(std::unique_ptr<OpenRequest> request, ino_t ino) {
  FuseNotImplemented(request.get());
}

void FileSystem::Read(std::unique_ptr<BufferRequest> request,
                      ino_t ino,
                      size_t size,
                      off_t off) {
  FuseNotImplemented(request.get());
}

void FileSystem::Write(std::unique_ptr<WriteRequest> request,
                       ino_t ino,
                       const char* buf,
                       size_t size,
                       off_t off) {
  FuseNotImplemented(request.get());
}

void FileSystem::Release(std::unique_ptr<OkRequest> request, ino_t ino) {
  FuseNotImplemented(request.get());
}

void FileSystem::OpenDir(std::unique_ptr<OpenRequest> request, ino_t ino) {
  FuseNotImplemented(request.get());
}

void FileSystem::ReadDir(std::unique_ptr<DirEntryRequest> request,
                         ino_t ino,
                         off_t off) {
  FuseNotImplemented(request.get());
}

void FileSystem::ReleaseDir(std::unique_ptr<OkRequest> request, ino_t ino) {
  FuseNotImplemented(request.get());
}

void FileSystem::Create(std::unique_ptr<CreateRequest> request,
                        ino_t parent,
                        const char* name,
                        mode_t mode) {
  FuseNotImplemented(request.get());
}

}  // namespace fusebox
