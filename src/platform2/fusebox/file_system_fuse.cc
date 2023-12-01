// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "fusebox/file_system.h"

namespace fusebox {

static void fs_init(void* userdata, struct fuse_conn_info* conn) {
  static_cast<FileSystem*>(userdata)->Init(userdata, conn);
}

static void fs_destroy(void* userdata) {
  static_cast<FileSystem*>(userdata)->Destroy(userdata);
}

inline FileSystem* fs(fuse_req_t req) {
  return static_cast<FileSystem*>(fuse_req_userdata(req));
}

static void fs_lookup(fuse_req_t req, fuse_ino_t parent, const char* name) {
  fs(req)->Lookup(std::make_unique<EntryRequest>(req), parent, name);
}

static void fs_forget(fuse_req_t req,
                      fuse_ino_t ino,
                      unsigned long nlookup) {  // NOLINT(runtime/int)
  fs(req)->Forget(std::make_unique<NoneRequest>(req), ino, nlookup);
}

static void fs_forget_multi(fuse_req_t req,
                            size_t count,
                            fuse_forget_data* forgets) {
  fs(req)->ForgetMulti(std::make_unique<NoneRequest>(req), count, forgets);
}

static void fs_getattr(fuse_req_t req,
                       fuse_ino_t ino,
                       struct fuse_file_info* fi) {
  fs(req)->GetAttr(std::make_unique<AttrRequest>(req, fi), ino);
}

static void fs_setattr(fuse_req_t req,
                       fuse_ino_t ino,
                       struct stat* attr,
                       int to_set,
                       struct fuse_file_info* fi) {
  fs(req)->SetAttr(std::make_unique<AttrRequest>(req, fi), ino, attr, to_set);
}

static void fs_mkdir(fuse_req_t req,
                     fuse_ino_t parent,
                     const char* name,
                     mode_t mode) {
  fs(req)->MkDir(std::make_unique<EntryRequest>(req), parent, name, mode);
}

static void fs_unlink(fuse_req_t req, fuse_ino_t parent, const char* name) {
  fs(req)->Unlink(std::make_unique<OkRequest>(req), parent, name);
}

static void fs_rmdir(fuse_req_t req, fuse_ino_t parent, const char* name) {
  fs(req)->RmDir(std::make_unique<OkRequest>(req), parent, name);
}

static void fs_rename(fuse_req_t req,
                      fuse_ino_t parent,
                      const char* name,
                      fuse_ino_t new_parent,
                      const char* new_name) {
  fs(req)->Rename(std::make_unique<OkRequest>(req), parent, name, new_parent,
                  new_name);
}

static void fs_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi) {
  fs(req)->Open(std::make_unique<OpenRequest>(req, fi), ino);
}

static void fs_read(fuse_req_t req,
                    fuse_ino_t ino,
                    size_t size,
                    off_t off,
                    struct fuse_file_info* fi) {
  fs(req)->Read(std::make_unique<BufferRequest>(req, fi), ino, size, off);
}

static void fs_write(fuse_req_t req,
                     fuse_ino_t ino,
                     const char* buf,
                     size_t size,
                     off_t off,
                     struct fuse_file_info* fi) {
  fs(req)->Write(std::make_unique<WriteRequest>(req, fi), ino, buf, size, off);
}

static void fs_release(fuse_req_t req,
                       fuse_ino_t ino,
                       struct fuse_file_info* fi) {
  fs(req)->Release(std::make_unique<OkRequest>(req, fi), ino);
}

static void fs_opendir(fuse_req_t req,
                       fuse_ino_t ino,
                       struct fuse_file_info* fi) {
  fs(req)->OpenDir(std::make_unique<OpenRequest>(req, fi), ino);
}

static void fs_readdir(fuse_req_t req,
                       fuse_ino_t ino,
                       size_t size,
                       off_t off,
                       struct fuse_file_info* fi) {
  fs(req)->ReadDir(std::make_unique<DirEntryRequest>(req, fi, size, off), ino,
                   off);
}

static void fs_releasedir(fuse_req_t req,
                          fuse_ino_t ino,
                          struct fuse_file_info* fi) {
  fs(req)->ReleaseDir(std::make_unique<OkRequest>(req, fi), ino);
}

static void fs_statfs(fuse_req_t req, fuse_ino_t ino) {
  fs(req)->GetFsattr(std::make_unique<FsattrRequest>(req));
}

static void fs_create(fuse_req_t req,
                      fuse_ino_t parent,
                      const char* name,
                      mode_t mode,
                      struct fuse_file_info* fi) {
  fs(req)->Create(std::make_unique<CreateRequest>(req, fi), parent, name, mode);
}

// static
fuse_lowlevel_ops FileSystem::FuseOps() {
  fuse_lowlevel_ops ops = {
      .init = fs_init,
      .destroy = fs_destroy,
      .lookup = fs_lookup,
      .forget = fs_forget,
      .getattr = fs_getattr,
      .setattr = fs_setattr,
      .mkdir = fs_mkdir,
      .unlink = fs_unlink,
      .rmdir = fs_rmdir,
      .rename = fs_rename,
      .open = fs_open,
      .read = fs_read,
      .write = fs_write,
      .release = fs_release,
      .opendir = fs_opendir,
      .readdir = fs_readdir,
      .releasedir = fs_releasedir,
      .statfs = fs_statfs,
      .create = fs_create,
      .forget_multi = fs_forget_multi,
  };

  return ops;
}

}  // namespace fusebox
