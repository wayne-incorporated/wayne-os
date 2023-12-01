// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbfs/request.h"

#include <errno.h>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <base/stl_util.h>

namespace smbfs {
namespace internal {

BaseRequest::BaseRequest(fuse_req_t req) : req_(req) {}

BaseRequest::~BaseRequest() {
  if (!replied_) {
    // If a reply was not sent, either because the request was interrupted or
    // the filesystem is being shut down, send an error reply so that the
    // request can be freed.
    fuse_reply_err(req_, EINTR);
  }
}

bool BaseRequest::IsInterrupted() const {
  return fuse_req_interrupted(req_);
}

void BaseRequest::ReplyError(int error) {
  DCHECK(!replied_);
  DCHECK_GT(error, 0);

  fuse_reply_err(req_, error);
  replied_ = true;
}

}  // namespace internal

void SimpleRequest::ReplyOk() {
  DCHECK(!replied_);

  fuse_reply_err(req_, 0);
  replied_ = true;
}

void StatFsRequest::ReplyStatFs(const struct statvfs& st) {
  DCHECK(!replied_);

  fuse_reply_statfs(req_, &st);
  replied_ = true;
}

void AttrRequest::ReplyAttr(const struct stat& attr, double attr_timeout) {
  DCHECK(!replied_);

  fuse_reply_attr(req_, &attr, attr_timeout);
  replied_ = true;
}

void EntryRequest::ReplyEntry(const fuse_entry_param& entry) {
  DCHECK(!replied_);

  fuse_reply_entry(req_, &entry);
  replied_ = true;
}

void OpenRequest::ReplyOpen(uint64_t file_handle) {
  DCHECK(!replied_);
  DCHECK_GT(file_handle, 0);

  fuse_file_info info = {0};
  info.fh = file_handle;
  fuse_reply_open(req_, &info);
  replied_ = true;
}

void CreateRequest::ReplyCreate(const fuse_entry_param& entry,
                                uint64_t file_handle) {
  DCHECK(!replied_);
  DCHECK_GT(file_handle, 0);

  fuse_file_info info = {0};
  info.fh = file_handle;
  fuse_reply_create(req_, &entry, &info);
  replied_ = true;
}

void BufRequest::ReplyBuf(const char* buf, size_t size) {
  DCHECK(!replied_);
  DCHECK(buf);

  fuse_reply_buf(req_, buf, size);
  replied_ = true;
}

void WriteRequest::ReplyWrite(size_t written) {
  DCHECK(!replied_);

  fuse_reply_write(req_, written);
  replied_ = true;
}

DirentryRequest::DirentryRequest(fuse_req_t req, size_t size)
    : internal::BaseRequest(req),
      size_(size),
      buf_(std::make_unique<char[]>(size)) {
  DCHECK(size_);
}

bool DirentryRequest::AddEntry(base::StringPiece name,
                               fuse_ino_t inode,
                               mode_t mode,
                               off_t next_offset) {
  CHECK(mode & S_IFREG || mode & S_IFDIR);
  CHECK_EQ(name.find('/'), base::StringPiece::npos);
  DCHECK_NE(name, ".");
  DCHECK_NE(name, "..");

  struct stat stat = {0};
  stat.st_ino = inode;
  stat.st_mode = mode;
  size_t remaining = size_ - off_;
  size_t used = fuse_add_direntry(req_, buf_.get() + off_, remaining,
                                  name.data(), &stat, next_offset);
  if (used > remaining) {
    return false;
  }
  off_ += used;
  return true;
}

void DirentryRequest::ReplyDone() {
  DCHECK(!replied_);

  fuse_reply_buf(req_, buf_.get(), off_);
  replied_ = true;
}

}  // namespace smbfs
