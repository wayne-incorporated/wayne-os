// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "fusebox/fuse_request.h"

#include <utility>

#include <base/check.h>
#include <base/check_op.h>

namespace fusebox {

FuseRequest::FuseRequest(fuse_req_t req, fuse_file_info* fi) : req_(req) {
  flags_ = fi ? fi->flags : 0;
  fh_ = fi ? fi->fh : 0;
}

bool FuseRequest::IsInterrupted() const {  // Kernel FUSE interrupt
  return fuse_req_interrupted(req_);
}

FuseRequest::~FuseRequest() {
  if (!replied_)
    fuse_reply_err(req_, EINTR);  // User-space FUSE interrupt
}

int FuseRequest::ReplyError(int error) {
  DCHECK(!replied_);
  DCHECK_GT(error, 0);
  fuse_reply_err(req_, error);
  replied_ = true;
  return error;
}

void OkRequest::ReplyOk() {
  DCHECK(!replied_);
  fuse_reply_err(req_, 0);
  replied_ = true;
}

void NoneRequest::ReplyNone() {
  DCHECK(!replied_);
  fuse_reply_none(req_);
  replied_ = true;
}

void AttrRequest::ReplyAttr(const struct stat& attr, double timeout) {
  DCHECK(!replied_);
  fuse_reply_attr(req_, &attr, timeout);
  replied_ = true;
}

void FsattrRequest::ReplyFsattr(const struct statvfs& fs_attr) {
  DCHECK(!replied_);
  fuse_reply_statfs(req_, &fs_attr);
  replied_ = true;
}

void EntryRequest::ReplyEntry(const fuse_entry_param& entry) {
  DCHECK(!replied_);
  fuse_reply_entry(req_, &entry);
  replied_ = true;
}

void OpenRequest::ReplyOpen(uint64_t fh) {
  DCHECK(!replied_);
  replied_ = true;

  DCHECK_NE(0, fh);
  fuse_file_info fi = {0};
  fi.fh = fh;

  if (create_) {
    DCHECK_GT(entry_.ino, FUSE_ROOT_ID);
    fuse_reply_create(req_, &entry_, &fi);
  } else {
    fuse_reply_open(req_, &fi);
  }
}

void CreateRequest::ReplyCreate(const fuse_entry_param& entry, uint64_t fh) {
  DCHECK(!replied_);
  replied_ = true;

  DCHECK_NE(0, fh);
  fuse_file_info fi = {0};
  fi.fh = fh;

  DCHECK(create_);
  fuse_reply_create(req_, &entry, &fi);
}

void BufferRequest::ReplyBuffer(const void* data, size_t size) {
  DCHECK(!replied_);
  replied_ = true;

  if (data) {
    fuse_reply_buf(req_, static_cast<const char*>(data), size);
  } else {
    fuse_reply_buf(req_, nullptr, 0);
  }
}

void WriteRequest::ReplyWrite(size_t count) {
  DCHECK(!replied_);
  fuse_reply_write(req_, count);
  replied_ = true;
}

DirEntryRequest::DirEntryRequest(fuse_req_t req,
                                 fuse_file_info* fi,
                                 size_t buf_size,
                                 off_t dir_offset)
    : FuseRequest(req, fi), buf_size_(buf_size), dir_offset_(dir_offset) {
  DCHECK(buf_size_);
}

bool DirEntryRequest::AddEntry(const struct DirEntry& entry, off_t dir_offset) {
  DCHECK(!replied_);

  const char* name = entry.name.c_str();
  struct stat stat = {0};
  stat.st_ino = entry.ino;
  stat.st_mode = entry.mode;

  if (!buf_.get()) {
    buf_ = std::make_unique<char[]>(buf_size_);
    CHECK(buf_.get());
    buf_offset_ = 0;
  }

  char* data = buf_.get() + buf_offset_;
  const size_t size = buf_size_ - buf_offset_;
  size_t used = fuse_add_direntry(req_, data, size, name, &stat, dir_offset);
  if (used > size)
    return false;  // no |buf_| space.

  buf_offset_ += used;
  CHECK_LE(buf_offset_, buf_size_);
  dir_offset_ = dir_offset;
  return true;
}

void DirEntryRequest::ReplyDone() {
  DCHECK(!replied_);
  fuse_reply_buf(req_, buf_.get(), buf_offset_);
  replied_ = true;
}

DirEntryBuffer::DirEntryBuffer() = default;

void DirEntryBuffer::AppendRequest(std::unique_ptr<DirEntryRequest> request) {
  request_.emplace_back(std::move(request));
  Respond();
}

void DirEntryBuffer::AppendResponse(std::vector<struct DirEntry> entry,
                                    bool end) {
  entry_.insert(entry_.end(), entry.begin(), entry.end());
  end_ = end;
  Respond();
}

int DirEntryBuffer::AppendResponse(int error) {
  error_ = error;
  Respond();
  return error;
}

void DirEntryBuffer::Respond() {
  constexpr size_t kFlushAddedEntries = 25;

  const auto process_next_request = [&](auto& request) {
    if (request->IsInterrupted())
      return true;

    if (error_) {
      request->ReplyError(error_);
      return true;
    }

    off_t dir_offset = request->dir_offset();
    if (dir_offset < 0) {
      request->ReplyError(EINVAL);
      return true;
    }

    size_t added;
    for (added = 0; dir_offset < entry_.size(); ++added) {
      const off_t next = 1 + dir_offset;
      if (request->AddEntry(entry_[dir_offset++], next))
        continue;  // add next entry
      request->ReplyDone();
      return true;
    }

    DCHECK_GE(dir_offset, entry_.size());
    bool done = end_ || added >= kFlushAddedEntries;
    if (done)
      request->ReplyDone();
    return done;
  };

  while (!request_.empty()) {
    if (!process_next_request(*request_.begin()))
      break;
    request_.erase(request_.begin());
  }
}

}  // namespace fusebox
