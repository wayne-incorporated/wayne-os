// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBFS_REQUEST_H_
#define SMBFS_REQUEST_H_

#include <fuse_lowlevel.h>

#include <memory>

#include <base/strings/string_piece.h>

namespace smbfs {
namespace internal {

// Base class for maintaining state about a fuse request, and ensuring requests
// are responded to correctly.
class BaseRequest {
 public:
  BaseRequest() = delete;
  BaseRequest(const BaseRequest&) = delete;
  BaseRequest& operator=(const BaseRequest&) = delete;

  bool IsInterrupted() const;
  void ReplyError(int error);

 protected:
  explicit BaseRequest(fuse_req_t req);
  virtual ~BaseRequest();

  const fuse_req_t req_;
  bool replied_ = false;
};

}  // namespace internal

// State of fuse requests that can be responded to with a simple 'success'
// response.
class SimpleRequest : public internal::BaseRequest {
 public:
  explicit SimpleRequest(fuse_req_t req) : internal::BaseRequest(req) {}
  void ReplyOk();
};

// State of fuse requests that can be responded to with a statfs response.
class StatFsRequest : public internal::BaseRequest {
 public:
  explicit StatFsRequest(fuse_req_t req) : internal::BaseRequest(req) {}
  void ReplyStatFs(const struct statvfs& st);
};

// State of fuse requests that can be responded to with an attributes response.
class AttrRequest : public internal::BaseRequest {
 public:
  explicit AttrRequest(fuse_req_t req) : internal::BaseRequest(req) {}
  void ReplyAttr(const struct stat& attr, double attr_timeout);
};

// State of fuse requests that can be responded to with an entry response.
class EntryRequest : public internal::BaseRequest {
 public:
  explicit EntryRequest(fuse_req_t req) : internal::BaseRequest(req) {}
  void ReplyEntry(const fuse_entry_param& entry);
};

// State of fuse requests that can be responded to with an open file handle.
class OpenRequest : public internal::BaseRequest {
 public:
  explicit OpenRequest(fuse_req_t req) : internal::BaseRequest(req) {}
  void ReplyOpen(uint64_t file_handle);
};

// State of fuse requests that can be responded to with a new entry and open
// file handle.
class CreateRequest : public internal::BaseRequest {
 public:
  explicit CreateRequest(fuse_req_t req) : internal::BaseRequest(req) {}
  void ReplyCreate(const fuse_entry_param& entry, uint64_t file_handle);
};

// State of fuse requests that can be responded to with a buffer of data
// (eg. read()).
class BufRequest : public internal::BaseRequest {
 public:
  explicit BufRequest(fuse_req_t req) : internal::BaseRequest(req) {}
  void ReplyBuf(const char* buf, size_t size);
};

// State of fuse requests that can be responded to with a number of bytes
// written.
class WriteRequest : public internal::BaseRequest {
 public:
  explicit WriteRequest(fuse_req_t req) : internal::BaseRequest(req) {}
  void ReplyWrite(size_t written);
};

// State of fuse requests that can be responded to with a set of directory
// entries.
class DirentryRequest : public internal::BaseRequest {
 public:
  DirentryRequest(fuse_req_t req, size_t size);

  // Add a directory entry to the response. |name| is the entry name, must not
  // be "." or "..", must be terminated with '\0', and must not contain '/'.
  // |inode| is the inode number for the entry. |mode| is the file type and must
  // be either S_IFREG or S_IFDIR. |next_offset| is the offset for the _next_
  // directory entry (not this one).
  bool AddEntry(base::StringPiece name,
                fuse_ino_t inode,
                mode_t mode,
                off_t next_offset);
  void ReplyDone();

 private:
  const size_t size_;
  std::unique_ptr<char[]> buf_;
  size_t off_ = 0;
};

}  // namespace smbfs

#endif  // SMBFS_REQUEST_H_
