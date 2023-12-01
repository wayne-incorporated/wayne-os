// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FUSEBOX_FUSE_REQUEST_H_
#define FUSEBOX_FUSE_REQUEST_H_

#include <fuse_lowlevel.h>

#include <memory>
#include <string>
#include <vector>

namespace fusebox {

/**
 * Kernel FUSE low level request responders: FuseRequest stores a Kernel
 * fuse_req_t type in member req_ and replies to that req_ with the FUSE
 * operation results (the response).
 *
 * Derived classes specialize the response for the given req_, and store
 * any request parameters needed to complete the operation.
 *
 * Note: the classes only define the low level FUSE request and response
 * API, they do not perform FUSE operations.
 */

class FuseRequest {
 protected:
  explicit FuseRequest(fuse_req_t req, fuse_file_info* fi = nullptr);
  FuseRequest(const FuseRequest&) = delete;
  FuseRequest& operator=(const FuseRequest&) = delete;
  virtual ~FuseRequest();

 public:
  int flags() const { return flags_; }
  uint64_t fh() const { return fh_; }
  bool IsInterrupted() const;
  int ReplyError(int error);

 protected:
  const fuse_req_t req_;
  bool replied_ = false;
  uint64_t fh_;
  int flags_;
};

// FUSE request with an OK response.
class OkRequest : public FuseRequest {
 public:
  explicit OkRequest(fuse_req_t req, fuse_file_info* fi = nullptr)
      : FuseRequest(req, fi) {}
  void ReplyOk();
};

// FUSE request with a none response.
class NoneRequest : public FuseRequest {
 public:
  explicit NoneRequest(fuse_req_t req) : FuseRequest(req) {}
  void ReplyNone();
};

// FUSE request with an attribute stat response.
class AttrRequest : public FuseRequest {
 public:
  AttrRequest(fuse_req_t req, fuse_file_info* fi) : FuseRequest(req, fi) {}
  void ReplyAttr(const struct stat& attr, double timeout);
};

// FUSE request with a file-system attribute stat response.
class FsattrRequest : public FuseRequest {
 public:
  explicit FsattrRequest(fuse_req_t req) : FuseRequest(req) {}
  void ReplyFsattr(const struct statvfs& fs_attr);
};

// FUSE request with a fuse_entry_param response.
class EntryRequest : public FuseRequest {
 public:
  explicit EntryRequest(fuse_req_t req) : FuseRequest(req) {}
  void ReplyEntry(const fuse_entry_param& entry);
};

// FUSE request with an open file handle response.
class OpenRequest : public FuseRequest {
 public:
  OpenRequest(fuse_req_t req, fuse_file_info* fi) : FuseRequest(req, fi) {}
  void ReplyOpen(uint64_t fh);

 protected:
  // Set true, iff |this| is a CreateRequest.
  bool create_ = false;
  // Entry for fuse_reply_create(3) response.
  fuse_entry_param entry_ = {0};
};

// FUSE request with an entry create response.
class CreateRequest : public OpenRequest {
 public:
  explicit CreateRequest(fuse_req_t req, fuse_file_info* fi)
      : OpenRequest(req, fi) {
    create_ = true;
  }
  void ReplyCreate(const fuse_entry_param& entry, uint64_t fh);

  // Entry for fuse_reply_create(3) response.
  void SetEntry(const fuse_entry_param& entry) { entry_ = entry; }
};

// FUSE request with a data buffer response.
class BufferRequest : public FuseRequest {
 public:
  BufferRequest(fuse_req_t req, fuse_file_info* fi) : FuseRequest(req, fi) {}
  void ReplyBuffer(const void* data, size_t size);
};

// FUSE request with a bytes written count response.
class WriteRequest : public FuseRequest {
 public:
  explicit WriteRequest(fuse_req_t req, fuse_file_info* fi)
      : FuseRequest(req, fi) {}
  void ReplyWrite(size_t count);
};

// FUSE request with a DirEntry list response.
class DirEntryRequest : public FuseRequest {
 public:
  DirEntryRequest(fuse_req_t req,
                  fuse_file_info* fi,
                  size_t buf_size,
                  off_t dir_offset);

  // Entry buffer |buf_| size.
  size_t buf_size() const { return buf_size_; }

  // Add entry to |buf_|. Returns true if the entry was added.
  bool AddEntry(const struct DirEntry& entry, off_t dir_offset);

  // Space used in |buf_| by the added entries.
  size_t buf_used() const { return buf_offset_; }

  // Offset to the next entry.
  off_t dir_offset() const { return dir_offset_; }

  // Reply with the entry buffer result.
  void ReplyDone();

 private:
  const size_t buf_size_;  // Measured in bytes.
  size_t buf_offset_ = 0;  // Measured in bytes.
  std::unique_ptr<char[]> buf_;
  // FUSE (the protocol) and libfuse (the library) does not mandate (it lets
  // the program choose) what units the offset is measured in, other than 0
  // means "from the beginning". This fusebox program uses "number of files".
  off_t dir_offset_;
};

// Responds to multiple DirEntryRequests, each with the same FUSE handle.
class DirEntryBuffer {
 public:
  DirEntryBuffer();

  // Append |request| to the DirEntryRequest list.
  void AppendRequest(std::unique_ptr<DirEntryRequest> request);

  // Append |entry| DirEntry to the DirEntry list.
  void AppendResponse(std::vector<struct DirEntry> entry, bool end = false);

  // Append errno |error| to the DirEntry list. Returns |error|.
  int AppendResponse(int error);

 private:
  // Called by AppendResponse() to respond to DirEntry requests.
  void Respond();

  // List of DirEntryRequest received from Kernel Fuse.
  std::vector<std::unique_ptr<DirEntryRequest>> request_;

  // List of DirEntry from the file system: readdir(2).
  std::vector<struct DirEntry> entry_;

  // Error state of the DirEntry list.
  int error_ = 0;

  // True when the DirEntry list is complete.
  bool end_ = false;
};

struct DirEntry {
  ino_t ino;
  std::string name;
  mode_t mode;
};

}  // namespace fusebox

#endif  // FUSEBOX_FUSE_REQUEST_H_
