// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "virtual_file_provider/fuse_main.h"

#include <unistd.h>

#include <algorithm>
#include <iterator>
#include <optional>
#include <string>
#include <utility>

#include <fuse/fuse.h>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/stringprintf.h>

#include "virtual_file_provider/operation_throttle.h"
#include "virtual_file_provider/util.h"

namespace virtual_file_provider {

namespace {

constexpr char kFileSystemName[] = "virtual-file-provider";

// Maximum number of operations running at the same time.
constexpr int kMaxOperationCount = 1024;

struct FusePrivateData {
  FuseMainDelegate* delegate;
  OperationThrottle* operation_throttle;
};

FuseMainDelegate* GetDelegate() {
  return static_cast<FusePrivateData*>(fuse_get_context()->private_data)
      ->delegate;
}

OperationThrottle* GetOperationThrottle() {
  return static_cast<FusePrivateData*>(fuse_get_context()->private_data)
      ->operation_throttle;
}

int GetAttr(const char* path, struct stat* stat) {
  // Everything except the root is a file.
  if (path == std::string("/")) {
    stat->st_mode = S_IFDIR | S_IXGRP;
    stat->st_nlink = 2;
  } else {
    DCHECK_EQ('/', path[0]);
    // File name is the ID.
    std::string id(path + 1);

    const int64_t size = GetDelegate()->GetSize(id);
    if (size < 0) {
      LOG(ERROR) << "Invalid ID " << id;
      return -ENOENT;
    }
    stat->st_mode = S_IFREG | S_IRGRP;
    stat->st_nlink = 1;
    stat->st_size = size;
  }
  return 0;
}

int Open(const char* path, struct fuse_file_info* fi) {
  DCHECK_EQ('/', path[0]);
  // File name is the ID.
  const std::string id(path + 1);

  const int64_t file_size = GetDelegate()->GetSize(id);
  if (file_size < 0) {
    LOG(ERROR) << "Invalid ID " << id;
    return -ENOENT;
  }

  return 0;
}

int Read(const char* path,
         char* buf,
         size_t size,
         off_t off,
         struct fuse_file_info* fi) {
  auto operation_reference = GetOperationThrottle()->StartOperation();

  DCHECK_EQ('/', path[0]);
  // File name is the ID.
  std::string id(path + 1);

  // Adjust the size to avoid issuing unnecessary read requests.
  const int64_t file_size = GetDelegate()->GetSize(id);
  if (file_size < 0) {
    LOG(ERROR) << "Invalid ID " << id;
    return -EIO;
  }
  size = std::min(static_cast<int64_t>(size), file_size - off);
  if (size <= 0) {
    return 0;
  }

  // Create a pipe to receive data from chrome. By using pipe instead of D-Bus
  // to receive data, we can reliably avoid deadlock at read(), provided chrome
  // doesn't leak the file descriptor of the write end.
  int fds[2] = {-1, -1};
  if (pipe(fds) != 0) {
    PLOG(ERROR) << "pipe() failed.";
    return -EIO;
  }
  base::ScopedFD read_end(fds[0]), write_end(fds[1]);

  // Send read request to chrome with the write end of the pipe.
  GetDelegate()->HandleReadRequest(id, off, size, std::move(write_end));

  // Read the data from the read end of the pipe.
  size_t result = 0;
  while (result < size) {
    ssize_t r = HANDLE_EINTR(read(read_end.get(), buf + result, size - result));
    if (r < 0) {
      return -EIO;
    }
    if (r == 0) {
      break;
    }
    result += r;
  }
  return result;
}

int Release(const char* path, struct fuse_file_info* fi) {
  DCHECK_EQ('/', path[0]);
  // File name is the ID.
  std::string id(path + 1);

  GetDelegate()->NotifyIdReleased(id);
  return 0;
}

int ReadDir(const char* path,
            void* buf,
            fuse_fill_dir_t filler,
            off_t offset,
            struct fuse_file_info* fi) {
  filler(buf, ".", nullptr, 0);
  filler(buf, "..", nullptr, 0);
  return 0;
}

void* Init(struct fuse_conn_info* conn) {
  CHECK(ClearCapabilities());
  // FUSE will overwrite the context's private_data with the return value.
  // Just return the current private_data.
  return fuse_get_context()->private_data;
}

}  // namespace

int FuseMain(const base::FilePath& mount_path,
             FuseMainDelegate* delegate,
             std::optional<uid_t> userId,
             std::optional<gid_t> groupId) {
  std::string mount_options = "noexec";  // disallow code execution
  if (userId || groupId) {
    // allow others to access files
    mount_options.append(",allow_other");
    if (userId) {
      mount_options.append(base::StringPrintf(",uid=%u", userId.value()));
    }
    if (groupId) {
      mount_options.append(base::StringPrintf(",gid=%u", groupId.value()));
    }
  }
  const char* fuse_argv[] = {
      kFileSystemName,
      mount_path.value().c_str(),
      "-f",  // "-f" for foreground.
      "-o",
      mount_options.c_str(),
  };
  constexpr struct fuse_operations operations = {
      .getattr = GetAttr,
      .open = Open,
      .read = Read,
      .release = Release,
      .readdir = ReadDir,
      .init = Init,
  };
  OperationThrottle operation_throttle(kMaxOperationCount);
  FusePrivateData private_data;
  private_data.delegate = delegate;
  private_data.operation_throttle = &operation_throttle;
  return fuse_main(std::size(fuse_argv), const_cast<char**>(fuse_argv),
                   &operations, &private_data);
}

}  // namespace virtual_file_provider
