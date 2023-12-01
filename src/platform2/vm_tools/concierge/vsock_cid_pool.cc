// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/vsock_cid_pool.h"

#include <sys/file.h>
#include <unistd.h>

#include <memory>
#include <utility>

#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/posix/eintr_wrapper.h>

namespace vm_tools {
namespace concierge {
namespace {
// The path to the file where we store the next cid to be used.
const char kNextCidPath[] = "/run/vm/next_cid";

// The max value for a VM cid
constexpr int kCidMaxValue = 8192;

// Acquires a file lock on an fd and drops the lock when it goes out of scope.
class FileLock final {
 public:
  static std::unique_ptr<FileLock> Acquire(base::ScopedFD file) {
    // Make sure that we get a lock on the file.
    if (HANDLE_EINTR(flock(file.get(), LOCK_EX)) != 0) {
      return nullptr;
    }

    return base::WrapUnique(new FileLock(std::move(file)));
  }

  ~FileLock() {
    if (HANDLE_EINTR(flock(file_.get(), LOCK_UN)) != 0) {
      // Since we failed to drop the file lock, just crash so that the kernel
      // will drop it for us.
      PLOG(FATAL) << "Failed to drop file lock";
    }
  }

  const base::ScopedFD& file() const { return file_; }

 private:
  explicit FileLock(base::ScopedFD file) : file_(std::move(file)) {}
  FileLock(const FileLock&) = delete;
  FileLock& operator=(const FileLock&) = delete;

  base::ScopedFD file_;
};

}  // namespace

// TODO(crbug.com/821478): Remove all this once we fix the vsock bug in the
// kernel.
uint32_t VsockCidPool::Allocate() {
  base::ScopedFD cid_file(
      open(kNextCidPath, O_RDWR | O_CREAT | O_CLOEXEC, 0600));

  if (!cid_file.is_valid()) {
    PLOG(ERROR) << "Failed to create or open " << kNextCidPath;
    return 0;
  }

  auto lock = FileLock::Acquire(std::move(cid_file));
  if (!lock) {
    LOG(ERROR) << "Failed to acquire lock on " << kNextCidPath;
    return 0;
  }

  // 0 and 1 are reserved and 2 is always the host system.
  // Reserve cids 3-31 for static vms.
  uint32_t cid = 32;
  ssize_t ret = HANDLE_EINTR(read(lock->file().get(), &cid, sizeof(cid)));
  if (ret < 0) {
    PLOG(ERROR) << "Failed to read cid from " << kNextCidPath;
    return 0;
  }

  // Either we read the new cid or it was empty and we'll use the default.
  if (ret != 0 && ret != sizeof(cid)) {
    LOG(ERROR) << "Read unexpected number of bytes from " << kNextCidPath
               << ": want " << sizeof(cid) << ", got " << ret;
    return 0;
  }

  // Seek back to the beginning of the file so that we can overwrite it.
  off_t pos = HANDLE_EINTR(lseek(lock->file().get(), 0, SEEK_SET));
  if (pos < 0) {
    PLOG(ERROR) << "Unable to seek to start of " << kNextCidPath;
    return 0;
  }
  if (pos != 0) {
    LOG(ERROR) << "Unexpected return value from lseek: want 0, got " << pos;
    return 0;
  }

  uint32_t next_cid = cid + 1;
  if (next_cid >= kCidMaxValue) {
    PLOG(ERROR) << "Next cid is greater than upper limit: " << next_cid;
    return 0;
  }

  ret = HANDLE_EINTR(write(lock->file().get(), &next_cid, sizeof(next_cid)));
  if (ret != sizeof(next_cid)) {
    PLOG(ERROR) << "Failed to write next cid to " << kNextCidPath;
    return 0;
  }

  return cid;
}

}  // namespace concierge
}  // namespace vm_tools
