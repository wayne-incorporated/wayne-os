// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_MOJO_PROXY_LOCAL_FILE_H_
#define ARC_VM_MOJO_PROXY_LOCAL_FILE_H_

#include <stdint.h>

#include <deque>
#include <memory>
#include <string>
#include <vector>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/scoped_file.h>
#include <base/functional/callback.h>
#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>

#include "arc/vm/mojo_proxy/message.pb.h"

namespace arc {

// LocalFile supports writing and reading from a file descriptor owned by this
// proxy process.
class LocalFile {
 public:
  // |can_send_fds| must be true to send/receive FDs using this object.
  // |error_handler| will be run on async IO error.
  // |blocking_task_runner| will be used to perform regular file IO.
  // TODO(hashimoto): Change the interface to report all IO errors via
  // |error_handler|, instead of synchronously returning bool.
  LocalFile(base::ScopedFD fd,
            bool can_send_fds,
            base::OnceClosure error_handler,
            scoped_refptr<base::TaskRunner> blocking_task_runner);
  LocalFile(const LocalFile&) = delete;
  LocalFile& operator=(const LocalFile&) = delete;

  ~LocalFile();

  // Reads the message from the file descriptor.
  // Returns a struct of error_code, where it is 0 on success or errno, blob
  // and attached fds if available.
  struct ReadResult {
    int error_code;
    std::string blob;
    std::vector<base::ScopedFD> fds;
  };
  ReadResult Read();

  // Writes the given blob and file descriptors to the wrapped file descriptor.
  // Returns true iff the whole message is written.
  bool Write(std::string blob, std::vector<base::ScopedFD> fds);

  // Reads |count| bytes from the file starting at |offset| and runs the
  // callback with the result.
  using PreadCallback = base::OnceCallback<void(arc_proxy::PreadResponse)>;
  void Pread(uint64_t count, uint64_t offset, PreadCallback callback);

  // Writes |blob| to the file starting at |offset| and runs the callback with
  // the result.
  using PwriteCallback = base::OnceCallback<void(arc_proxy::PwriteResponse)>;
  void Pwrite(std::string blob, uint64_t offset, PwriteCallback callback);

  // Runs the callback with the file descriptor's stat attribute.
  using FstatCallback = base::OnceCallback<void(arc_proxy::FstatResponse)>;
  void Fstat(FstatCallback callback);

  // Truncates the file to the specified length and runs the callback with the
  // result.
  using FtruncateCallback =
      base::OnceCallback<void(arc_proxy::FtruncateResponse)>;
  void Ftruncate(int64_t length, FtruncateCallback callback);

 private:
  void TrySendMsg();

  base::ScopedFD fd_;
  const bool can_send_fds_;
  base::OnceClosure error_handler_;

  struct Data {
    std::string blob;
    std::vector<base::ScopedFD> fds;
    size_t blob_offset = 0;
  };
  std::deque<Data> pending_write_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> writable_watcher_;

  scoped_refptr<base::TaskRunner> blocking_task_runner_;

  base::WeakPtrFactory<LocalFile> weak_factory_{this};
};

}  // namespace arc

#endif  // ARC_VM_MOJO_PROXY_LOCAL_FILE_H_
