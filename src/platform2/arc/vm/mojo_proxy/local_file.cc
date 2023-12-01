// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/mojo_proxy/local_file.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>

#include "arc/vm/mojo_proxy/file_descriptor_util.h"

namespace arc {

LocalFile::LocalFile(base::ScopedFD fd,
                     bool can_send_fds,
                     base::OnceClosure error_handler,
                     scoped_refptr<base::TaskRunner> blocking_task_runner)
    : fd_(std::move(fd)),
      can_send_fds_(can_send_fds),
      error_handler_(std::move(error_handler)),
      blocking_task_runner_(blocking_task_runner) {}

LocalFile::~LocalFile() {
  // Asynchronous tasks running on the blocking task runner may be using the FD.
  // Post a task to destruct the FD on the task runner after all tasks finish.
  if (blocking_task_runner_) {
    blocking_task_runner_->PostTask(
        FROM_HERE, base::BindOnce([](base::ScopedFD fd) {}, std::move(fd_)));
  }
}

LocalFile::ReadResult LocalFile::Read() {
  // Get the amont of readable data (for pipes or stream sockets) or the size of
  // the next datagram (for datagram sockets).
  int buffer_size = 0;
  if (HANDLE_EINTR(ioctl(fd_.get(), FIONREAD, &buffer_size)) < 0) {
    int error_code = errno;
    PLOG(ERROR) << "ioctl(FIONREAD) failed";
    return {error_code, std::string(), {}};
  }

  // Caller is responsible to call this function only when FD is readable.
  // FD is readable && buffer_size==0 means it reached EOF.
  if (buffer_size == 0)
    return {0, std::string(), {}};

  // Read data.
  std::string buf(buffer_size, 0);
  std::vector<base::ScopedFD> fds;
  ssize_t size = can_send_fds_
                     ? Recvmsg(fd_.get(), &buf[0], buf.size(), &fds)
                     : HANDLE_EINTR(read(fd_.get(), &buf[0], buf.size()));
  if (size == -1) {
    int error_code = errno;
    PLOG(ERROR) << "Failed to read";
    return {error_code, std::string(), {}};
  }
  buf.resize(size);
  return {0 /* succeed */, std::move(buf), std::move(fds)};
}

bool LocalFile::Write(std::string blob, std::vector<base::ScopedFD> fds) {
  pending_write_.emplace_back(Data{std::move(blob), std::move(fds)});
  if (!writable_watcher_)  // TrySendMsg will be called later if watching.
    TrySendMsg();
  return true;
}

void LocalFile::Pread(uint64_t count, uint64_t offset, PreadCallback callback) {
  blocking_task_runner_.get()->PostTaskAndReplyWithResult(
      FROM_HERE,
      base::BindOnce(
          [](int fd, uint64_t count, uint64_t offset) {
            arc_proxy::PreadResponse response;
            std::string buffer;
            buffer.resize(count);
            int result = HANDLE_EINTR(pread(fd, &buffer[0], count, offset));
            if (result < 0) {
              response.set_error_code(errno);
            } else {
              buffer.resize(result);
              response.set_error_code(0);
              response.set_blob(std::move(buffer));
            }
            return response;
          },
          fd_.get(), count, offset),
      std::move(callback));
}

void LocalFile::Pwrite(std::string blob,
                       uint64_t offset,
                       PwriteCallback callback) {
  blocking_task_runner_.get()->PostTaskAndReplyWithResult(
      FROM_HERE,
      base::BindOnce(
          [](int fd, std::string blob, uint64_t offset) {
            arc_proxy::PwriteResponse response;
            int result =
                HANDLE_EINTR(pwrite(fd, &blob[0], blob.size(), offset));
            if (result < 0) {
              response.set_error_code(errno);
            } else {
              response.set_bytes_written(result);
            }
            return response;
          },
          fd_.get(), std::move(blob), offset),
      std::move(callback));
}

void LocalFile::Fstat(FstatCallback callback) {
  blocking_task_runner_.get()->PostTaskAndReplyWithResult(
      FROM_HERE,
      base::BindOnce(
          [](int fd) {
            arc_proxy::FstatResponse response;
            struct stat st;
            int result = fstat(fd, &st);
            if (result < 0) {
              response.set_error_code(errno);
            } else {
              response.set_error_code(0);
              response.set_size(st.st_size);
            }
            return response;
          },
          fd_.get()),
      std::move(callback));
}

void LocalFile::Ftruncate(int64_t length, FtruncateCallback callback) {
  blocking_task_runner_.get()->PostTaskAndReplyWithResult(
      FROM_HERE,
      base::BindOnce(
          [](int fd, int64_t length) {
            arc_proxy::FtruncateResponse response;
            int result = HANDLE_EINTR(ftruncate(fd, length));
            if (result < 0) {
              response.set_error_code(errno);
            } else {
              response.set_error_code(0);
            }
            return response;
          },
          fd_.get(), length),
      std::move(callback));
}

void LocalFile::TrySendMsg() {
  DCHECK(!pending_write_.empty());
  for (; !pending_write_.empty(); pending_write_.pop_front()) {
    auto& data = pending_write_.front();

    while (data.blob_offset < data.blob.size()) {
      const char* data_ptr = data.blob.data() + data.blob_offset;
      const size_t data_size = data.blob.size() - data.blob_offset;
      const ssize_t result =
          data.fds.empty() ? HANDLE_EINTR(write(fd_.get(), data_ptr, data_size))
                           : Sendmsg(fd_.get(), data_ptr, data_size, data.fds);
      if (result == -1) {
        if (errno == EAGAIN) {
          // Will retry later.
          if (!writable_watcher_) {
            writable_watcher_ = base::FileDescriptorWatcher::WatchWritable(
                fd_.get(), base::BindRepeating(&LocalFile::TrySendMsg,
                                               weak_factory_.GetWeakPtr()));
          }
          return;
        }
        PLOG(ERROR) << "Failed to write";
        writable_watcher_.reset();
        std::move(error_handler_).Run();  // May result in deleting this object.
        return;
      }
      data.fds.clear();  // To avoid sending FDs twice.
      data.blob_offset += result;
    }
  }
  // No pending data left. Stop watching.
  writable_watcher_.reset();
}

}  // namespace arc
