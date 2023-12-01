// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/async_file_reader.h"

#include <fcntl.h>
#include <sys/stat.h>

#include <cerrno>
#include <cstdio>
#include <utility>

#include <base/check_op.h>
#include <base/logging.h>
#include <base/time/time.h>

#include "power_manager/common/tracing.h"

namespace power_manager::system {

namespace {

// Since we don't know the file size in advance, we'll have to read successively
// larger chunks.  Start with 4 KB and double the chunk size with each new read.
const size_t kInitialFileReadSize = 4096;

// How often to poll for the AIO status.
constexpr base::TimeDelta kPoll = base::Milliseconds(100);

}  // namespace

AsyncFileReader::AsyncFileReader() : initial_read_size_(kInitialFileReadSize) {}

AsyncFileReader::~AsyncFileReader() {
  Reset();
  close(fd_);
}

bool AsyncFileReader::Init(const base::FilePath& path) {
  CHECK_EQ(fd_, -1) << "Attempting to open new file when a valid file "
                    << "descriptor exists.";
  fd_ = open(path.value().c_str(), O_RDONLY, 0);
  if (fd_ == -1) {
    PLOG(ERROR) << "Could not open file " << path.value();
    return false;
  }
  path_ = path;
  trace_id_ = reinterpret_cast<uint64_t>(this) ^ fd_;
  return true;
}

bool AsyncFileReader::HasOpenedFile() const {
  return (fd_ != -1);
}

void AsyncFileReader::StartRead(
    base::OnceCallback<void(const std::string&)> read_cb,
    base::OnceCallback<void()> error_cb) {
  TRACE_EVENT("power", "AsyncFileReader::StartRead",
              perfetto::Flow::ProcessScoped(trace_id_), "path", path_.value());
  Reset();

  if (fd_ == -1) {
    LOG(ERROR) << "No file handle available.";
    if (!error_cb.is_null())
      std::move(error_cb).Run();
    return;
  }

  if (!AsyncRead(initial_read_size_, 0)) {
    if (!error_cb.is_null())
      std::move(error_cb).Run();
    return;
  }
  read_cb_ = std::move(read_cb);
  error_cb_ = std::move(error_cb);
  read_in_progress_ = true;
}

void AsyncFileReader::UpdateState() {
  TRACE_EVENT("power", "AsyncFileReader::UpdateState",
              perfetto::Flow::ProcessScoped(trace_id_), "path", path_.value());
  if (!read_in_progress_) {
    update_state_timer_.Reset();
    return;
  }

  int status = aio_error(&aio_control_);
  TRACE_EVENT_INSTANT("power", "AsyncFileReader::UpdateState::Result", "status",
                      status);

  // If the read is still in-progress, keep the timer running.
  if (status == EINPROGRESS)
    return;

  // Otherwise, we stop the timer.
  update_state_timer_.Stop();

  switch (status) {
    case ECANCELED:
      Reset();
      break;
    case 0: {
      size_t size = aio_return(&aio_control_);
      // Save the data that was read, and free the buffer.
      stored_data_.insert(stored_data_.end(), aio_buffer_.get(),
                          aio_buffer_.get() + size);
      aio_buffer_ = nullptr;

      if (size == aio_control_.aio_nbytes) {
        // Read more data if the previous read didn't reach the end of file.
        if (AsyncRead(size * 2, aio_control_.aio_offset + size))
          break;
      }
      if (!read_cb_.is_null())
        std::move(read_cb_).Run(stored_data_);
      Reset();
      break;
    }
    default: {
      LOG(ERROR) << "Error during read of file " << path_.value()
                 << ", status=" << status;
      if (!error_cb_.is_null())
        std::move(error_cb_).Run();
      Reset();
      break;
    }
  }
}

void AsyncFileReader::Reset() {
  if (!read_in_progress_)
    return;

  update_state_timer_.Stop();

  int cancel_result = aio_cancel(fd_, &aio_control_);
  if (cancel_result == -1) {
    PLOG(ERROR) << "aio_cancel() failed";
  } else if (cancel_result == AIO_NOTCANCELED) {
    LOG(INFO) << "aio_cancel() returned AIO_NOTCANCELED; waiting for "
              << "request to complete";
    const aiocb* aiocb_list = {&aio_control_};
    if (aio_suspend(&aiocb_list, 1, nullptr) == -1)
      PLOG(ERROR) << "aio_suspend() failed";
  }

  aio_buffer_ = nullptr;
  stored_data_.clear();
  read_cb_.Reset();
  error_cb_.Reset();
  read_in_progress_ = false;
}

bool AsyncFileReader::AsyncRead(int size, int offset) {
  aio_buffer_.reset(new char[size]);
  memset(&aio_buffer_[0], 0, size);

  memset(&aio_control_, 0, sizeof(aio_control_));
  aio_control_.aio_nbytes = size;
  aio_control_.aio_fildes = fd_;
  aio_control_.aio_offset = offset;
  aio_control_.aio_buf = aio_buffer_.get();

  if (aio_read(&aio_control_) == -1) {
    LOG(ERROR) << "Unable to access " << path_.value();
    aio_buffer_ = nullptr;
    return false;
  }

  update_state_timer_.Start(FROM_HERE, kPoll, this,
                            &AsyncFileReader::UpdateState);
  return true;
}

}  // namespace power_manager::system
