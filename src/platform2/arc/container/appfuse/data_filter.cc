// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/container/appfuse/data_filter.h"

#include <linux/fuse.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_piece.h>
#include <base/task/single_thread_task_runner.h>

namespace arc {
namespace appfuse {

namespace {

// This must be larger than kFuseMaxWrite and kFuseMaxRead defined in
// Android's system/core/libappfuse/include/libappfuse/FuseBuffer.h.
constexpr size_t kMaxFuseDataSize = 256 * 1024;

// Writes the |data| into |fd| with one write(2) (unless EINTR),
// and returns whether or not it succeeded. |name| is used for logging message.
bool WriteData(int fd, const std::vector<char>& data, base::StringPiece name) {
  int result = HANDLE_EINTR(write(fd, data.data(), data.size()));
  if (result != data.size()) {
    if (result < 0) {
      PLOG(ERROR) << "Failed to write to " << name;
    } else {
      // Partial write should never happen with /dev/fuse nor sockets.
      LOG(ERROR) << "Unexpected write result " << result << " when writing "
                 << data.size() << " byte(s) to " << name;
    }
    return false;
  }

  return true;
}

}  // namespace

DataFilter::DataFilter()
    : watch_thread_("DataFilter"),
      origin_task_runner_(base::SingleThreadTaskRunner::GetCurrentDefault()) {}

DataFilter::~DataFilter() {
  // File watching must be cleaned up on the |watch_thread_|.
  // Unretained(this) here is safe because watch_thread_ is owned by |this|.
  watch_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&DataFilter::AbortWatching, base::Unretained(this)));

  // Explicitly call Stop() here to ensure the AbortWatching posted above
  // is completed before destructing any field.
  watch_thread_.Stop();
}

base::ScopedFD DataFilter::Start(base::ScopedFD fd_dev) {
  int raw_socks[2];
  // SOCK_SEQPACKET to mimic the behavior of real /dev/fuse whose read & write
  // result always contains one single command.
  if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, raw_socks) == -1) {
    PLOG(ERROR) << "socketpair() failed.";
    return base::ScopedFD();
  }
  base::ScopedFD socket_for_filter(raw_socks[0]);
  base::ScopedFD socket_for_app(raw_socks[1]);

  if (!watch_thread_.StartWithOptions(
          base::Thread::Options(base::MessagePumpType::IO, 0))) {
    LOG(ERROR) << "Failed to start a data filter thread.";
    return base::ScopedFD();
  }
  fd_dev_ = std::move(fd_dev);
  fd_socket_ = std::move(socket_for_filter);
  // Unretained(this) here is safe because watch_thread_ is owned by |this|.
  watch_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&DataFilter::StartWatching, base::Unretained(this)));
  return socket_for_app;
}

void DataFilter::OnDevReadable() {
  std::vector<char> data(kMaxFuseDataSize);
  int result = HANDLE_EINTR(read(fd_dev_.get(), data.data(), data.size()));
  if (result <= 0) {
    if (result == 0)
      LOG(ERROR) << "Unexpected EOF on /dev/fuse";
    else
      PLOG(ERROR) << "Failed to read /dev/fuse";
    AbortWatching();
    return;
  }
  data.resize(result);

  if (!FilterDataFromDev(&data))
    AbortWatching();
}

void DataFilter::OnDevWritable() {
  DCHECK(!pending_data_to_dev_.empty());
  if (!WriteData(fd_dev_.get(), pending_data_to_dev_.front(), "/dev/fuse")) {
    AbortWatching();
    return;
  }
  pending_data_to_dev_.pop_front();
  UpdateDevWritableWatcher();
}

void DataFilter::UpdateDevWritableWatcher() {
  if (pending_data_to_dev_.empty() && dev_writable_watcher_) {
    dev_writable_watcher_ = nullptr;
  } else if (!pending_data_to_dev_.empty() && !dev_writable_watcher_) {
    dev_writable_watcher_ = base::FileDescriptorWatcher::WatchWritable(
        fd_dev_.get(), base::BindRepeating(&DataFilter::OnDevWritable,
                                           base::Unretained(this)));
  }
}

void DataFilter::OnSocketReadable() {
  std::vector<char> data(kMaxFuseDataSize);
  int result = HANDLE_EINTR(read(fd_socket_.get(), data.data(), data.size()));
  if (result <= 0) {
    PLOG_IF(ERROR, result < 0) << "Failed to read socket";
    AbortWatching();
    return;
  }
  data.resize(result);

  if (!FilterDataFromSocket(&data))
    AbortWatching();
}

void DataFilter::OnSocketWritable() {
  DCHECK(!pending_data_to_socket_.empty());
  if (!WriteData(fd_socket_.get(), pending_data_to_socket_.front(), "socket")) {
    AbortWatching();
    return;
  }
  pending_data_to_socket_.pop_front();
  UpdateSocketWritableWatcher();
}

void DataFilter::UpdateSocketWritableWatcher() {
  if (pending_data_to_socket_.empty() && socket_writable_watcher_) {
    socket_writable_watcher_ = nullptr;
  } else if (!pending_data_to_socket_.empty() && !socket_writable_watcher_) {
    socket_writable_watcher_ = base::FileDescriptorWatcher::WatchWritable(
        fd_socket_.get(), base::BindRepeating(&DataFilter::OnSocketWritable,
                                              base::Unretained(this)));
  }
}

void DataFilter::StartWatching() {
  dev_readable_watcher_ = base::FileDescriptorWatcher::WatchReadable(
      fd_dev_.get(),
      base::BindRepeating(&DataFilter::OnDevReadable, base::Unretained(this)));
  socket_readable_watcher_ = base::FileDescriptorWatcher::WatchReadable(
      fd_socket_.get(), base::BindRepeating(&DataFilter::OnSocketReadable,
                                            base::Unretained(this)));
}

void DataFilter::AbortWatching() {
  dev_readable_watcher_ = nullptr;
  dev_writable_watcher_ = nullptr;
  socket_readable_watcher_ = nullptr;
  socket_writable_watcher_ = nullptr;
  fd_dev_.reset();
  fd_socket_.reset();

  if (!on_stopped_callback_.is_null())
    origin_task_runner_->PostTask(FROM_HERE, std::move(on_stopped_callback_));
}

bool DataFilter::FilterDataFromDev(std::vector<char>* data) {
  const auto* header = reinterpret_cast<const fuse_in_header*>(data->data());
  if (data->size() < sizeof(fuse_in_header) || header->len != data->size()) {
    LOG(ERROR) << "Invalid fuse_in_header";
    return false;
  }
  switch (header->opcode) {
    case FUSE_FORGET:  // No response for FORGET, so no need to save opcode.
      break;
    case FUSE_LOOKUP:
    case FUSE_GETATTR:
    case FUSE_OPEN:
    case FUSE_READ:
    case FUSE_WRITE:
    case FUSE_RELEASE:
    case FUSE_FSYNC:
    case FUSE_INIT: {
      // Save opcode to verify the response later.
      if (unique_to_opcode_.count(header->unique)) {
        LOG(ERROR) << "Conflicting unique value";
        return false;
      }
      unique_to_opcode_[header->unique] = header->opcode;
      break;
    }
    default: {
      // Operation not supported. Return ENOSYS to /dev/fuse.
      std::vector<char> response(sizeof(fuse_out_header));
      auto* out_header = reinterpret_cast<fuse_out_header*>(response.data());
      out_header->len = sizeof(fuse_out_header);
      out_header->error = -ENOSYS;
      out_header->unique = header->unique;
      pending_data_to_dev_.push_back(std::move(response));
      UpdateDevWritableWatcher();
      return true;
    }
  }
  // Pass the data to the socket.
  pending_data_to_socket_.push_back(std::move(*data));
  UpdateSocketWritableWatcher();
  return true;
}

bool DataFilter::FilterDataFromSocket(std::vector<char>* data) {
  const auto* header = reinterpret_cast<const fuse_out_header*>(data->data());
  if (data->size() < sizeof(fuse_out_header) || header->len != data->size()) {
    LOG(ERROR) << "Invalid fuse_out_header";
    return false;
  }
  // Get opcode of the original request.
  auto it = unique_to_opcode_.find(header->unique);
  if (it == unique_to_opcode_.end()) {
    LOG(ERROR) << "Invalid unique value";
    return false;
  }
  const int opcode = it->second;
  unique_to_opcode_.erase(it);

  if (header->error == 0) {
    // Check the response contents.
    switch (opcode) {
      case FUSE_LOOKUP: {
        if (data->size() < sizeof(fuse_out_header) + sizeof(fuse_entry_out)) {
          LOG(ERROR) << "Invalid LOOKUP response";
          return false;
        }
        const auto* entry_out = reinterpret_cast<const fuse_entry_out*>(
            data->data() + sizeof(fuse_out_header));
        if (!S_ISREG(entry_out->attr.mode) && !S_ISDIR(entry_out->attr.mode)) {
          LOG(ERROR) << "Invalid mode";
          return false;
        }
        break;
      }
      case FUSE_GETATTR: {
        if (data->size() < sizeof(fuse_out_header) + sizeof(fuse_attr_out)) {
          LOG(ERROR) << "Invalid GETATTR response";
          return false;
        }
        const auto* attr_out = reinterpret_cast<const fuse_attr_out*>(
            data->data() + sizeof(fuse_out_header));
        if (!S_ISREG(attr_out->attr.mode) && !S_ISDIR(attr_out->attr.mode)) {
          LOG(ERROR) << "Invalid mode";
          return false;
        }
        break;
      }
    }
  }
  // Pass the data to /dev/fuse.
  pending_data_to_dev_.push_back(std::move(*data));
  UpdateDevWritableWatcher();
  return true;
}

}  // namespace appfuse
}  // namespace arc
