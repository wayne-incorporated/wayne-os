// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "midis/subdevice_client_fd_holder.h"

#include <memory>
#include <utility>
#include <vector>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>

#include "midis/constants.h"

namespace midis {

SubDeviceClientFdHolder::SubDeviceClientFdHolder(
    uint32_t client_id,
    uint32_t subdevice_id,
    base::ScopedFD fd,
    ClientDataCallback client_data_cb)
    : client_id_(client_id),
      subdevice_id_(subdevice_id),
      fd_(std::move(fd)),
      client_data_cb_(std::move(client_data_cb)),
      queue_(std::make_unique<midi::MidiMessageQueue>(true)),
      weak_factory_(this) {}

SubDeviceClientFdHolder::~SubDeviceClientFdHolder() = default;

std::unique_ptr<SubDeviceClientFdHolder> SubDeviceClientFdHolder::Create(
    uint32_t client_id,
    uint32_t subdevice_id,
    base::ScopedFD fd,
    ClientDataCallback client_data_cb) {
  auto holder = std::make_unique<SubDeviceClientFdHolder>(
      client_id, subdevice_id, std::move(fd), std::move(client_data_cb));
  if (!holder->StartClientMonitoring()) {
    return nullptr;
  }
  return holder;
}

void SubDeviceClientFdHolder::WriteDeviceDataToClient(const void* buffer,
                                                      size_t buf_len) {
  queue_->Add(reinterpret_cast<const uint8_t*>(buffer), buf_len);
  std::vector<uint8_t> message;
  queue_->Get(&message);
  while (!message.empty()) {
    ssize_t ret =
        HANDLE_EINTR(write(GetRawFd(), message.data(), message.size()));
    if (ret != static_cast<ssize_t>(message.size())) {
      PLOG(ERROR) << "Error writing to client fd.";
    }
    queue_->Get(&message);
  }
}

bool SubDeviceClientFdHolder::StartClientMonitoring() {
  // TODO(pmalani): Should make this conditional on whether the device
  // can accept input.
  watcher_ = base::FileDescriptorWatcher::WatchReadable(
      fd_.get(),
      base::BindRepeating(&SubDeviceClientFdHolder::HandleClientMidiData,
                          weak_factory_.GetWeakPtr()));
  if (!watcher_) {
    LOG(ERROR) << "Client id: " << client_id_
               << " watcher for pipeFD, for output to"
                  " subdevice: "
               << subdevice_id_ << " failed.";
    return false;
  }
  return true;
}

void SubDeviceClientFdHolder::HandleClientMidiData() {
  uint8_t buf[kMaxBufSize];
  ssize_t ret = HANDLE_EINTR(read(fd_.get(), buf, sizeof(buf)));
  if (ret < 0) {
    PLOG(ERROR) << "Error reading from pipe fd.";
    return;
  }

  client_data_cb_.Run(subdevice_id_, buf, ret);
}

}  // namespace midis
