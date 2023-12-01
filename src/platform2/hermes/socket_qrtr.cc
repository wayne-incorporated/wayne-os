// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include <base/functional/bind.h>
#include <base/logging.h>

#include "hermes/socket_qrtr.h"

#include <libqrtr.h>

namespace {

constexpr uint8_t kQrtrPort = 0;

}  // namespace

namespace hermes {

SocketQrtr::SocketQrtr() = default;

void SocketQrtr::SetDataAvailableCallback(DataAvailableCallback cb) {
  cb_ = cb;
}

bool SocketQrtr::Open() {
  if (IsValid()) {
    return true;
  }

  socket_.reset(qrtr_open(kQrtrPort));
  if (!socket_.is_valid()) {
    LOG(ERROR) << "Failed to open QRTR socket with port " << kQrtrPort;
    return false;
  }

  watcher_ = base::FileDescriptorWatcher::WatchReadable(
      socket_.get(),
      base::BindRepeating(&SocketQrtr::OnFileCanReadWithoutBlocking,
                          base::Unretained(this)));

  if (!watcher_) {
    LOG(ERROR) << "Failed to set up WatchFileDescriptor";
    socket_.reset();
    return false;
  }

  return true;
}

void SocketQrtr::Close() {
  if (IsValid()) {
    watcher_ = nullptr;
    // Since socket_ is a ScopedFD, socket_.reset() calls close() on the socket.
    socket_.reset();
  }
}

bool SocketQrtr::StartService(uint32_t service,
                              uint16_t version_major,
                              uint16_t version_minor) {
  return qrtr_new_lookup(socket_.get(), service, version_major,
                         version_minor) >= 0;
}

bool SocketQrtr::StopService(uint32_t service,
                             uint16_t version_major,
                             uint16_t version_minor) {
  return qrtr_remove_lookup(socket_.get(), service, version_major,
                            version_minor) >= 0;
}

int SocketQrtr::Recv(void* buf, size_t size, void* metadata) {
  uint32_t node, port;
  int ret = qrtr_recvfrom(socket_.get(), buf, size, &node, &port);
  VLOG(2) << "Receiving packet from node: " << node << " port: " << port;
  if (metadata) {
    PacketMetadata* data = reinterpret_cast<PacketMetadata*>(metadata);
    data->node = node;
    data->port = port;
  }
  return ret;
}

int SocketQrtr::Send(const void* data, size_t size, const void* metadata) {
  uint32_t node = 0, port = 0;
  if (metadata) {
    const PacketMetadata* data =
        reinterpret_cast<const PacketMetadata*>(metadata);
    node = data->node;
    port = data->port;
  }
  VLOG(2) << "Sending packet to node: " << node << " port: " << port;
  return qrtr_sendto(socket_.get(), node, port, data, size);
}

void SocketQrtr::OnFileCanReadWithoutBlocking() {
  if (cb_) {
    cb_.Run(this);
  }
}

bool SocketQrtr::PacketMetadata::operator==(
    const SocketQrtr::PacketMetadata& rhs) const {
  return this->port == rhs.port && this->node == rhs.node;
}

}  // namespace hermes
