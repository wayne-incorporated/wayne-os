// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_SOCKET_QRTR_H_
#define HERMES_SOCKET_QRTR_H_

#include <memory>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/scoped_file.h>

#include "hermes/socket_interface.h"

namespace hermes {

class SocketQrtr : public SocketInterface {
 public:
  struct PacketMetadata {
    uint32_t port;
    uint32_t node;
    bool operator==(const PacketMetadata& rhs) const;
  };

  SocketQrtr();

  void SetDataAvailableCallback(DataAvailableCallback cb) override;

  bool Open() override;
  void Close() override;
  bool IsValid() const override { return socket_.is_valid(); }
  Type GetType() const override { return Type::kQrtr; }

  bool StartService(uint32_t service,
                    uint16_t version_major,
                    uint16_t version_minor) override;
  bool StopService(uint32_t service,
                   uint16_t version_major,
                   uint16_t version_minor) override;

  // If the metadata ptr is not null, it must point to a
  // SocketQrtr::PacketMetadata instance.
  int Recv(void* buf, size_t size, void* metadata) override;
  int Send(const void* data, size_t size, const void* metadata) override;

 private:
  void OnFileCanReadWithoutBlocking();

 private:
  base::ScopedFD socket_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> watcher_;

  DataAvailableCallback cb_;
};

}  // namespace hermes

namespace std {

template <>
struct std::hash<hermes::SocketQrtr::PacketMetadata> {
  std::size_t operator()(const hermes::SocketQrtr::PacketMetadata& key) const {
    return std::hash<uint32_t>()(key.node) ^ std::hash<uint32_t>()(key.port);
  }
};

}  // namespace std

#endif  // HERMES_SOCKET_QRTR_H_
