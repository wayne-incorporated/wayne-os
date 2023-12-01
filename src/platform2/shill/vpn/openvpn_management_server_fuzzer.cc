// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <vector>

#include <base/check.h>
#include <base/logging.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "shill/net/io_handler.h"
#include "shill/net/sockets.h"
#include "shill/vpn/openvpn_driver.h"
#include "shill/vpn/openvpn_management_server.h"

namespace {
const int kPlaceholderSocket = 234;
}

namespace shill {

class FakeOpenVPNDriver : public OpenVPNDriver {
 public:
  FakeOpenVPNDriver() : OpenVPNDriver(nullptr, nullptr) {}
  FakeOpenVPNDriver(const FakeOpenVPNDriver&) = delete;
  FakeOpenVPNDriver& operator=(const FakeOpenVPNDriver&) = delete;

  ~FakeOpenVPNDriver() = default;

  void OnReconnecting(ReconnectReason) override{};
  void FailService(Service::ConnectFailure, base::StringPiece) override{};
  void ReportCipherMetrics(const std::string&) override{};
};

class FakeSockets : public Sockets {
 public:
  FakeSockets() = default;
  FakeSockets(const FakeSockets&) = delete;
  FakeSockets& operator=(const FakeSockets&) = delete;

  ~FakeSockets() override = default;
  int Accept(int sockfd,
             struct sockaddr* addr,
             socklen_t* addrlen) const override {
    return kPlaceholderSocket;
  };
  int Close(int fd) const override { return 0; };
  ssize_t Send(int sockfd,
               const void* buf,
               size_t len,
               int flags) const override {
    return len;
  };
};

class OpenVPNManagementServerFuzzer {
 public:
  void Run(const uint8_t* data, size_t size) {
    // First just send random strings.
    FuzzedDataProvider provider(data, size);
    OpenVPNManagementServer::ParseSubstring(
        provider.ConsumeRandomLengthString(1024),
        provider.ConsumeRandomLengthString(1024),
        provider.ConsumeRandomLengthString(1024));

    // Next force some of the logic to actually run.
    OpenVPNManagementServer::ParseSubstring(
        provider.ConsumeRandomLengthString(1024),
        provider.ConsumeBytesAsString(1), provider.ConsumeBytesAsString(1));

    // Next the helpers.
    OpenVPNManagementServer::ParsePasswordTag(
        provider.ConsumeRandomLengthString(1024));
    OpenVPNManagementServer::ParsePasswordFailedReason(
        provider.ConsumeRandomLengthString(1024));

    // Send remaining data to test general entry point OnInput().
    auto data_vector = provider.ConsumeRemainingBytes<uint8_t>();
    InputData input_data(data_vector.data(), data_vector.size());
    FakeOpenVPNDriver driver;
    FakeSockets sockets;
    OpenVPNManagementServer server(&driver);
    server.connected_socket_ = kPlaceholderSocket;
    server.sockets_ = &sockets;
    server.OnInput(&input_data);
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Turn off logging.
  logging::SetMinLogLevel(logging::LOGGING_FATAL);

  OpenVPNManagementServerFuzzer fuzzer;
  fuzzer.Run(data, size);
  return 0;
}

}  // namespace shill
