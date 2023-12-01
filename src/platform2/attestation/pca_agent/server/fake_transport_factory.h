// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_PCA_AGENT_SERVER_FAKE_TRANSPORT_FACTORY_H_
#define ATTESTATION_PCA_AGENT_SERVER_FAKE_TRANSPORT_FACTORY_H_

#include "attestation/pca_agent/server/transport_factory.h"

#include <memory>
#include <string>
#include <unordered_map>

#include <brillo/http/http_transport_fake.h>

namespace attestation {
namespace pca_agent {

// This class implements the factory function by creating
// brillo::http::fake::Transport per proxy server. The consumer can gets the
// fake transport instance by the access function |get_fake_transport|.
class FakeTransportFactory : public TransportFactory {
 public:
  FakeTransportFactory() = default;
  virtual ~FakeTransportFactory() = default;
  std::shared_ptr<brillo::http::Transport> CreateWithProxy(
      const std::string& proxy_server) override {
    return std::static_pointer_cast<brillo::http::Transport>(
        get_fake_transport(proxy_server));
  }
  const std::shared_ptr<brillo::http::fake::Transport>& get_fake_transport(
      const std::string& proxy_server) {
    std::shared_ptr<brillo::http::fake::Transport>& transport =
        table_[proxy_server];
    if (!transport) {
      transport = std::make_shared<brillo::http::fake::Transport>();
    }
    return transport;
  }

 private:
  // Maps the proxy server to fake transport.
  std::unordered_map<std::string,
                     std::shared_ptr<brillo::http::fake::Transport>>
      table_;
};

}  // namespace pca_agent
}  // namespace attestation

#endif  // ATTESTATION_PCA_AGENT_SERVER_FAKE_TRANSPORT_FACTORY_H_
