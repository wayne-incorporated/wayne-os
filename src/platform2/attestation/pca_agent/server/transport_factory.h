// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_PCA_AGENT_SERVER_TRANSPORT_FACTORY_H_
#define ATTESTATION_PCA_AGENT_SERVER_TRANSPORT_FACTORY_H_

#include <memory>
#include <string>

#include <brillo/http/http_transport.h>

namespace attestation {

namespace pca_agent {

// Factory class to create |brillo::http::Transport| with proxy server input.
class TransportFactory {
 public:
  TransportFactory() = default;
  virtual ~TransportFactory() = default;
  // Creates a td::shared_ptr<brillo::http::Transport> with proxy server.
  virtual std::shared_ptr<brillo::http::Transport> CreateWithProxy(
      const std::string& proxy_server) = 0;
};

}  // namespace pca_agent

}  // namespace attestation

#endif  // ATTESTATION_PCA_AGENT_SERVER_TRANSPORT_FACTORY_H_
