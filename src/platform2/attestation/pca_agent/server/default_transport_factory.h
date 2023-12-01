// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_PCA_AGENT_SERVER_DEFAULT_TRANSPORT_FACTORY_H_
#define ATTESTATION_PCA_AGENT_SERVER_DEFAULT_TRANSPORT_FACTORY_H_

#include "attestation/pca_agent/server/transport_factory.h"

#include <memory>
#include <string>

namespace attestation {

namespace pca_agent {

// This class implements the factory function using
// |brillo::http::Transport::CreateDefault|.
class DefaultTransportFactory : public TransportFactory {
 public:
  DefaultTransportFactory() = default;
  virtual ~DefaultTransportFactory() = default;
  std::shared_ptr<brillo::http::Transport> CreateWithProxy(
      const std::string& proxy_server) override;
};

}  // namespace pca_agent

}  // namespace attestation

#endif  // ATTESTATION_PCA_AGENT_SERVER_DEFAULT_TRANSPORT_FACTORY_H_
