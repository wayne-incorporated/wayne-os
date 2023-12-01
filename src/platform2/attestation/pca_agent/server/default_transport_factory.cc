// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "attestation/pca_agent/server/default_transport_factory.h"

#include <memory>
#include <string>

#include <brillo/http/http_transport.h>

namespace attestation {
namespace pca_agent {

std::shared_ptr<brillo::http::Transport>
DefaultTransportFactory::CreateWithProxy(const std::string& proxy_server) {
  return brillo::http::Transport::CreateDefaultWithProxy(proxy_server);
}

}  // namespace pca_agent
}  // namespace attestation
