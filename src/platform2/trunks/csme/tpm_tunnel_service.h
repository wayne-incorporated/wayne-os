// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_CSME_TPM_TUNNEL_SERVICE_H_
#define TRUNKS_CSME_TPM_TUNNEL_SERVICE_H_

#include <memory>

#include "trunks/csme/mei_client.h"
#include "trunks/csme/mei_client_factory.h"
#include "trunks/trunks_dbus_proxy.h"

namespace trunks {
namespace csme {

class TpmTunnelService {
 public:
  TpmTunnelService() = default;
  explicit TpmTunnelService(TrunksDBusProxy* proxy);
  ~TpmTunnelService() = default;
  bool Initialize();
  bool Run();

 private:
  TrunksDBusProxy default_trunks_proxy_;
  TrunksDBusProxy* trunks_proxy_ = &default_trunks_proxy_;
  MeiClientFactory mei_client_factory_;
  std::unique_ptr<MeiClient> mei_client_;
  bool initialized_ = false;
};

}  // namespace csme
}  // namespace trunks

#endif  // TRUNKS_CSME_TPM_TUNNEL_SERVICE_H_
