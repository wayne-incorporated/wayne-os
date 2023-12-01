// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/keymaster/cert_store_instance.h"

#include <utility>
#include <vector>

#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/pending_remote.h>

namespace arc {
namespace keymaster {

CertStoreInstance::CertStoreInstance(
    base::WeakPtr<KeymasterServer> keymaster_server)
    : keymaster_server_(keymaster_server) {}

void CertStoreInstance::UpdatePlaceholderKeys(
    std::vector<mojom::ChromeOsKeyPtr> keys,
    UpdatePlaceholderKeysCallback callback) {
  if (keymaster_server_) {
    keymaster_server_->UpdateContextPlaceholderKeys(std::move(keys),
                                                    std::move(callback));
  } else {
    std::move(callback).Run(/*success=*/false);
  }
}

}  // namespace keymaster
}  // namespace arc
