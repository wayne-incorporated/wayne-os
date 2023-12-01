// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/csme/pinweaver_core_client.h"

#include <algorithm>
#include <string>

#include <base/check.h>
#include <base/logging.h>

#include "trunks/csme/pinweaver_client_utils.h"
#include "trunks/csme/pinweaver_csme_types.h"

#if USE_PINWEAVER_CSME
#include "trunks/csme/pinweaver_core_client_impl.h"
#else
#include "trunks/csme/pinweaver_core_client_null.h"
#endif

namespace trunks {
namespace csme {

// static
std::unique_ptr<PinWeaverCoreClient> PinWeaverCoreClient::Create(
    MeiClientFactory* mei_client_factory) {
  std::unique_ptr<PinWeaverCoreClient> core_client;
#if USE_PINWEAVER_CSME
  core_client.reset(new PinWeaverCoreClientImpl(mei_client_factory));
#else
  core_client.reset(new PinWeaverCoreClientNull());
#endif
  return core_client;
}

}  // namespace csme
}  // namespace trunks
