// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/chaps_client_factory.h"

#include <chaps/token_manager_client.h>

namespace cryptohome {

ChapsClientFactory::ChapsClientFactory() {}
ChapsClientFactory::~ChapsClientFactory() {}

chaps::TokenManagerClient* ChapsClientFactory::New() {
  return new chaps::TokenManagerClient();
}

}  // namespace cryptohome
