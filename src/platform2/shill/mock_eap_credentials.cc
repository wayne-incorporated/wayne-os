// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/mock_eap_credentials.h"

#include <gtest/gtest.h>

namespace shill {

MockEapCredentials::MockEapCredentials() : EapCredentials() {
  ON_CALL(*this, key_management())
      .WillByDefault(testing::ReturnRef(kDefaultKeyManagement));
}

MockEapCredentials::~MockEapCredentials() = default;

}  // namespace shill
