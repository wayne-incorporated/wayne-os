// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

#include "shill/wifi/mock_wifi_provider.h"

// Needed for mock method instantiation.
#include "shill/profile.h"

using testing::_;
using testing::Invoke;
using testing::Return;
using testing::WithArg;

namespace shill {

MockWiFiProvider::MockWiFiProvider(Manager* manager) : WiFiProvider(manager) {
  ON_CALL(*this, GetHiddenSSIDList()).WillByDefault(Return(ByteArrays()));
  ON_CALL(*this, UpdateRegAndPhyInfo(_))
      .WillByDefault(WithArg<0>(Invoke([](auto cb) { std::move(cb).Run(); })));
}

MockWiFiProvider::~MockWiFiProvider() = default;

}  // namespace shill
