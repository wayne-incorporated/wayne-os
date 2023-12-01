// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/mock_dbus_objectmanager_proxy.h"

#include <utility>

#include "shill/testing.h"

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::Invoke;
using ::testing::WithArgs;

namespace shill {
MockDBusObjectManagerProxy::MockDBusObjectManagerProxy() {
  ON_CALL(*this, GetManagedObjects(_))
      .WillByDefault(WithArgs<0>(Invoke([](ManagedObjectsCallback callback) {
        std::move(callback).Run(ObjectsWithProperties(), Error());
      })));
}

MockDBusObjectManagerProxy::~MockDBusObjectManagerProxy() = default;

void MockDBusObjectManagerProxy::IgnoreSetCallbacks() {
  EXPECT_CALL(*this, set_interfaces_added_callback(_)).Times(AnyNumber());
  EXPECT_CALL(*this, set_interfaces_removed_callback(_)).Times(AnyNumber());
}
}  // namespace shill
