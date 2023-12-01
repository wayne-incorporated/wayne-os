// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_MOCK_CELLULAR_SERVICE_PROVIDER_H_
#define SHILL_CELLULAR_MOCK_CELLULAR_SERVICE_PROVIDER_H_

#include "shill/cellular/cellular_service_provider.h"

#include <base/functional/callback.h>
#include <gmock/gmock.h>

#include "shill/network/network.h"

namespace shill {

class MockCellularServiceProvider : public CellularServiceProvider {
 public:
  explicit MockCellularServiceProvider(Manager* manager)
      : CellularServiceProvider(manager) {}
  ~MockCellularServiceProvider() override = default;

  MOCK_METHOD(bool, HardwareSupportsTethering, (), ());
  MOCK_METHOD(
      void,
      TetheringEntitlementCheck,
      (base::OnceCallback<void(TetheringManager::EntitlementStatus result)>),
      ());
  MOCK_METHOD(void,
              AcquireTetheringNetwork,
              (TetheringManager::AcquireNetworkCallback),
              ());
  MOCK_METHOD(void,
              ReleaseTetheringNetwork,
              (Network*, base::OnceCallback<void(bool)>),
              ());
};

}  // namespace shill

#endif  // SHILL_CELLULAR_MOCK_CELLULAR_SERVICE_PROVIDER_H_
