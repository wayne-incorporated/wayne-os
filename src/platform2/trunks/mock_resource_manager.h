// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_MOCK_RESOURCE_MANAGER_H_
#define TRUNKS_MOCK_RESOURCE_MANAGER_H_

#include <gmock/gmock.h>

#include "trunks/resource_manager.h"

namespace trunks {

class MockResourceManager : public ResourceManager {
 public:
  MockResourceManager(const TrunksFactory& factory,
                      CommandTransceiver* next_transceiver)
      : ResourceManager(factory, next_transceiver) {}

  MOCK_METHOD0(Suspend, void());
  MOCK_METHOD0(Resume, void());
};

}  // namespace trunks

#endif  // TRUNKS_MOCK_RESOURCE_MANAGER_H_
