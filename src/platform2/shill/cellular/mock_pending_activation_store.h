// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_MOCK_PENDING_ACTIVATION_STORE_H_
#define SHILL_CELLULAR_MOCK_PENDING_ACTIVATION_STORE_H_

#include <string>

#include <base/files/file_path.h>
#include <gmock/gmock.h>

#include "shill/cellular/pending_activation_store.h"

namespace shill {

class MockPendingActivationStore : public PendingActivationStore {
 public:
  MockPendingActivationStore();
  ~MockPendingActivationStore() override;

  MOCK_METHOD(bool, InitStorage, (const base::FilePath&), (override));
  MOCK_METHOD(State,
              GetActivationState,
              (IdentifierType, const std::string&),
              (const, override));
  MOCK_METHOD(bool,
              SetActivationState,
              (IdentifierType, const std::string&, State),
              (override));
  MOCK_METHOD(bool,
              RemoveEntry,
              (IdentifierType, const std::string&),
              (override));
};

}  // namespace shill

#endif  // SHILL_CELLULAR_MOCK_PENDING_ACTIVATION_STORE_H_
