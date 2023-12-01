// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_MOCK_LOCAL_DATA_STORE_H_
#define TPM_MANAGER_SERVER_MOCK_LOCAL_DATA_STORE_H_

#include "tpm_manager/server/local_data_store.h"

#include <gmock/gmock.h>

namespace tpm_manager {

class MockLocalDataStore : public LocalDataStore {
 public:
  MockLocalDataStore();
  ~MockLocalDataStore() override;

  MOCK_METHOD(bool, Read, (LocalData*), (override));
  MOCK_METHOD(bool, Write, (const LocalData&), (override));

  const LocalData& GetFakeData() const { return fake_; }
  LocalData& GetMutableFakeData() { return fake_; }

 private:
  LocalData fake_;
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_MOCK_LOCAL_DATA_STORE_H_
