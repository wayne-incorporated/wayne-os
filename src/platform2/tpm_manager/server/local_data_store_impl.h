// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_LOCAL_DATA_STORE_IMPL_H_
#define TPM_MANAGER_SERVER_LOCAL_DATA_STORE_IMPL_H_

#include "tpm_manager/server/local_data_store.h"

#include <string>

namespace tpm_manager {

class LocalDataStoreImpl : public LocalDataStore {
 public:
  LocalDataStoreImpl();

  // A constructor that takes the parameter of the path of the local data.
  explicit LocalDataStoreImpl(const std::string& local_data_path);
  LocalDataStoreImpl(const LocalDataStoreImpl&) = delete;
  LocalDataStoreImpl& operator=(const LocalDataStoreImpl&) = delete;

  ~LocalDataStoreImpl() override = default;

  // LocalDataStore methods.
  bool Read(LocalData* data) override;
  bool Write(const LocalData& data) override;

 private:
  const std::string local_data_path_;
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_LOCAL_DATA_STORE_IMPL_H_
