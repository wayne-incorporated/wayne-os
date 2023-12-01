// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_LOCAL_DATA_STORE_H_
#define TPM_MANAGER_SERVER_LOCAL_DATA_STORE_H_

#include <tpm_manager/proto_bindings/tpm_manager.pb.h>

namespace tpm_manager {

// LocalDataStore is an interface class that provides access to read and write
// local system data.
class LocalDataStore {
 public:
  LocalDataStore() = default;
  virtual ~LocalDataStore() = default;

  // Reads local |data| from persistent storage. If no local data exists, the
  // output is an empty protobuf and the method succeeds. Returns true on
  // success.
  virtual bool Read(LocalData* data) = 0;

  // Writes local |data| to persistent storage. Returns true on success.
  virtual bool Write(const LocalData& data) = 0;
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_LOCAL_DATA_STORE_H_
