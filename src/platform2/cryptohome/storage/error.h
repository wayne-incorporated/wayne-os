// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_STORAGE_ERROR_H_
#define CRYPTOHOME_STORAGE_ERROR_H_

#include <string>
#include <utility>

#include <base/location.h>
#include <dbus/cryptohome/dbus-constants.h>

#include <libhwsec-foundation/error/error.h>
#include <libhwsec-foundation/status/status_chain.h>
#include <libhwsec-foundation/status/status_chain_or.h>

#include "cryptohome/storage/mount_utils.h"

namespace cryptohome {

class StorageError : public hwsec_foundation::status::Error {
 public:
  using MakeStatusTrait =
      hwsec_foundation::status::DefaultMakeStatus<StorageError>;
  using BaseErrorType = StorageError;

  StorageError(base::Location location,
               std::string message,
               MountError error,
               bool report = true)
      : hwsec_foundation::status::Error(message),
        location_(location),
        error_(error) {
    PLOG(ERROR) << ToString();
    if (report) {
      ForkAndCrash(ToString());
    }
  }
  StorageError(const StorageError&) = default;
  StorageError(StorageError&&) = default;
  StorageError& operator=(const StorageError&) = default;
  StorageError& operator=(StorageError&&) = default;

  ~StorageError() override {}

  MountError error() const { return error_; }

  std::string ToString() const override {
    return location_.ToString() + " | " + Error::ToString() +
           " | error = " + std::to_string(static_cast<uint32_t>(error_));
  }

 private:
  base::Location location_;
  MountError error_;
};

using StorageStatus = hwsec_foundation::status::StatusChain<StorageError>;
template <typename _Et>
using StorageStatusOr =
    hwsec_foundation::status::StatusChainOr<_Et, StorageError>;

}  // namespace cryptohome

#endif  // CRYPTOHOME_STORAGE_ERROR_H_
