// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_SOFTCLEAR_UTILS_TPM2_IMPL_H_
#define TPM_SOFTCLEAR_UTILS_TPM2_IMPL_H_

#include "tpm_softclear_utils/tpm.h"

#include <optional>
#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <trunks/trunks_factory.h>
#include <trunks/trunks_factory_impl.h>

namespace tpm_softclear_utils {

constexpr char kTpmLocalDataFile[] = "/var/lib/tpm_manager/local_tpm_data";
constexpr char kDefaultLockoutPassword[] = "";

// Length of the lockout password set when TPM ownership is being taken.
constexpr size_t kLockoutPasswordSize = 20;

// Utility class for soft-clearing TPM 2.0.
class Tpm2Impl : public Tpm {
 public:
  Tpm2Impl() = default;
  Tpm2Impl(const Tpm2Impl&) = delete;
  Tpm2Impl& operator=(const Tpm2Impl&) = delete;

  ~Tpm2Impl() override = default;

  // Initializes trunks factory. Returns if the initialization succeeded.
  bool Initialize() override;

  // Gets the lockout password from tpm_manager's DB and returns it. In case of
  // an error, returns an empty Optional object.
  //
  // Note: Initialize() should be called before calling this function.
  std::optional<std::string> GetAuthForOwnerReset() override;

  // Clears the TPM ownership, including resetting the owner hierarchy and
  // endorsement hierarchy, using the lockout password in
  // |auth_for_owner_reset|.
  //
  // Note: Initialize() should be called before calling this function.
  //
  // Returns if the TPM is soft-cleared successfully.
  bool SoftClearOwner(const std::string& auth_for_owner_reset) override;

  // Overrides current trunks factory. This function should be called by tests
  // only.
  void set_trunks_factory(trunks::TrunksFactory* factory) {
    trunks_factory_ = factory;
  }

 protected:
  // Reads the contents of |path| and stores the contents in |data|. This
  // function can be overridden for testing purposes.
  //
  // TODO(garryxiao): move cryptohome::Platform to a common place, use Platform
  // to read file, and unit-test with its mock instead.
  virtual bool ReadFileToString(const base::FilePath& path, std::string* data) {
    return base::ReadFileToString(path, data);
  }

 private:
  trunks::TrunksFactoryImpl default_trunks_factory_;
  trunks::TrunksFactory* trunks_factory_ = nullptr;

  const base::FilePath local_data_path_{kTpmLocalDataFile};
};

}  // namespace tpm_softclear_utils

#endif  // TPM_SOFTCLEAR_UTILS_TPM2_IMPL_H_
