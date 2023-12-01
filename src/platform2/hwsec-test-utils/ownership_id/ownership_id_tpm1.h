// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HWSEC_TEST_UTILS_OWNERSHIP_ID_OWNERSHIP_ID_TPM1_H_
#define HWSEC_TEST_UTILS_OWNERSHIP_ID_OWNERSHIP_ID_TPM1_H_

#include <memory>
#include <optional>
#include <string>

#include <tpm_manager/client/tpm_manager_utility.h>

#include "hwsec-test-utils/ownership_id/ownership_id.h"

namespace hwsec_test_utils {

class OwnershipIdTpm1 : public OwnershipId {
 public:
  OwnershipIdTpm1() = default;
  virtual ~OwnershipIdTpm1() = default;

  std::optional<std::string> Get() override;

 private:
  bool InitializeTpmManagerUtility();

  std::unique_ptr<tpm_manager::TpmManagerUtility> tpm_manager_utility_;
};

}  // namespace hwsec_test_utils

#endif  // HWSEC_TEST_UTILS_OWNERSHIP_ID_OWNERSHIP_ID_TPM1_H_
