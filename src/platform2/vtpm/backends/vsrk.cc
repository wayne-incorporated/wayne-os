// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/backends/vsrk.h"

#include <memory>
#include <string>

#include <base/check.h>
#include <trunks/tpm_generated.h>
#include <trunks/tpm_utility.h>
#include <trunks/trunks_factory.h>

namespace vtpm {

Vsrk::Vsrk(trunks::TrunksFactory* factory) : factory_(factory) {
  CHECK(factory_);
}

trunks::TPM_RC Vsrk::Get(std::string& blob) {
  std::unique_ptr<trunks::AuthorizationDelegate> empty_password_authorization =
      factory_->GetPasswordAuthorization("");
  return factory_->GetTpmUtility()->CreateRestrictedECCKeyPair(
      trunks::TpmUtility::kDecryptKey, trunks::TPM_ECC_NIST_P256,
      /*password=*/"",
      /*policy_digest=*/"",
      /*use_only_policy_authorization=*/false,
      /*creation_pcr_indexes=*/{}, empty_password_authorization.get(), &blob,
      /*creation_blob=*/nullptr);
}

}  // namespace vtpm
