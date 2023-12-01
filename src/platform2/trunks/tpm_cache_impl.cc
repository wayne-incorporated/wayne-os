// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/tpm_cache_impl.h"

#include <memory>

#include <base/logging.h>

#include "trunks/tpm_generated.h"
#include "trunks/tpm_state.h"
#include "trunks/tpm_utility.h"
#include "trunks/trunks_factory.h"

namespace trunks {

TpmCacheImpl::TpmCacheImpl(const TrunksFactory& factory) : factory_(factory) {}

TPM_RC TpmCacheImpl::GetSaltingKeyPublicArea(TPMT_PUBLIC* public_area) {
  // sanity check
  if (!public_area) {
    LOG(ERROR) << __func__ << ": public_area is uninitialized.";
    return TPM_RC_FAILURE;
  }

  if (salting_key_pub_area_) {
    // return from cache
    *public_area = *salting_key_pub_area_;
    return TPM_RC_SUCCESS;
  }

  TPM2B_NAME unused_out_name;
  TPM2B_NAME unused_qualified_name;
  TPM2B_PUBLIC public_data;
  TPM_RC result = factory_.GetTpm()->ReadPublicSync(
      kSaltingKey, "" /* object_handle_name, not used */, &public_data,
      &unused_out_name, &unused_qualified_name,
      nullptr /* authorization_delegate */);

  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Failed to get public area for salting key";
    return result;
  }

  if (!public_data.size) {
    LOG(ERROR) << __func__
               << ": Failed to read public information - empty data";
    return TPM_RC_FAILURE;
  }
  salting_key_pub_area_ = public_data.public_area;
  *public_area = *salting_key_pub_area_;

  return TPM_RC_SUCCESS;
}

TPM_ALG_ID TpmCacheImpl::GetBestSupportedKeyType() {
  if (best_key_type_) {
    return *best_key_type_;
  }

  std::unique_ptr<TpmState> tpm_state = factory_.GetTpmState();
  if (tpm_state->Initialize() != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Failed to refresh tpm state.";
    return TPM_ALG_ERROR;
  }

  // The if-else order below matters because ECC is preferable to RSA.
  if (tpm_state->IsECCSupported()) {
    best_key_type_ = TPM_ALG_ECC;
  } else if (tpm_state->IsRSASupported()) {
    best_key_type_ = TPM_ALG_RSA;
  }

  return best_key_type_ ? *best_key_type_ : TPM_ALG_ERROR;
}

}  // namespace trunks
