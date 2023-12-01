// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_TPM_CACHE_H_
#define TRUNKS_TPM_CACHE_H_

#include "trunks/tpm_generated.h"
#include "trunks/trunks_export.h"

namespace trunks {

// TpmCache is an interface which provides access to TPM cache information.
class TRUNKS_EXPORT TpmCache {
 public:
  TpmCache() = default;
  TpmCache(const TpmCache&) = delete;
  TpmCache& operator=(const TpmCache&) = delete;

  virtual ~TpmCache() = default;

  // Stores the cached salting key public area in |public_area|. If the cache
  // doesn't exist, gets the public area from TPM and caches it. |public_area|
  // is untouched if there's an error.
  virtual TPM_RC GetSaltingKeyPublicArea(TPMT_PUBLIC* public_area) = 0;

  // Returns the best supported key type for SRK and salting key, and it can
  // only be TPM_ALG_ECC or TPM_ALG_RSA. ECC is preferred to RSA. If the cache
  // doesn't exist, gets the info from TPM and caches it. In case neither ECC
  // nor RSA is supported, or there is an error, returns TPM_ALG_ERROR.
  virtual TPM_ALG_ID GetBestSupportedKeyType() = 0;
};

}  // namespace trunks

#endif  // TRUNKS_TPM_CACHE_H_
