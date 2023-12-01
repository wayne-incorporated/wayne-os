// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_MOCK_TPM_CACHE_H_
#define TRUNKS_MOCK_TPM_CACHE_H_

#include <gmock/gmock.h>

#include "trunks/tpm_cache.h"
#include "trunks/tpm_generated.h"

namespace trunks {

class MockTpmCache : public TpmCache {
 public:
  MockTpmCache();
  MockTpmCache(const MockTpmCache&) = delete;
  MockTpmCache& operator=(const MockTpmCache&) = delete;

  ~MockTpmCache() override = default;

  MOCK_METHOD(TPM_RC,
              GetSaltingKeyPublicArea,
              (TPMT_PUBLIC * public_area),
              (override));
  MOCK_METHOD(TPM_ALG_ID, GetBestSupportedKeyType, (), (override));
};

}  // namespace trunks

#endif  // TRUNKS_MOCK_TPM_CACHE_H_
