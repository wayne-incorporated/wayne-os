// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/mock_tpm_cache.h"

#include <gmock/gmock.h>

#include "trunks/tpm_generated.h"

using testing::_;
using testing::Return;

namespace trunks {

MockTpmCache::MockTpmCache() {
  ON_CALL(*this, GetSaltingKeyPublicArea(_))
      .WillByDefault(Return(TPM_RC_FAILURE));
  ON_CALL(*this, GetBestSupportedKeyType()).WillByDefault(Return(TPM_ALG_ECC));
}

}  // namespace trunks
