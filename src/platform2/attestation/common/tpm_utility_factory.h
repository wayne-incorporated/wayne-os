// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_COMMON_TPM_UTILITY_FACTORY_H_
#define ATTESTATION_COMMON_TPM_UTILITY_FACTORY_H_

#include "attestation/common/tpm_utility.h"

namespace attestation {

class TpmUtilityFactory {
 public:
  static TpmUtility* New();
};

}  // namespace attestation

#endif  // ATTESTATION_COMMON_TPM_UTILITY_FACTORY_H_
