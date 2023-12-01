// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_BACKENDS_TPM_PROPERTY_MANAGER_H_
#define VTPM_BACKENDS_TPM_PROPERTY_MANAGER_H_

#include <vector>

#include <trunks/tpm_generated.h>

namespace vtpm {

class TpmPropertyManager {
 public:
  virtual ~TpmPropertyManager() = default;
  virtual void AddCommand(trunks::TPM_CC cc) = 0;
  virtual const std::vector<trunks::TPM_CC>& GetCommandList() = 0;
  virtual const std::vector<trunks::TPMS_TAGGED_PROPERTY>&
  GetCapabilityPropertyList() = 0;
};

}  // namespace vtpm

#endif  // VTPM_BACKENDS_TPM_PROPERTY_MANAGER_H_
