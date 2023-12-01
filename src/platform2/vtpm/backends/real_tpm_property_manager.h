// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_BACKENDS_REAL_TPM_PROPERTY_MANAGER_H_
#define VTPM_BACKENDS_REAL_TPM_PROPERTY_MANAGER_H_

#include "vtpm/backends/tpm_property_manager.h"

#include <vector>

namespace vtpm {

class RealTpmPropertyManager : public TpmPropertyManager {
 public:
  RealTpmPropertyManager();
  ~RealTpmPropertyManager() override = default;
  void AddCommand(trunks::TPM_CC cc) override;
  const std::vector<trunks::TPM_CC>& GetCommandList() override;
  const std::vector<trunks::TPMS_TAGGED_PROPERTY>& GetCapabilityPropertyList()
      override;

 private:
  std::vector<trunks::TPM_CC> commands_;
  bool commands_is_sorted_ = true;
  std::vector<trunks::TPMS_TAGGED_PROPERTY> capability_properties_;
  bool is_total_commands_updated_ = true;
};

}  // namespace vtpm

#endif  // VTPM_BACKENDS_REAL_TPM_PROPERTY_MANAGER_H_
