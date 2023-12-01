// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_TPM2_STATUS_IMPL_H_
#define TPM_MANAGER_SERVER_TPM2_STATUS_IMPL_H_

#include "tpm_manager/server/tpm_status.h"

#include <memory>
#include <vector>

#include <base/logging.h>
#include <trunks/tpm_state.h>
#include <trunks/trunks_factory.h>

#include "tpm_manager/common/typedefs.h"

namespace tpm_manager {

class Tpm2StatusImpl : public TpmStatus {
 public:
  // Does not take ownership of |factory|.
  explicit Tpm2StatusImpl(const trunks::TrunksFactory& factory);
  Tpm2StatusImpl(const Tpm2StatusImpl&) = delete;
  Tpm2StatusImpl& operator=(const Tpm2StatusImpl&) = delete;

  ~Tpm2StatusImpl() override = default;

  // TpmStatus methods.
  bool IsTpmEnabled() override;
  bool GetTpmOwned(TpmOwnershipStatus* status) override;
  bool GetDictionaryAttackInfo(uint32_t* counter,
                               uint32_t* threshold,
                               bool* lockout,
                               uint32_t* seconds_remaining) override;
  bool GetVersionInfo(uint32_t* family,
                      uint64_t* spec_level,
                      uint32_t* manufacturer,
                      uint32_t* tpm_model,
                      uint64_t* firmware_version,
                      std::vector<uint8_t>* vendor_specific) override;
  bool IsDictionaryAttackMitigationEnabled(bool* is_enabled) override;
  void MarkRandomOwnerPasswordSet() override;
  bool SupportU2f() override;
  bool SupportPinweaver() override;
  GscVersion GetGscVersion() override;
  bool GetRoVerificationStatus(
      tpm_manager::RoVerificationStatus* status) override;
  bool GetAlertsData(AlertsData* alerts) override;
  bool GetTi50Stats(uint32_t* fs_init_time,
                    uint32_t* fs_size,
                    uint32_t* aprov_time,
                    uint32_t* aprov_status) override;

 private:
  // Refreshes the Tpm state information. Can be called as many times as needed
  // to refresh the cached information in this class. Return true if the
  // refresh operation succeeded.
  bool Refresh();

  // Tests if the TPM SRK public area is readable with default auth and has
  // correct attributes, and check the salting session. Returns:
  // 1. true if the test succeed.
  // 2. false if any error.
  bool TestTpmSrkAndSaltingSession();

  bool initialized_{false};
  TpmOwnershipStatus ownership_status_{kTpmUnowned};
  const trunks::TrunksFactory& trunks_factory_;
  std::unique_ptr<trunks::TpmState> trunks_tpm_state_;
  std::unique_ptr<trunks::TpmUtility> trunks_tpm_utility_;
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_TPM2_STATUS_IMPL_H_
