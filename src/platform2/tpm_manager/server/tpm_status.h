// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_TPM_STATUS_H_
#define TPM_MANAGER_SERVER_TPM_STATUS_H_

#include <stdint.h>

#include <vector>

#include <tpm_manager/proto_bindings/tpm_manager.pb.h>

namespace tpm_manager {

// TpmStatus is an interface class that reports status information for some kind
// of TPM device.
class TpmStatus {
 public:
  // Number of alerts supported by UMA
  static inline constexpr size_t kAlertsNumber = 45;
  struct AlertsData {
    // alert counters with UMA enum index
    uint16_t counters[kAlertsNumber];
  };

  enum TpmOwnershipStatus {
    // TPM is not owned. The owner password is empty.
    kTpmUnowned = 0,

    // TPM is pre-owned. The owner password is set to a well-known password, but
    // TPM initialization is not completed yet.
    kTpmPreOwned,

    // TPM initialization is completed. The owner password is set to a randomly-
    // generated password.
    kTpmOwned,

    // TPM initialization is completed. But the ownership taken process is
    // completed by the other system. The TPM is not owned by tpm_manager.
    kTpmSrkNoAuth,

    // TPM is disabled.
    kTpmDisabled,
  };

  TpmStatus() = default;
  virtual ~TpmStatus() = default;

  // Returns true iff the TPM is enabled.
  virtual bool IsTpmEnabled() = 0;

  // Gets current TPM ownership status and stores it in |status|. The status
  // will be kTpmOwned iff the entire TPM initialization process has finished,
  // including all the password set up.
  //
  // Sends out a signal to the dbus if the TPM state is changed to owned from a
  // different state.
  //
  // Returns whether the operation is successful or not.
  virtual bool GetTpmOwned(TpmOwnershipStatus* status) = 0;

  // Reports the current state of the TPM dictionary attack logic.
  virtual bool GetDictionaryAttackInfo(uint32_t* counter,
                                       uint32_t* threshold,
                                       bool* lockout,
                                       uint32_t* seconds_remaining) = 0;

  // Checks whether the dictionary attack mitigation mechanism is enabled.
  // Returns `true` if the operation succeeds and stores the result in
  // `is_enabled`.
  virtual bool IsDictionaryAttackMitigationEnabled(bool* is_enabled) = 0;

  // Get TPM hardware and software version information.
  virtual bool GetVersionInfo(uint32_t* family,
                              uint64_t* spec_level,
                              uint32_t* manufacturer,
                              uint32_t* tpm_model,
                              uint64_t* firmware_version,
                              std::vector<uint8_t>* vendor_specific) = 0;

  // Checks TPM support for U2F.
  virtual bool SupportU2f() = 0;

  // Checks TPM support for Pinweaver.
  virtual bool SupportPinweaver() = 0;

  // Get the GSC version.
  virtual GscVersion GetGscVersion() = 0;

  // Get the RO verification status.
  virtual bool GetRoVerificationStatus(
      tpm_manager::RoVerificationStatus* status) = 0;

  // Marks the random owner password is set.
  //
  // NOTE: This method should be used by TPM 1.2 only.
  virtual void MarkRandomOwnerPasswordSet() = 0;

  // Gets alerts data the TPM
  //
  // Parameters
  //   alerts (OUT) - Struct that contains TPM alerts information
  // Returns true is hardware supports Alerts reporting, false otherwise
  virtual bool GetAlertsData(AlertsData* alerts) = 0;

  // Gets Ti50 specific metrics filesystem init time, filesystem size, AP RO
  // verification time, and expanded AP RO verification status.
  virtual bool GetTi50Stats(uint32_t* fs_init_time,
                            uint32_t* fs_size,
                            uint32_t* aprov_time,
                            uint32_t* aprov_status) = 0;
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_TPM_STATUS_H_
