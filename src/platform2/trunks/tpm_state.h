// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_TPM_STATE_H_
#define TRUNKS_TPM_STATE_H_

#include <string>

#include "trunks/tpm_generated.h"
#include "trunks/trunks_export.h"

namespace trunks {

// TpmState is an interface which provides access to TPM state information.
class TRUNKS_EXPORT TpmState {
 public:
  TpmState() {}
  TpmState(const TpmState&) = delete;
  TpmState& operator=(const TpmState&) = delete;

  virtual ~TpmState() {}

  // Initializes based on the current TPM state. This method must be called once
  // before any other method. It may be called multiple times to refresh the
  // state information.
  virtual TPM_RC Initialize() = 0;

  // Returns true iff TPMA_PERMANENT:ownerAuthSet is set.
  virtual bool IsOwnerPasswordSet() = 0;

  // Returns true iff TPMA_PERMANENT:endorsementAuthSet is set.
  virtual bool IsEndorsementPasswordSet() = 0;

  // Returns true iff TPMA_PERMANENT:lockoutAuthSet is set.
  virtual bool IsLockoutPasswordSet() = 0;

  // Returns true iff owner, endorsement and lockout passwords are set.
  virtual bool IsOwned() = 0;

  // Returns true iff TPMA_PERMANENT:inLockout is set.
  virtual bool IsInLockout() = 0;

  // Returns true iff TPMA_STARTUP_CLEAR:phEnable is set.
  virtual bool IsPlatformHierarchyEnabled() = 0;

  // Returns true iff TPMA_STARTUP_CLEAR:shEnable is set.
  virtual bool IsStorageHierarchyEnabled() = 0;

  // Returns true iff TPMA_STARTUP_CLEAR:ehEnable is set.
  virtual bool IsEndorsementHierarchyEnabled() = 0;

  // Returns true iff shEnable and ehEnable are set and phEnable is clear.
  virtual bool IsEnabled() = 0;

  // Returns true iff TPMA_STARTUP_CLEAR:orderly is set.
  virtual bool WasShutdownOrderly() = 0;

  // Returns true iff the TPM supports RSA-2048 keys.
  virtual bool IsRSASupported() = 0;

  // Returns true iff the TPM supports the ECC NIST P-256 curve.
  virtual bool IsECCSupported() = 0;

  // Returns the current value of the Lockout counter.
  virtual uint32_t GetLockoutCounter() = 0;

  // Returns the maximum lockout failures allowed before the TPM goes into
  // lockout.
  virtual uint32_t GetLockoutThreshold() = 0;

  // Returns the number of seconds before the lockout counter will decrement.
  virtual uint32_t GetLockoutInterval() = 0;

  // Returns the number of seconds after a LockoutAuth failure before
  // LockoutAuth can be used again.
  virtual uint32_t GetLockoutRecovery() = 0;

  // Returns the maximum size, in bytes, of an NV index data area.
  virtual uint32_t GetMaxNVSize() = 0;

  // Returns the TPM family value. This is a 4-character string encoded in an
  // uint32_t, e.g. 0x322E3000 for "2.0".
  virtual uint32_t GetTpmFamily() = 0;

  // Returns the specification level implemented by the TPM.
  virtual uint32_t GetSpecificationLevel() = 0;

  // Returns the specification revision implemented by the TPM.
  virtual uint32_t GetSpecificationRevision() = 0;

  // Returns the manufacturer vendor ID for the TPM.
  virtual uint32_t GetManufacturer() = 0;

  // Returns the manufacturer-determined TPM model number.
  virtual uint32_t GetTpmModel() = 0;

  // Returns the version number of the firmware running on the TPM.
  virtual uint64_t GetFirmwareVersion() = 0;

  // Returns the vendor ID string.
  virtual std::string GetVendorIDString() = 0;

  // Gets the |value| of any |property|. |value| may be NULL. Returns false if
  // a value is not available for the property.
  virtual bool GetTpmProperty(TPM_PT property, uint32_t* value) = 0;

  // Gets |algorithm| |properties|. |properties| may be NULL. Returns false if
  // properties are not available for the algorithm.
  virtual bool GetAlgorithmProperties(TPM_ALG_ID algorithm,
                                      TPMA_ALGORITHM* properties) = 0;
};

}  // namespace trunks

#endif  // TRUNKS_TPM_STATE_H_
