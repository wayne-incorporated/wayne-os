// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM1_BACKEND_H_
#define LIBHWSEC_BACKEND_TPM1_BACKEND_H_

#include <memory>
#include <optional>

#include "libhwsec/backend/backend.h"
#include "libhwsec/backend/tpm1/attestation.h"
#include "libhwsec/backend/tpm1/config.h"
#include "libhwsec/backend/tpm1/da_mitigation.h"
#include "libhwsec/backend/tpm1/deriving.h"
#include "libhwsec/backend/tpm1/encryption.h"
#include "libhwsec/backend/tpm1/key_management.h"
#include "libhwsec/backend/tpm1/pinweaver.h"
#include "libhwsec/backend/tpm1/random.h"
#include "libhwsec/backend/tpm1/recovery_crypto.h"
#include "libhwsec/backend/tpm1/sealing.h"
#include "libhwsec/backend/tpm1/signature_sealing.h"
#include "libhwsec/backend/tpm1/signing.h"
#include "libhwsec/backend/tpm1/state.h"
#include "libhwsec/backend/tpm1/storage.h"
#include "libhwsec/backend/tpm1/tss_helper.h"
#include "libhwsec/backend/tpm1/u2f.h"
#include "libhwsec/backend/tpm1/vendor.h"
#include "libhwsec/backend/tpm1/version_attestation.h"
#include "libhwsec/middleware/middleware_derivative.h"

#ifndef BUILD_LIBHWSEC
#error "Don't include this file outside libhwsec!"
#endif

namespace hwsec {

class BackendTpm1 : public Backend {
 public:
  BackendTpm1(Proxy& proxy, MiddlewareDerivative middleware_derivative);

  ~BackendTpm1() override;

  TssHelper& GetTssHelper() { return tss_helper_; }

  StateTpm1& GetStateTpm1() { return state_; }
  DAMitigationTpm1& GetDAMitigationTpm1() { return da_mitigation_; }
  StorageTpm1& GetStorageTpm1() { return storage_; }
  SealingTpm1& GetSealingTpm1() { return sealing_; }
  SignatureSealingTpm1& GetSignatureSealingTpm1() { return signature_sealing_; }
  DerivingTpm1& GetDerivingTpm1() { return deriving_; }
  EncryptionTpm1& GetEncryptionTpm1() { return encryption_; }
  SigningTpm1& GetSigningTpm1() { return signing_; }
  KeyManagementTpm1& GetKeyManagementTpm1() { return key_management_; }
  ConfigTpm1& GetConfigTpm1() { return config_; }
  RandomTpm1& GetRandomTpm1() { return random_; }
  PinWeaverTpm1& GetPinWeaverTpm1() { return pinweaver_; }
  VendorTpm1& GetVendorTpm1() { return vendor_; }
  RecoveryCryptoTpm1& GetRecoveryCryptoTpm1() { return recovery_crypto_; }
  U2fTpm1& GetU2fTpm1() { return u2f_; }
  AttestationTpm1& GetAttestationTpm1() { return attestation_; }
  VersionAttestationTpm1& GetVersionAttestationTpm1() {
    return version_attestation_;
  }

  void set_middleware_derivative_for_test(
      MiddlewareDerivative middleware_derivative) {
    middleware_derivative_ = middleware_derivative;
  }

 private:
  State* GetState() override { return &state_; }
  DAMitigation* GetDAMitigation() override { return &da_mitigation_; }
  Storage* GetStorage() override { return &storage_; }
  RoData* GetRoData() override { return nullptr; }
  Sealing* GetSealing() override { return &sealing_; }
  SignatureSealing* GetSignatureSealing() override {
    return &signature_sealing_;
  }
  Deriving* GetDeriving() override { return &deriving_; }
  Encryption* GetEncryption() override { return &encryption_; }
  Signing* GetSigning() override { return &signing_; }
  KeyManagement* GetKeyManagement() override { return &key_management_; }
  SessionManagement* GetSessionManagement() override { return nullptr; }
  Config* GetConfig() override { return &config_; }
  Random* GetRandom() override { return &random_; }
  PinWeaver* GetPinWeaver() override { return &pinweaver_; }
  Vendor* GetVendor() override { return &vendor_; }
  RecoveryCrypto* GetRecoveryCrypto() override { return &recovery_crypto_; }
  U2f* GetU2f() override { return &u2f_; }
  Attestation* GetAttestation() override { return &attestation_; }
  VersionAttestation* GetVersionAttestation() override {
    return &version_attestation_;
  }

  Proxy& proxy_;
  org::chromium::TpmManagerProxyInterface& tpm_manager_;
  org::chromium::TpmNvramProxyInterface& tpm_nvram_;
  overalls::Overalls& overalls_;
  crossystem::Crossystem& crossystem_;

  MiddlewareDerivative middleware_derivative_;

  TssHelper tss_helper_;

  StateTpm1 state_;
  DAMitigationTpm1 da_mitigation_;
  StorageTpm1 storage_;
  ConfigTpm1 config_;
  RandomTpm1 random_;
  KeyManagementTpm1 key_management_;
  SealingTpm1 sealing_;
  DerivingTpm1 deriving_;
  SignatureSealingTpm1 signature_sealing_;
  EncryptionTpm1 encryption_;
  SigningTpm1 signing_;
  PinWeaverTpm1 pinweaver_;
  VendorTpm1 vendor_;
  RecoveryCryptoTpm1 recovery_crypto_;
  U2fTpm1 u2f_;
  AttestationTpm1 attestation_;
  VersionAttestationTpm1 version_attestation_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM1_BACKEND_H_
