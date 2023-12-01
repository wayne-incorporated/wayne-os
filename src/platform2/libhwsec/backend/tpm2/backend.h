// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM2_BACKEND_H_
#define LIBHWSEC_BACKEND_TPM2_BACKEND_H_

#include <memory>
#include <trunks/command_transceiver.h>
#include <trunks/trunks_factory.h>

#include "libhwsec/backend/backend.h"
#include "libhwsec/backend/tpm2/attestation.h"
#include "libhwsec/backend/tpm2/config.h"
#include "libhwsec/backend/tpm2/da_mitigation.h"
#include "libhwsec/backend/tpm2/deriving.h"
#include "libhwsec/backend/tpm2/encryption.h"
#include "libhwsec/backend/tpm2/key_management.h"
#include "libhwsec/backend/tpm2/pinweaver.h"
#include "libhwsec/backend/tpm2/random.h"
#include "libhwsec/backend/tpm2/recovery_crypto.h"
#include "libhwsec/backend/tpm2/ro_data.h"
#include "libhwsec/backend/tpm2/sealing.h"
#include "libhwsec/backend/tpm2/session_management.h"
#include "libhwsec/backend/tpm2/signature_sealing.h"
#include "libhwsec/backend/tpm2/signing.h"
#include "libhwsec/backend/tpm2/state.h"
#include "libhwsec/backend/tpm2/storage.h"
#include "libhwsec/backend/tpm2/trunks_context.h"
#include "libhwsec/backend/tpm2/u2f.h"
#include "libhwsec/backend/tpm2/vendor.h"
#include "libhwsec/backend/tpm2/version_attestation.h"
#include "libhwsec/middleware/middleware_derivative.h"
#include "libhwsec/proxy/proxy.h"

#ifndef BUILD_LIBHWSEC
#error "Don't include this file outside libhwsec!"
#endif

namespace hwsec {

class BackendTpm2 : public Backend {
 public:
  BackendTpm2(Proxy& proxy, MiddlewareDerivative middleware_derivative);

  ~BackendTpm2() override;

  StateTpm2& GetStateTpm2() { return state_; }
  DAMitigationTpm2& GetDAMitigationTpm2() { return da_mitigation_; }
  StorageTpm2& GetStorageTpm2() { return storage_; }
  RoDataTpm2& GetRoDataTpm2() { return ro_data_; }
  SealingTpm2& GetSealingTpm2() { return sealing_; }
  SignatureSealingTpm2& GetSignatureSealingTpm2() { return signature_sealing_; }
  DerivingTpm2& GetDerivingTpm2() { return deriving_; }
  EncryptionTpm2& GetEncryptionTpm2() { return encryption_; }
  SigningTpm2& GetSigningTpm2() { return signing_; }
  KeyManagementTpm2& GetKeyManagementTpm2() { return key_management_; }
  SessionManagementTpm2& GetSessionManagementTpm2() {
    return session_management_;
  }
  ConfigTpm2& GetConfigTpm2() { return config_; }
  RandomTpm2& GetRandomTpm2() { return random_; }
  PinWeaverTpm2& GetPinWeaverTpm2() { return pinweaver_; }
  VendorTpm2& GetVendorTpm2() { return vendor_; }
  RecoveryCryptoTpm2& GetRecoveryCryptoTpm2() { return recovery_crypto_; }
  U2fTpm2& GetU2fTpm2() { return u2f_; }
  AttestationTpm2& GetAttestationTpm2() { return attestation_; }
  VersionAttestationTpm2& GetVersionAttestationTpm2() {
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
  RoData* GetRoData() override { return &ro_data_; }
  Sealing* GetSealing() override { return &sealing_; }
  SignatureSealing* GetSignatureSealing() override {
    return &signature_sealing_;
  }
  Deriving* GetDeriving() override { return &deriving_; }
  Encryption* GetEncryption() override { return &encryption_; }
  Signing* GetSigning() override { return &signing_; }
  KeyManagement* GetKeyManagement() override { return &key_management_; }
  SessionManagement* GetSessionManagement() override {
    return &session_management_;
  }
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
  crossystem::Crossystem& crossystem_;

  MiddlewareDerivative middleware_derivative_;

  TrunksContext context_;

  StateTpm2 state_;
  DAMitigationTpm2 da_mitigation_;
  SessionManagementTpm2 session_management_;
  ConfigTpm2 config_;
  StorageTpm2 storage_;
  KeyManagementTpm2 key_management_;
  SealingTpm2 sealing_;
  SignatureSealingTpm2 signature_sealing_;
  DerivingTpm2 deriving_;
  EncryptionTpm2 encryption_;
  SigningTpm2 signing_;
  RandomTpm2 random_;
  PinWeaverTpm2 pinweaver_;
  VendorTpm2 vendor_;
  RecoveryCryptoTpm2 recovery_crypto_;
  U2fTpm2 u2f_;
  AttestationTpm2 attestation_;
  RoDataTpm2 ro_data_;
  VersionAttestationTpm2 version_attestation_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM2_BACKEND_H_
