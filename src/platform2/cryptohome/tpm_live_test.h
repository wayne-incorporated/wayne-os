// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Test methods that run on a real TPM.
// Note: the TPM must be owned in order for all tests to work correctly.

#ifndef CRYPTOHOME_TPM_LIVE_TEST_H_
#define CRYPTOHOME_TPM_LIVE_TEST_H_

#include <map>
#include <memory>
#include <string>

#include <base/logging.h>
#include <brillo/secure_blob.h>
#include <libhwsec/factory/factory.h>

#include "cryptohome/cryptohome_keys_manager.h"
#include "cryptohome/fake_platform.h"

namespace cryptohome {

using TPMTestCallback = base::OnceCallback<void(bool status)>;

class TpmLiveTest {
 public:
  TpmLiveTest();
  TpmLiveTest(const TpmLiveTest&) = delete;
  TpmLiveTest& operator=(const TpmLiveTest&) = delete;

  ~TpmLiveTest() = default;

  // These tests check TPM-bound AuthBlocks work correctly.
  void TpmEccAuthBlockTest(TPMTestCallback callback);
  void TpmBoundToPcrAuthBlockTest(TPMTestCallback callback);
  void TpmNotBoundToPcrAuthBlockTest(TPMTestCallback callback);

  // This test checks if we can create and load an RSA decryption key and use
  // it to encrypt and decrypt.
  bool DecryptionKeyTest();

  // This test checks if we can seal and unseal a blob to current state using
  // some authorization value.
  bool SealWithCurrentUserTest();

  // This test checks the signature-sealed secret creation and its unsealing. A
  // random RSA key is used.
  bool SignatureSealedSecretTest();

  // This test checks the recovery TPM backend's key import/sealing and
  // load/unsealing.
  bool RecoveryTpmBackendTest();

 private:
  // Helper method to try to encrypt and decrypt some data.
  bool EncryptAndDecryptData(const brillo::SecureBlob& pcr_bound_key,
                             const std::map<uint32_t, brillo::Blob>& pcr_map);

  FakePlatform platform_;
  std::unique_ptr<hwsec::Factory> hwsec_factory_;
  std::unique_ptr<const hwsec::CryptohomeFrontend> hwsec_;
  std::unique_ptr<const hwsec::RecoveryCryptoFrontend> recovery_crypto_;
  CryptohomeKeysManager cryptohome_keys_manager_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_TPM_LIVE_TEST_H_
