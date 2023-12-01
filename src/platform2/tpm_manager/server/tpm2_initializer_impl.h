// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_TPM2_INITIALIZER_IMPL_H_
#define TPM_MANAGER_SERVER_TPM2_INITIALIZER_IMPL_H_

#include "tpm_manager/server/tpm_initializer.h"

#include <memory>
#include <string>

#include <trunks/trunks_factory.h>

#include "tpm_manager/common/typedefs.h"
#include "tpm_manager/server/local_data_store.h"
#include "tpm_manager/server/openssl_crypto_util.h"
#include "tpm_manager/server/openssl_crypto_util_impl.h"
#include "tpm_manager/server/tpm_status.h"

namespace tpm_manager {

// This class initializes a Tpm2.0 chip by taking ownership. Example use of
// this class is:
// LocalDataStore data_store;
// Tpm2StatusImpl status;
// OwnershipTakenCallBack callback;
// Tpm2InitializerImpl initializer(&data_store, &status, callback);
// initializer.InitializeTpm(&already_owned);
//
// If the tpm is unowned, InitializeTpm injects random owner, endorsement and
// lockout passwords, intializes the SRK with empty authorization, and persists
// the passwords to disk until all the owner dependencies are satisfied.
//
// The ownership taken callback must be provided when the tpm initializer is
// constructed and stay alive during the entire lifetime of the tpm initializer.
class Tpm2InitializerImpl : public TpmInitializer {
 public:
  // Does not take ownership of arguments.
  Tpm2InitializerImpl(const trunks::TrunksFactory& factory,
                      LocalDataStore* local_data_store,
                      TpmStatus* tpm_status);
  // Does not take ownership of arguments.
  Tpm2InitializerImpl(const trunks::TrunksFactory& factory,
                      OpensslCryptoUtil* openssl_util,
                      LocalDataStore* local_data_store,
                      TpmStatus* tpm_status);
  Tpm2InitializerImpl(const Tpm2InitializerImpl&) = delete;
  Tpm2InitializerImpl& operator=(const Tpm2InitializerImpl&) = delete;

  ~Tpm2InitializerImpl() override = default;

  // TpmInitializer methods.
  bool InitializeTpm(bool* already_owned) override;
  bool PreInitializeTpm() override;
  bool EnsurePersistentOwnerDelegate() override;
  void VerifiedBootHelper() override;
  DictionaryAttackResetStatus ResetDictionaryAttackLock() override;
  TpmInitializerStatus DisableDictionaryAttackMitigation() override;
  void PruneStoredPasswords() override;
  bool ChangeOwnerPassword(const std::string& old_password,
                           const std::string& new_password) override;

 private:
  // Seeds the onboard Tpm random number generator with random bytes from
  // Openssl, if the Tpm RNG has not been seeded yet. Returns true on success.
  bool SeedTpmRng();

  // Gets random bytes of length |num_bytes| and populates the string at
  // |random_data|. Returns true on success.
  bool GetTpmRandomData(size_t num_bytes, std::string* random_data);

  const trunks::TrunksFactory& trunks_factory_;
  OpensslCryptoUtilImpl default_openssl_util_;
  OpensslCryptoUtil* openssl_util_;
  LocalDataStore* local_data_store_;
  TpmStatus* tpm_status_;
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_TPM2_INITIALIZER_IMPL_H_
