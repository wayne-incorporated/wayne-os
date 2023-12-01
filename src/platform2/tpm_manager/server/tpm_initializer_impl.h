// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_TPM_INITIALIZER_IMPL_H_
#define TPM_MANAGER_SERVER_TPM_INITIALIZER_IMPL_H_

#include <string>
#include <vector>

#include <tpm_manager/proto_bindings/tpm_manager.pb.h>
#include <trousers/tss.h>

#include "tpm_manager/common/typedefs.h"
#include "tpm_manager/server/openssl_crypto_util_impl.h"
#include "tpm_manager/server/tpm_connection.h"
#include "tpm_manager/server/tpm_initializer.h"

namespace tpm_manager {

class LocalDataStore;
class TpmStatus;

// This class initializes a Tpm1.2 chip by taking ownership. Example use of
// this class is:
// LocalDataStore data_store;
// TpmStatusImpl status;
// OwnershipTakenCallBack callback;
// TpmInitializerImpl initializer(&data_store, &status, callback);
// initializer.InitializeTpm();
//
// If the tpm is unowned, InitializeTpm injects a random owner password,
// initializes and unrestricts the SRK, and persists the owner password to disk
// until all the owner dependencies are satisfied.
//
// The ownership taken callback must be provided when the tpm initializer is
// constructed and stay alive during the entire lifetime of the tpm initializer.
class TpmInitializerImpl : public TpmInitializer {
 public:
  // Does not take ownership of |local_data_store| or |tpm_status|.
  TpmInitializerImpl(LocalDataStore* local_data_store, TpmStatus* tpm_status);
  TpmInitializerImpl(const TpmInitializerImpl&) = delete;
  TpmInitializerImpl& operator=(const TpmInitializerImpl&) = delete;

  ~TpmInitializerImpl() override = default;

  // TpmInitializer methods.
  bool InitializeTpm(bool* already_owned) override;
  bool PreInitializeTpm() override;
  bool EnsurePersistentOwnerDelegate() override;
  void VerifiedBootHelper() override;
  DictionaryAttackResetStatus ResetDictionaryAttackLock() override;
  TpmInitializerStatus DisableDictionaryAttackMitigation() override;
  void PruneStoredPasswords() override;
  // This method changes old owner password with a new owner password.
  // Returns true on success, else false.
  bool ChangeOwnerPassword(const std::string& old_password,
                           const std::string& new_password) override;

 private:
  // This method checks if an EndorsementKey exists on the Tpm and creates it
  // if not. Returns true on success, else false.
  bool InitializeEndorsementKey();

  // This method takes ownership of the Tpm with the default TSS password.
  // Returns true on success, else false. The |connection| already has the
  // default owner password injected.
  bool TakeOwnership(TpmConnection* connection);

  // This method initializes the SRK if it does not exist, zero's the SRK
  // password and unrestricts its usage. Returns true on success, else false.
  // The |connection| already has the current owner password injected.
  bool InitializeSrk(TpmConnection* connection);

  // This method changes the Tpm owner password from the default TSS password
  // to the password provided in the |owner_password| argument.
  // Returns true on success, else false. The |connection| already has the old
  // owner password injected.
  bool ChangeOwnerPassword(TpmConnection* connection,
                           const std::string& owner_password);

  // Reads owner password and delegate from local data and stores them in
  // |owner_password| and |owner_delegate| respectively. For each input arg, if
  // it's nullptr, it will be ignored and neither written nor considered as an
  // error.
  //
  // Returns whether the read was successful.
  bool ReadOwnerAuthFromLocalData(std::string* owner_password,
                                  AuthDelegate* owner_delegate);

  // Creates delegate with the default label and store the result in |delegate|.
  // Returns |true| iff the operation succeeds.
  bool CreateDelegateWithDefaultLabel(AuthDelegate* delegate);

  // Creates a TPM owner delegate for future use.
  //
  // Parameters
  //   bound_pcrs - Specifies the PCRs to which the delegate is bound.
  //   delegate_family_label - Specifies the label of the created delegate
  //                           family. Should be equal to
  //                           |kDefaultDelegateFamilyLabel| in most cases. Non-
  //                           default values are primarily intended for testing
  //                           purposes.
  //   delegate_label - Specifies the label of the created delegate. Should be
  //                    equal to |kDefaultDelegateLabel| in most cases. Non-
  //                    default values are primarily intended for testing
  //                    purposes.
  //   delegate_blob - The blob for the owner delegate.
  //   delegate_secret - The delegate secret that will be required to perform
  //                     privileged operations in the future.
  bool CreateAuthDelegate(const std::vector<uint32_t>& bound_pcrs,
                          uint8_t delegate_family_label,
                          uint8_t delegate_label,
                          std::string* delegate_blob,
                          std::string* delegate_secret);

  // Retrieves a |data| attribute defined by |flag| and |sub_flag| from a TSS
  // |object_handle|. The |context_handle| is only used for TSS memory
  // management.
  bool GetDataAttribute(TSS_HCONTEXT context,
                        TSS_HOBJECT object,
                        TSS_FLAG flag,
                        TSS_FLAG sub_flag,
                        std::string* data);

  OpensslCryptoUtilImpl openssl_util_;
  LocalDataStore* local_data_store_;
  TpmStatus* tpm_status_;

  // If set, an auth error was encountered in a previous attempt of resetting DA
  // lock, and there was no auth update after the attempt.
  bool reset_da_lock_auth_failed_ = false;
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_TPM_INITIALIZER_IMPL_H_
