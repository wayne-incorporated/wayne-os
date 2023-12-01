// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_LE_CREDENTIAL_MANAGER_IMPL_H_
#define CRYPTOHOME_LE_CREDENTIAL_MANAGER_IMPL_H_

#include "cryptohome/le_credential_manager.h"

#include <map>
#include <memory>
#include <optional>
#include <vector>

#include <libhwsec/frontend/pinweaver/frontend.h>

#include "cryptohome/sign_in_hash_tree.h"

namespace cryptohome {

// Class containing all logic pertaining to management of Low Entropy(LE)
// credentials. The stated aim of this class should be the following:
// - Provide an interface to Set and Remove credentials in the underlying
// storage.
// - Provide an interface to verify a credential.
//
// This class contains a SignInHashTree object, which is used to store and
// maintain the credentials on disk.
//
// It also contains a pointer to a TPM object which will be able to invoke the
// necessary commands on the TPM side, for verification.
class LECredentialManagerImpl : public LECredentialManager {
 public:
  explicit LECredentialManagerImpl(const hwsec::PinWeaverFrontend* pinweaver,
                                   const base::FilePath& le_basedir);

  virtual ~LECredentialManagerImpl() {}

  LECredStatus InsertCredential(
      const std::vector<hwsec::OperationPolicySetting>& policies,
      const brillo::SecureBlob& le_secret,
      const brillo::SecureBlob& he_secret,
      const brillo::SecureBlob& reset_secret,
      const DelaySchedule& delay_sched,
      std::optional<uint32_t> expiration_delay,
      uint64_t* ret_label) override;

  LECredStatus CheckCredential(uint64_t label,
                               const brillo::SecureBlob& le_secret,
                               brillo::SecureBlob* he_secret,
                               brillo::SecureBlob* reset_secret) override;

  LECredStatus ResetCredential(uint64_t label,
                               const brillo::SecureBlob& reset_secret,
                               bool strong_reset) override;

  LECredStatus RemoveCredential(uint64_t label) override;

  // Returns the number of wrong authentication attempts done since the label
  // was reset or created. Returns -1 if |label| is not present in the tree or
  // the tree is corrupted.
  int GetWrongAuthAttempts(uint64_t label) override;

  LECredStatusOr<uint32_t> GetDelayInSeconds(uint64_t label) override;

  LECredStatusOr<std::optional<uint32_t>> GetExpirationInSeconds(
      uint64_t label) override;

  LECredStatusOr<DelaySchedule> GetDelaySchedule(uint64_t label) override;

  LECredStatus InsertRateLimiter(
      uint8_t auth_channel,
      const std::vector<hwsec::OperationPolicySetting>& policies,
      const brillo::SecureBlob& reset_secret,
      const DelaySchedule& delay_sched,
      std::optional<uint32_t> expiration_delay,
      uint64_t* ret_label) override;

  LECredStatusOr<StartBiometricsAuthReply> StartBiometricsAuth(
      uint8_t auth_channel,
      uint64_t label,
      const brillo::Blob& client_nonce) override;

 private:
  // Helper to turn a label into an original credential. Helper for a lot of the
  // Get* functions which starts with a label and first need to turn it into a
  // credential to call the actual Pinweaver function they need to call.
  //
  // The le_operation_type string specifies the type parameter that will be
  // passed to ReportLEResult to report metrics on LE operation success and
  // failure.
  LECredStatusOr<brillo::Blob> GetCredentialMetadata(
      uint64_t label, const char* le_operation_type);

  // Since the InsertCredential() and InsertRateLimiter() functions are very
  // similar, this function combines the common parts of both the calls
  // into a generic "insert leaf" function. |auth_channel| is only valid in
  // InsertRateLimiter(), while |le_secret| and |he_secret| is only valid in
  // InsertCredential(). |is_rate_limiter| is used to signal whether the leaf
  // being inserted is a rate-limiter (true) or a normal credential (false).
  //
  // On success, returns OkStatus and stores the
  // newly provisioned label in |ret_label|.
  //
  // On failure, returns status with:
  // - LE_CRED_ERROR_NO_FREE_LABEL if there is no free label.
  // - LE_CRED_ERROR_HASH_TREE if there was an error in the hash tree.
  //
  // The returned label should be placed into the metadata associated with the
  // authentication factor. so that it can be used to look up the credential
  // later.
  LECredStatus InsertLeaf(
      uint8_t* auth_channel,
      const std::vector<hwsec::OperationPolicySetting>& policies,
      const brillo::SecureBlob* le_secret,
      const brillo::SecureBlob* he_secret,
      const brillo::SecureBlob& reset_secret,
      const DelaySchedule& delay_sched,
      std::optional<uint32_t> expiration_delay,
      bool is_rate_limiter,
      uint64_t* ret_label);

  // Since the CheckCredential() and ResetCredential() functions are very
  // similar, this function combines the common parts of both the calls
  // into a generic "check credential" function. The label to be checked
  // is stored in |label|, the secret to be verified is in |secret|, the
  // high entropy credential and reset secret which gets released on successful
  // verification are stored in |he_secret| and |reset_secret|. A flag
  // |is_le_secret| is used to signal whether the secret being checked is the LE
  // secret (true) or the reset secret (false).
  //
  // Returns OkStatus on success.
  //
  // On failure, returns a status with:
  // - LE_CRED_ERROR_INVALID_LE_SECRET for incorrect LE authentication attempt.
  // - LE_CRED_ERROR_INVALID_RESET_SECRET for incorrect reset secret.
  // incorrect attempts).
  // - LE_CRED_ERROR_HASH_TREE for error in hash tree.
  // - LE_CRED_ERROR_INVALID_LABEL for invalid label.
  // - LE_CRED_ERROR_INVALID_METADATA for invalid credential metadata.
  // - LE_CRED_ERROR_PCR_NOT_MATCH if the PCR registers from TPM have unexpected
  // values, in which case only reboot will allow this user to authenticate.
  LECredStatus CheckSecret(uint64_t label,
                           const brillo::SecureBlob& secret,
                           brillo::SecureBlob* he_secret,
                           brillo::SecureBlob* reset_secret,
                           bool strong_reset,
                           bool is_le_secret);

  // Helper function to perform RemoveCredential. The |during_sync| param is
  // provided because RemoveCredential is one of the steps need to be performed
  // during a sync. If it checks Sync() again, there might potentially be a
  // infinite recursion.
  LECredStatus RemoveCredentialInternal(uint64_t label, bool during_sync);

  // Helper function to retrieve the credential metadata, MAC, and auxiliary
  // hashes associated with a label |label| (stored in |cred_metadata|, |mac|
  // and |h_aux| respectively). |metadata_lost| will denote whether the label
  // contains valid metadata (false) or not (true).
  //
  // Returns OkStatus on success.
  // On failure, returns a status with:
  // - LE_CRED_ERROR_INVALID_LABEL if the label provided doesn't exist.
  // - LE_CRED_ERROR_HASH_TREE if there was hash tree error (possibly out of
  // sync).
  LECredStatus RetrieveLabelInfo(const SignInHashTree::Label& label,
                                 brillo::Blob* cred_metadata,
                                 brillo::Blob* mac,
                                 std::vector<brillo::Blob>* h_aux,
                                 bool* metadata_lost);

  // Given a label, gets the list of auxiliary hashes for that label.
  // On failure, returns an empty vector.
  std::vector<brillo::Blob> GetAuxHashes(const SignInHashTree::Label& label);

  // Converts the error returned from LECredentialBackend to the equivalent
  // LECredError.
  LECredError BackendErrorToCredError(
      hwsec::PinWeaverFrontend::CredentialTreeResult::ErrorCode err);

  // Converts the error returned from LECredentialBackend to a LECredStatus.
  LECredStatus ConvertTpmError(
      hwsec::PinWeaverFrontend::CredentialTreeResult::ErrorCode err);

  // Performs checks to ensure the SignInHashTree is in sync with the tree
  // state in the LECredentialBackend. If there is an out-of-sync situation,
  // this function also attempts to get the HashTree back in sync.
  //
  // Returns true on successful synchronization, and false on failure. On
  // failure, |is_locked_| will be set to true, to prevent further
  // operations during the class lifecycle.
  bool Sync();

  // Replays the InsertCredential operation using the information provided
  // from the log entry from the LE credential backend.
  // |label| denotes which label to perform the operation on,
  // |log_root| is what the root hash should be after this operation is
  // completed. It should directly be used from the log entry.
  // |mac| is the MAC of the credential which has to be inserted.
  //
  // Returns true on success, false on failure.
  //
  // NOTE: A replayed insert is unusable and should be deleted after the replay
  // is complete.
  bool ReplayInsert(uint64_t label,
                    const brillo::Blob& log_root,
                    const brillo::Blob& mac);

  // Replays the CheckCredential / ResetCredential operation using the
  // information provided from the log entry from the LE credential
  // backend.
  // |label| denotes which credential label to perform the operation on.
  // |log_root| is what the root hash should be after this operation is
  // completed. It should directly be used from the log entry.
  // |is_full_replay| is whether the log_replay is done with successfully
  // locating the current root hash in the log entries, or done with replaying
  // using all entries.
  //
  // Returns true on success, false on failure.
  bool ReplayCheck(uint64_t label,
                   const brillo::Blob& log_root,
                   bool is_full_replay);

  // Resets the HashTree.
  bool ReplayResetTree();

  // Replays the RemoveCredential for |label| which is provided from
  // the LE Backend Replay logs.
  //
  // Returns true on success, false otherwise.
  bool ReplayRemove(uint64_t label);

  // Replays all the log operations provided in |log|, and makes the
  // corresponding updates to the HashTree.
  bool ReplayLogEntries(
      const std::vector<hwsec::PinWeaverFrontend::GetLogResult::LogEntry>& log,
      const brillo::Blob& disk_root_hash);

  // Last resort flag which prevents any further Low Entropy operations from
  // occurring, till the next time the class is instantiated.
  // This is used in a situation where an operation succeeds on the TPM,
  // but its on-disk counterpart fails. In this case, the mitigation strategy
  // is as follows:
  // - Prevent any further LE operations, to prevent disk and TPM from
  // going further out of state, till next reboot.
  // - Hope that on reboot, the problems causing disk failure don't recur,
  // and the TPM replay log will enable the disk state to get in sync with
  // the TPM again.
  //
  // We will collect UMA stats from the field and refine this strategy
  // as required.
  bool is_locked_;
  // Pointer to an implementation of the pinweaver operations.
  const hwsec::PinWeaverFrontend* pinweaver_;
  // In-memory copy of LEBackend's root hash value.
  brillo::Blob root_hash_;
  // Directory where all LE Credential related data is stored.
  base::FilePath basedir_;
  std::unique_ptr<SignInHashTree> hash_tree_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_LE_CREDENTIAL_MANAGER_IMPL_H_
