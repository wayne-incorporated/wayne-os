// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_LE_CREDENTIAL_MANAGER_H_
#define CRYPTOHOME_LE_CREDENTIAL_MANAGER_H_

#include <map>
#include <optional>
#include <vector>

#include <libhwsec/structures/operation_policy.h>

#include "cryptohome/error/cryptohome_le_cred_error.h"

namespace cryptohome {

// This is a pure virtual interface providing all the public methods necessary
// to work with the low entropy credential functionality.
class LECredentialManager {
 public:
  typedef std::map<uint32_t, uint32_t> DelaySchedule;

  struct StartBiometricsAuthReply {
    brillo::Blob server_nonce;
    brillo::Blob iv;
    brillo::Blob encrypted_he_secret;
  };

  virtual ~LECredentialManager() = default;

  // Inserts an LE credential into the system.
  //
  // The Low entropy credential is represented by |le_secret|, and the high
  // entropy and reset secrets by |he_secret| and |reset_secret| respectively.
  // The delay schedule which governs the rate at which CheckCredential()
  // attempts are allowed is provided in |delay_sched|. The expiration delay
  // which governs how long a credential expires after creation/reset is
  // provided in |expiration_delay|. Nullopt for |expiration_delay| means that
  // the credential won't expire. On success, returns OkStatus and stores the
  // newly provisioned label in |ret_label|. On failure, returns status with:
  // - LE_CRED_ERROR_NO_FREE_LABEL if there is no free label.
  // - LE_CRED_ERROR_HASH_TREE if there was an error in the hash tree.
  //
  // The returned label should be placed into the metadata associated with the
  // Encrypted Vault Key (EVK). so that it can be used to look up the credential
  // later.
  virtual LECredStatus InsertCredential(
      const std::vector<hwsec::OperationPolicySetting>& policies,
      const brillo::SecureBlob& le_secret,
      const brillo::SecureBlob& he_secret,
      const brillo::SecureBlob& reset_secret,
      const DelaySchedule& delay_sched,
      std::optional<uint32_t> expiration_delay,
      uint64_t* ret_label) = 0;

  // Attempts authentication for a LE Credential.
  //
  // Checks whether the LE credential |le_secret| for a |label| is correct.
  // Returns LE_CRED_SUCCESS on success. Additionally, the released
  // high entropy credential is placed in |he_secret| and the reset secret is
  // placed in |reset_secret| if CR50 version with protocol > 0 is used.
  //
  // On failure, returns status with:
  // LE_CRED_ERROR_INVALID_LE_SECRET for incorrect authentication attempt.
  // LE_CRED_ERROR_TOO_MANY_ATTEMPTS for locked out credential (too many
  // incorrect attempts). LE_CRED_ERROR_HASH_TREE for error in hash tree.
  // LE_CRED_ERROR_INVALID_LABEL for invalid label.
  // LE_CRED_ERROR_INVALID_METADATA for invalid credential metadata.
  // LE_CRED_ERROR_PCR_NOT_MATCH if the PCR registers from TPM have unexpected
  // values, in which case only reboot will allow this user to authenticate.
  virtual LECredStatus CheckCredential(uint64_t label,
                                       const brillo::SecureBlob& le_secret,
                                       brillo::SecureBlob* he_secret,
                                       brillo::SecureBlob* reset_secret) = 0;

  // Attempts reset of a LE Credential. |strong_reset| indicates whether the
  // expiration time should be reset (extended to |expiration_delay| seconds
  // from now) too.
  //
  // Returns LE_CRED_SUCCESS on success.
  //
  // On failure, returns status with:
  // - LE_CRED_ERROR_INVALID_RESET_SECRET for incorrect reset secret.
  // incorrect attempts).
  // - LE_CRED_ERROR_HASH_TREE for error in hash tree.
  // - LE_CRED_ERROR_INVALID_LABEL for invalid label.
  // - LE_CRED_ERROR_INVALID_METADATA for invalid credential metadata.
  virtual LECredStatus ResetCredential(uint64_t label,
                                       const brillo::SecureBlob& reset_secret,
                                       bool strong_reset) = 0;

  // Remove a credential at node with label |label|.
  //
  // Returns OkStatus on success.
  // On failure, returns status with:
  // - LE_CRED_ERROR_INVALID_LABEL for invalid label.
  // - LE_CRED_ERROR_HASH_TREE for hash tree error.
  virtual LECredStatus RemoveCredential(uint64_t label) = 0;

  // Returns the number of wrong authentication attempts done since the label
  // was reset or created. Returns -1 if |label| is not present in the tree or
  // the tree is corrupted.
  virtual int GetWrongAuthAttempts(uint64_t label) = 0;

  // Returns the delay in seconds.
  virtual LECredStatusOr<uint32_t> GetDelayInSeconds(uint64_t label) = 0;

  // Get the remaining time until the credential expires, in seconds. Nullopt
  // means the credential won't expire. 0 means the credential already expired.
  virtual LECredStatusOr<std::optional<uint32_t>> GetExpirationInSeconds(
      uint64_t label) = 0;

  // Returns the delay schedule for a credential.
  virtual LECredStatusOr<DelaySchedule> GetDelaySchedule(uint64_t label) = 0;

  // Inserts an biometrics rate-limiter into the system.
  //
  // The can be reset by the reset secret |reset_secret|.
  // The delay schedule which governs the rate at which CheckCredential()
  // attempts are allowed is provided in |delay_sched|. The expiration delay
  // which governs how long a credential expires after creation/reset is
  // provided in |expiration_delay|. Nullopt for |expiration_delay| means that
  // the credential won't expire.
  //
  // On success, returns OkStatus and stores the
  // newly provisioned label in |ret_label|.
  //
  // On failure, returns status with:
  // - LE_CRED_ERROR_NO_FREE_LABEL if there is no free label.
  // - LE_CRED_ERROR_HASH_TREE if there was an error in the hash tree.
  //
  // The returned label should be placed into the metadata associated with the
  // Encrypted Vault Key (EVK). so that it can be used to look up the credential
  // later.
  virtual LECredStatus InsertRateLimiter(
      uint8_t auth_channel,
      const std::vector<hwsec::OperationPolicySetting>& policies,
      const brillo::SecureBlob& reset_secret,
      const DelaySchedule& delay_sched,
      std::optional<uint32_t> expiration_delay,
      uint64_t* ret_label) = 0;

  // Starts an authentication attempt with a rate-limiter.
  //
  // The |client_nonce| is used to perform session key exchange, which is then
  // used for encrypting the |encrypted_he_secret| released on success.
  //
  // On failure, returns status with:
  // LE_CRED_ERROR_INVALID_LE_SECRET for incorrect authentication attempt.
  // LE_CRED_ERROR_TOO_MANY_ATTEMPTS for locked out credential (too many
  // incorrect attempts).
  // LE_CRED_ERROR_HASH_TREE for error in hash tree.
  // LE_CRED_ERROR_INVALID_LABEL for invalid label.
  // LE_CRED_ERROR_INVALID_METADATA for invalid credential metadata.
  // LE_CRED_ERROR_PCR_NOT_MATCH if the PCR registers from TPM have unexpected
  // values, in which case only reboot will allow this user to authenticate.
  // LE_CRED_EXPIRED for expired credential.
  virtual LECredStatusOr<StartBiometricsAuthReply> StartBiometricsAuth(
      uint8_t auth_channel,
      uint64_t label,
      const brillo::Blob& client_nonce) = 0;
};

};  // namespace cryptohome

#endif  // CRYPTOHOME_LE_CREDENTIAL_MANAGER_H_
