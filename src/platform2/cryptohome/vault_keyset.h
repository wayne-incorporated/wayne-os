// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_VAULT_KEYSET_H_
#define CRYPTOHOME_VAULT_KEYSET_H_

#include <memory>
#include <optional>
#include <string>

#include <base/compiler_specific.h>
#include <base/files/file_path.h>
#include <base/gtest_prod_util.h>
#include <brillo/secure_blob.h>

#include "cryptohome/crypto.h"
#include "cryptohome/cryptohome_common.h"
#include "cryptohome/error/cryptohome_crypto_error.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "cryptohome/key_objects.h"
#include "cryptohome/username.h"
#include "cryptohome/vault_keyset.pb.h"

namespace cryptohome {

class FileSystemKeyset;
class Platform;

// VaultKeyset holds the File Encryption Key (FEK) and File Name Encryption Key
// (FNEK) and their corresponding signatures.
class VaultKeyset {
 public:
  // Constructors and destructors.
  VaultKeyset();
  VaultKeyset(VaultKeyset&&) = default;
  VaultKeyset(const VaultKeyset&) = default;
  VaultKeyset& operator=(const VaultKeyset&) = default;
  virtual ~VaultKeyset() = default;

  // Does not take ownership of platform and crypto. The objects pointed to by
  // them must outlive this object.
  virtual void Initialize(Platform* platform, Crypto* crypto);

  // This function initializes the VaultKeyset as a backup keyset by setting the
  // |backup_vk_| field to true. Does not take ownership of platform and crypto.
  // The objects pointed to by them must outlive this object.
  void InitializeAsBackup(Platform* platform, Crypto* crypto);

  // Populates the fields from a SerializedVaultKeyset.
  void InitializeFromSerialized(const SerializedVaultKeyset& serialized);

  // Populates the fields from a Vaultkeyset to add a new key for the user.
  virtual void InitializeToAdd(const VaultKeyset& vault_keyset);

  //  The following methods deal with importing another object type into this
  //  VaultKeyset container.
  virtual void FromKeys(const VaultKeysetKeys& keys);
  [[nodiscard]] virtual bool FromKeysBlob(const brillo::SecureBlob& keys_blob);

  // The following two methods export this VaultKeyset container to other
  // objects.
  [[nodiscard]] virtual bool ToKeys(VaultKeysetKeys* keys) const;
  [[nodiscard]] virtual bool ToKeysBlob(brillo::SecureBlob* keys_blob) const;

  // Do not call Load directly, use KeysetManagement::LoadVaultKeysetForUser.
  [[nodiscard]] virtual bool Load(const base::FilePath& filename);

  // Encrypt must be called first.
  virtual bool Save(const base::FilePath& filename);

  // Load must be called first.
  // Decrypts the encrypted fields of the VaultKeyset from serialized with the
  // provided |key_blobs|.
  virtual CryptoStatus DecryptEx(const KeyBlobs& key_blobs);

  // Encrypts the VaultKeyset fields with the provided |key_blobs| based on the
  // encryption mechanisms provided by the |auth_state|.
  virtual CryptohomeStatus EncryptEx(const KeyBlobs& key_blobs,
                                     const AuthBlockState& auth_state);

  // Convenience methods to initialize a new VaultKeyset with random values.
  virtual void CreateRandomChapsKey();
  virtual void CreateRandomResetSeed();
  virtual void CreateFromFileSystemKeyset(
      const FileSystemKeyset& file_system_keyset);

  // Methods to access runtime class state.
  virtual const base::FilePath& GetSourceFile() const;

  virtual void SetAuthLocked(bool locked);
  virtual bool GetAuthLocked() const;

  // Group 1. Methods to access plaintext metadata as stored in AuthBlockState.
  // Returns the SerializedVaultKeyset flags.
  virtual int32_t GetFlags() const;
  virtual void SetFlags(int32_t flags);

  // Getters and setters for the index. See the |legacy_index_| member for a
  // comment explaining the legacy name.
  virtual void SetLegacyIndex(int index);
  virtual const int GetLegacyIndex() const;

  virtual bool HasTpmPublicKeyHash() const;
  virtual const brillo::SecureBlob& GetTpmPublicKeyHash() const;
  virtual void SetTpmPublicKeyHash(const brillo::SecureBlob& hash);

  virtual bool HasPasswordRounds() const;
  virtual int32_t GetPasswordRounds() const;

  // TODO(b/205759690, dlunev): can be removed after a stepping stone release.
  virtual bool HasLastActivityTimestamp() const;
  virtual int64_t GetLastActivityTimestamp() const;

  virtual bool HasKeyData() const;
  virtual void SetKeyData(const KeyData& key_data);
  virtual void ClearKeyData();
  virtual const KeyData& GetKeyData() const;

  // Gets the KeyData or return default value if it's empty.
  virtual KeyData GetKeyDataOrDefault() const;

  // Gets the label from the KeyData.
  virtual std::string GetLabel() const;

  // Checks the key data policy for low entropy credential (not the flags).
  virtual bool IsLECredential() const;

  // Populates the le cred policy field in |key_data_|. |key_data_| is created
  // if empty. An LE credential is a PinWeaver credential.
  virtual void SetLowEntropyCredential(bool is_le_cred);

  // Checks the flags field if this is a signature challenge credential.
  virtual bool IsSignatureChallengeProtected() const;

  // Sets the label on |key_data_|. |key_data_| is created if empty.
  virtual void SetKeyDataLabel(const std::string& key_label);

  virtual void SetResetIV(const brillo::SecureBlob& iv);
  virtual bool HasResetIV() const;
  virtual const brillo::SecureBlob& GetResetIV() const;

  virtual void SetLELabel(uint64_t label);
  virtual bool HasLELabel() const;
  virtual uint64_t GetLELabel() const;

  virtual void SetLEFekIV(const brillo::SecureBlob& iv);
  virtual bool HasLEFekIV() const;
  virtual const brillo::SecureBlob& GetLEFekIV() const;

  virtual void SetLEChapsIV(const brillo::SecureBlob& iv);
  virtual bool HasLEChapsIV() const;
  virtual const brillo::SecureBlob& GetLEChapsIV() const;

  virtual void SetResetSalt(const brillo::SecureBlob& reset_salt);
  virtual bool HasResetSalt() const;
  virtual const brillo::SecureBlob& GetResetSalt() const;

  virtual void SetFSCryptPolicyVersion(int32_t policy_version);
  virtual bool HasFSCryptPolicyVersion() const;
  virtual int32_t GetFSCryptPolicyVersion() const;

  virtual bool HasVkkIv() const;
  virtual const brillo::SecureBlob& GetVkkIv() const;

  // Group 2. Fields containing wrapped data.

  virtual void SetWrappedKeyset(const brillo::SecureBlob& wrapped_keyset);
  virtual const brillo::SecureBlob& GetWrappedKeyset() const;

  virtual bool HasWrappedChapsKey() const;
  virtual void SetWrappedChapsKey(const brillo::SecureBlob& wrapped_chaps_key);
  virtual const brillo::SecureBlob& GetWrappedChapsKey() const;
  virtual void ClearWrappedChapsKey();

  virtual bool HasTPMKey() const;
  virtual void SetTPMKey(const brillo::SecureBlob& tpm_key);
  virtual const brillo::SecureBlob& GetTPMKey() const;

  virtual bool HasExtendedTPMKey() const;
  virtual void SetExtendedTPMKey(const brillo::SecureBlob& tpm_key);
  virtual const brillo::SecureBlob& GetExtendedTPMKey() const;

  virtual bool HasWrappedResetSeed() const;
  virtual void SetWrappedResetSeed(const brillo::SecureBlob& reset_seed);
  virtual const brillo::SecureBlob& GetWrappedResetSeed() const;

  virtual bool HasSignatureChallengeInfo() const;
  virtual const SerializedVaultKeyset::SignatureChallengeInfo&
  GetSignatureChallengeInfo() const;
  virtual void SetSignatureChallengeInfo(
      const SerializedVaultKeyset::SignatureChallengeInfo& info);

  // Group 3. Unwrapped data.

  virtual const brillo::SecureBlob& GetFek() const;
  virtual const brillo::SecureBlob& GetFekSig() const;
  virtual const brillo::SecureBlob& GetFekSalt() const;
  virtual const brillo::SecureBlob& GetFnek() const;
  virtual const brillo::SecureBlob& GetFnekSig() const;
  virtual const brillo::SecureBlob& GetFnekSalt() const;

  virtual void SetChapsKey(const brillo::SecureBlob& chaps_key);
  virtual const brillo::SecureBlob& GetChapsKey() const;
  virtual void ClearChapsKey();

  virtual void SetResetSeed(const brillo::SecureBlob& reset_seed);
  virtual const brillo::SecureBlob& GetResetSeed() const;

  virtual void SetResetSecret(const brillo::SecureBlob& reset_secret);
  virtual const brillo::SecureBlob& GetResetSecret() const;

  // This populates each sub type of AuthBlockState into the caller allocated
  // object.
  [[nodiscard]] bool GetTpmBoundToPcrState(AuthBlockState* auth_state) const;
  [[nodiscard]] bool GetTpmNotBoundToPcrState(AuthBlockState* auth_state) const;
  [[nodiscard]] bool GetPinWeaverState(AuthBlockState* auth_state) const;
  [[nodiscard]] bool GetSignatureChallengeState(
      AuthBlockState* auth_state) const;
  [[nodiscard]] bool GetScryptState(AuthBlockState* auth_state) const;
  [[nodiscard]] bool GetDoubleWrappedCompatState(
      AuthBlockState* auth_state) const;
  [[nodiscard]] bool GetTpmEccState(AuthBlockState* auth_state) const;

  // Reads an auth block state and update the VaultKeyset with what it
  // returns.
  void SetAuthBlockState(const AuthBlockState& auth_state);

  // Set each type of AuthBlockState's sub messages.
  void SetTpmNotBoundToPcrState(
      const TpmNotBoundToPcrAuthBlockState& auth_state);
  void SetTpmBoundToPcrState(const TpmBoundToPcrAuthBlockState& auth_state);
  void SetPinWeaverState(const PinWeaverAuthBlockState& auth_state);
  void SetScryptState(const ScryptAuthBlockState& auth_state);
  void SetChallengeCredentialState(
      const ChallengeCredentialAuthBlockState& auth_state);
  void SetTpmEccState(const TpmEccAuthBlockState& auth_state);

  // Returns whether the VaultKeyset is setup for backup purpose.
  bool IsForBackup() const { return backup_vk_; }
  // Returns whether the VaultKeyset is migrated to USS.
  bool IsMigrated() const { return migrated_vk_; }

  // Setter for the |backup_vk_|.
  void set_backup_vk_for_testing(bool value) { backup_vk_ = value; }

  // Setter for the |migrated_vk_|.
  void set_migrated_vk_for_testing(bool value) { migrated_vk_ = value; }

  // Marks the VaultKeyset migrated. Every migrated VaultKeyset to USS should be
  // set as a backup VaultKeyset for USS.
  void MarkMigrated(bool migrated);

 private:
  // Converts the class to a protobuf for serialization to disk.
  SerializedVaultKeyset ToSerialized() const;

  // Clears all the fields set from the SerializedVaultKeyset.
  void ResetVaultKeyset();

  // This function decrypts a keyset that is encrypted with a VaultKeysetKey.
  //
  // Parameters
  //   serialized - The serialized vault keyset protobuf.
  //   vkk_data - Key data includes the VaultKeysetKey to decrypt the serialized
  // keyset.
  // Return
  //   error - The specific error code on failure.
  CryptoStatus UnwrapVKKVaultKeyset(const SerializedVaultKeyset& serialized,
                                    const KeyBlobs& vkk_data);

  // This function decrypts a keyset that is encrypted with an scrypt derived
  // key.
  //
  // Parameters
  //   serialized - The serialized vault keyset protobuf.
  //   vkk_data - Key data that includes the scrypt derived keys.
  // Return
  //   error - The specific error code on failure.
  CryptoStatus UnwrapScryptVaultKeyset(const SerializedVaultKeyset& serialized,
                                       const KeyBlobs& vkk_data);

  // This function encrypts a keyset with a VaultKeysetKey.
  //
  // Parameters
  //   key_blobs - Key bloc that stores VaultKeysetKey.
  CryptohomeStatus WrapVaultKeysetWithAesDeprecated(const KeyBlobs& blobs);

  // This function encrypts a VaultKeyset with an scrypt derived key.
  //
  // Parameters
  //   auth_block_state - AuthBlockState that stores salts for scrypt wrapping.
  //   key_blobs - Key blob that stores scrypt derived keys.
  // Return
  //   error - The specific error code on failure.
  CryptohomeStatus WrapScryptVaultKeyset(const AuthBlockState& auth_block_state,
                                         const KeyBlobs& key_blobs);

  // This function consumes the Vault Keyset Key (VKK) and IV, and produces
  // the unwrapped secrets from the Vault Keyset.
  //
  // Parameters
  //   serialized - The serialized vault keyset protobuf.
  //   vkk_data - The VKK and the VKK IV.
  // Return
  //   error - The specific error code on failure.
  CryptoStatus UnwrapVaultKeyset(const SerializedVaultKeyset& serialized,
                                 const KeyBlobs& vkk_data);

  // Decrypts an encrypted vault keyset which is obtained from the unwrapped
  // secrets returned from UnwrapVaultKeyset() using the key_blobs.
  //
  // Parameters
  //   key_blobs - KeyBlobs to decrypt serialized VaultKeyset.
  // Return
  //   error - The specific error code on failure.
  CryptoStatus DecryptVaultKeysetEx(const KeyBlobs& key_blobs);

  // These store run time state for the class.
  Platform* platform_;
  Crypto* crypto_;
  bool loaded_;
  bool encrypted_;
  base::FilePath source_file_;

  // The following data members are grouped into three categories. Each category
  // should be split into a separate object in the future.

  // Group 1. AuthBlockState. This is metadata used to derive the keys,
  // persisted as plaintext.
  int32_t flags_;
  // Field to tag the VaultKeyset as a backup VaultKeyset for USS.
  bool backup_vk_;
  // Field to tag the VaultKeyset as a migrated VaultKeyset to USS.
  bool migrated_vk_;
  // The salt used to derive the user input in auth block.
  brillo::SecureBlob auth_salt_;
  // The IV used to encrypt the encryption key.
  std::optional<brillo::SecureBlob> vkk_iv_;
  // legacy_index_ is the index of the keyset for the user. It is called legacy
  // due to previous plans to fully switch to label-based addressing, which,
  // unfortunately, wasn't followed through.
  // TODO(dlunev): rename it not to say legacy.
  int legacy_index_;
  bool auth_locked_;
  // This is used by the TPM AuthBlocks to make sure the keyset was sealed to
  // the TPM on this system. It's not a security check, but a diagnostic.
  std::optional<brillo::SecureBlob> tpm_public_key_hash_;
  // Passwords which are TPM backed, not PCR bound, and not run through scrypt
  // before the TPM operation, have a number of rounds to run the key derivation
  // function.
  std::optional<int32_t> password_rounds_;
  // An optional timestamp field.
  // TODO(b/205759690, dlunev): can be removed after a stepping stone release.
  std::optional<int64_t> last_activity_timestamp_;
  // Plaintet metadata describing the key.
  std::optional<KeyData> key_data_;
  // Used for the reset seed wrapping.
  std::optional<brillo::SecureBlob> reset_iv_;
  // The label for PinWeaver secrets.
  std::optional<uint64_t> le_label_;
  // IV for the file encryption key of PinWeaver credentials.
  std::optional<brillo::SecureBlob> le_fek_iv_;
  // IV for the chaps key wrapping of PinWeaver credentials.
  std::optional<brillo::SecureBlob> le_chaps_iv_;
  // Used with the resed seed to derive the reset secret. PinWeaver only.
  std::optional<brillo::SecureBlob> reset_salt_;
  // Specifies which version of fscrypt encryption policy this is used with.
  std::optional<int32_t> fscrypt_policy_version_;

  // Group 2. Wrapped stuff.
  // An encrypted copy of the VaultKeysetKeys struct, which holds important
  // fields such as a the file encryption key.
  brillo::SecureBlob wrapped_keyset_;
  // Wrapped copy of the key used to authenticate with the PKCS#11 service.
  std::optional<brillo::SecureBlob> wrapped_chaps_key_;
  // The VaultKeysetKey encrypted with the user's password and TPM.
  std::optional<brillo::SecureBlob> tpm_key_;
  // Used by the PCR bound AuthBlock where the TPM's PCR is extended with the
  // username.
  std::optional<brillo::SecureBlob> extended_tpm_key_;
  // The reset seed for LE credentials.
  std::optional<brillo::SecureBlob> wrapped_reset_seed_;
  // Information specific to the signature-challenge response protection. This
  // has plaintext metadata in it, but also the sealed secret, so it goes here.
  std::optional<SerializedVaultKeyset::SignatureChallengeInfo>
      signature_challenge_info_;

  // Group 3. Unwrapped secrets.
  // The file encryption key present in all VaultKeysets.
  brillo::SecureBlob fek_;
  // Randomly generated key identifier.
  brillo::SecureBlob fek_sig_;
  // Randomly generated salt for use with the file encryption key.
  brillo::SecureBlob fek_salt_;
  // The file name encryption key present in dircrypto, not fscrypt keysets.
  brillo::SecureBlob fnek_;
  // Randomly generated key identifier for the |fnek_|.
  brillo::SecureBlob fnek_sig_;
  // Randomly generated salt for use with the file name encryption key.
  brillo::SecureBlob fnek_salt_;
  // Unwrapped key used for PKCS#11 operations.
  brillo::SecureBlob chaps_key_;
  // The seed mixed with the salt to derive the reset secret.
  brillo::SecureBlob reset_seed_;
  // Used by LECredentials only.
  brillo::SecureBlob reset_secret_;

  // With the SerializedVaultKeyset properly abstracted by VaultKeyset, Crypto
  // should really be folded into VaultKeyset class. But this amount of
  // refactoring for legacy code is undesirable, so it is made a friend class.
  friend class Crypto;

  FRIEND_TEST_ALL_PREFIXES(CryptoTest, TpmStepTest);
  FRIEND_TEST_ALL_PREFIXES(CryptoTest, Tpm1_2_StepTest);
  FRIEND_TEST_ALL_PREFIXES(CryptoTest, TpmDecryptFailureTest);
  FRIEND_TEST_ALL_PREFIXES(CryptoTest, ScryptStepTest);
  FRIEND_TEST_ALL_PREFIXES(LeCredentialsManagerTest, Decrypt);
  FRIEND_TEST_ALL_PREFIXES(LeCredentialsManagerTest, Encrypt);
  FRIEND_TEST_ALL_PREFIXES(LeCredentialsManagerTest, DecryptWithKeyBlobs);
  FRIEND_TEST_ALL_PREFIXES(LeCredentialsManagerTest, EncryptWithKeyBlobs);
  FRIEND_TEST_ALL_PREFIXES(LeCredentialsManagerTest, EncryptFail);
  FRIEND_TEST_ALL_PREFIXES(LeCredentialsManagerTest, EncryptTestReset);
  FRIEND_TEST_ALL_PREFIXES(VaultKeysetTest, GetEccAuthBlockStateTest);
  FRIEND_TEST_ALL_PREFIXES(VaultKeysetTest, EncryptionTest);
  FRIEND_TEST_ALL_PREFIXES(VaultKeysetTest, DecryptionTest);
  FRIEND_TEST_ALL_PREFIXES(VaultKeysetTest, LibScryptBackwardCompatibility);
  FRIEND_TEST_ALL_PREFIXES(KeysetManagementTest, AddInitialKeyset);
  FRIEND_TEST_ALL_PREFIXES(KeysetManagementTest, AddResetSeed);
  FRIEND_TEST_ALL_PREFIXES(KeysetManagementTest, AddWrappedResetSeed);
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_VAULT_KEYSET_H_
