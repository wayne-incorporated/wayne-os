// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm1/signature_sealing.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <tuple>
#include <utility>

#include <absl/container/flat_hash_set.h>
#include <base/check_op.h>
#include <base/rand_util.h>
#include <brillo/secure_blob.h>
#include <libhwsec-foundation/crypto/rsa.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>
#include <libhwsec-foundation/crypto/sha.h>
#include <libhwsec-foundation/status/status_chain_macros.h>

#include "libhwsec/backend/tpm1/static_utils.h"
#include "libhwsec/error/tpm1_error.h"
#include "libhwsec/overalls/overalls.h"
#include "libhwsec/status.h"
#include "libhwsec/tss_utils/scoped_tss_type.h"

using brillo::Blob;
using brillo::BlobFromString;
using brillo::BlobToString;
using brillo::SecureBlob;
using hwsec_foundation::CreateSecureRandomBlob;
using hwsec_foundation::kWellKnownExponent;
using hwsec_foundation::RsaOaepDecrypt;
using hwsec_foundation::RsaOaepEncrypt;
using hwsec_foundation::Sha1;
using hwsec_foundation::status::MakeStatus;

namespace hwsec {

namespace {

// Size of the AuthData blob to be randomly generated.
//
// The choice of this constant is dictated by the desire to provide sufficient
// amount of entropy as the authorization secret for the TPM_Seal command (but
// with taking into account that this authorization value is hashed by SHA-1
// by Trousers anyway).
constexpr int kAuthDataSizeBytes = 32;

constexpr uint32_t kDefaultDiscardableWrapPasswordLength = 32;

// Extracts the public modulus from the OpenSSL RSA struct.
StatusOr<Blob> GetRsaModulus(const RSA& rsa) {
  Blob modulus(RSA_size(&rsa));
  const BIGNUM* n;
  RSA_get0_key(&rsa, &n, nullptr, nullptr);
  if (BN_bn2bin(n, modulus.data()) != modulus.size()) {
    return MakeStatus<TPMError>("RSA modulus size mismatch",
                                TPMRetryAction::kNoRetry);
  }
  return modulus;
}

bool IsPcrValueMatch(const ConfigTpm1::PcrMap& current,
                     const std::vector<Tpm12PcrValue>& target) {
  if (current.size() != target.size()) {
    return false;
  }

  absl::flat_hash_set<uint32_t> checked;

  for (const Tpm12PcrValue& value : target) {
    if (!value.pcr_index.has_value()) {
      return false;
    }

    auto iter = current.find(value.pcr_index.value());
    if (iter == current.end()) {
      return false;
    }

    if (iter->second != value.pcr_value) {
      return false;
    }

    auto [chk_iter, new_element] = checked.insert(iter->first);
    if (!new_element) {
      // We have repeat elements.
      return false;
    }
  }

  return true;
}

// The legacy PCR bound items format is:
//
// std::vector<Tpm12PcrBoundItem>{
//     Tpm12PcrBoundItem{
//         .pcr_values =
//             {
//                 Tpm12PcrValue{
//                     .pcr_index = kCurrentUserPcrTpm1,
//                     .pcr_value = "", // empty
//                 },
//             },
//         .bound_secret = ".......",
//     },
//     Tpm12PcrBoundItem{
//         .pcr_values =
//             {
//                 Tpm12PcrValue{
//                     .pcr_index = kCurrentUserPcrTpm1,
//                     .pcr_value = "", // empty
//                 },
//             },
//         .bound_secret = "......",
//     },
// }
bool IsLegacyFormatPcrBoundItems(
    const std::vector<Tpm12PcrBoundItem>& bound_items) {
  if (bound_items.size() != 2) {
    return false;
  }

  if (bound_items[0].pcr_values.size() != 1) {
    return false;
  }

  if (!bound_items[0].pcr_values[0].pcr_value.empty()) {
    return false;
  }

  if (bound_items[1].pcr_values.size() != 1) {
    return false;
  }

  if (!bound_items[1].pcr_values[0].pcr_value.empty()) {
    return false;
  }

  return true;
}

StatusOr<Blob> FindBoundSecretForLegacyFormat(
    const ConfigTpm1::PcrMap& current,
    const std::vector<Tpm12PcrBoundItem>& bound_items) {
  if (current.size() != 1) {
    return MakeStatus<TPMError>("PCR map size mismatch for legacy format",
                                TPMRetryAction::kNoRetry);
  }

  // Already checked in IsLegacyFormatPcrBoundItems.
  DCHECK_EQ(bound_items.size(), 2);
  DCHECK_EQ(bound_items[0].pcr_values.size(), 1);
  DCHECK_EQ(bound_items[1].pcr_values.size(), 1);

  const auto& [index, value] = *current.begin();

  if (index != kCurrentUserPcrTpm1) {
    return MakeStatus<TPMError>("PCR index mismatch for legacy format",
                                TPMRetryAction::kNoRetry);
  }

  // The first one is bound to prior login state, the PCR value is all zero.
  if (value == Blob(SHA_DIGEST_LENGTH, 0)) {
    return bound_items[0].bound_secret;
  }

  return bound_items[1].bound_secret;
}

StatusOr<Blob> FindBoundSecret(
    const ConfigTpm1::PcrMap& current,
    const std::vector<Tpm12PcrBoundItem>& bound_items) {
  // Special conversion for backwards-compatibility.
  // Note: The empty pcr_values format was introduced in
  // https://crrev.com/c/3277702
  if (IsLegacyFormatPcrBoundItems(bound_items)) {
    return FindBoundSecretForLegacyFormat(current, bound_items);
  }

  for (const Tpm12PcrBoundItem& item : bound_items) {
    if (IsPcrValueMatch(current, item.pcr_values)) {
      return item.bound_secret;
    }
  }

  return MakeStatus<TPMError>("No matching bound item",
                              TPMRetryAction::kNoRetry);
}

// Returns the digest of the blob of the TPM_MSA_COMPOSITE structure containing
// a sole reference to the specified key (whose TPM_PUBKEY blob is passed via
// |msa_pubkey_digest|).
Blob BuildMsaCompositeDigest(const Blob& msa_pubkey_digest) {
  // Build the structure.
  DCHECK_EQ(TPM_SHA1_160_HASH_LEN, msa_pubkey_digest.size());
  TPM_DIGEST digest;
  memcpy(digest.digest, msa_pubkey_digest.data(), msa_pubkey_digest.size());
  TPM_MSA_COMPOSITE msa_composite{
      .MSAlist = 1,
      .migAuthDigest = &digest,
  };
  // Serialize the structure.
  uint64_t serializing_offset = 0;
  Trspi_LoadBlob_MSA_COMPOSITE(&serializing_offset, nullptr, &msa_composite);
  Blob msa_composite_blob(serializing_offset);
  serializing_offset = 0;
  Trspi_LoadBlob_MSA_COMPOSITE(&serializing_offset, msa_composite_blob.data(),
                               &msa_composite);
  return Sha1(msa_composite_blob);
}

// Obtains via the TPM_CMK_ApproveMA command the migration authority approval
// ticket for the given TPM_MSA_COMPOSITE structure blob. Returns the ticket.
StatusOr<Blob> ObtainMaApprovalTicket(overalls::Overalls& overalls,
                                      TSS_HCONTEXT tpm_context,
                                      TSS_HTPM tpm_handle,
                                      Blob msa_composite_digest) {
  ScopedTssObject<TSS_HMIGDATA> migdata_handle(overalls, tpm_context);

  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls.Ospi_Context_CreateObject(
          tpm_context, TSS_OBJECT_TYPE_MIGDATA, 0, migdata_handle.ptr())))
      .WithStatus<TPMError>("Failed to create TSS_OBJECT_TYPE_MIGDATA");

  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls.Ospi_SetAttribData(
          migdata_handle, TSS_MIGATTRIB_AUTHORITY_DATA,
          TSS_MIGATTRIB_AUTHORITY_DIGEST, msa_composite_digest.size(),
          msa_composite_digest.data())))
      .WithStatus<TPMError>("Failed to set TSS_MIGATTRIB_AUTHORITY_DIGEST");

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Ospi_TPM_CMKApproveMA(
                      tpm_handle, migdata_handle)))
      .WithStatus<TPMError>("Failed to call Ospi_TPM_CMKApproveMA");

  uint32_t size = 0;
  ScopedTssMemory ma_approval_ticket_buf(overalls, tpm_context);
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Ospi_GetAttribData(
                      migdata_handle, TSS_MIGATTRIB_AUTHORITY_DATA,
                      TSS_MIGATTRIB_AUTHORITY_APPROVAL_HMAC, &size,
                      ma_approval_ticket_buf.ptr())))
      .WithStatus<TPMError>(
          "Failed to get TSS_MIGATTRIB_AUTHORITY_APPROVAL_HMAC");

  return Blob(ma_approval_ticket_buf.value(),
              ma_approval_ticket_buf.value() + size);
}

struct GenerateCmkResult {
  // the CMK TPM_PUBKEY blob.
  Blob cmk_pubkey;
  // The wrapped CMK blob
  Blob srk_wrapped_cmk;
};

// Generates the Certified Migratable Key, associated with the protection public
// key (via the TPM_MSA_COMPOSITE digest passed by |msa_composite_digest|). The
// |ma_approval_ticket| should contain ticket obtained from the
// TPM_CMK_ApproveMA command. Returns the GenerateCmkResult.
//
// TODO(b/240509609): The reason that |msa_composite_digest| and
// |ma_approval_ticket| are not passing by const reference is because the
// trousers API want mutable input, we should change these to const reference
// after trousers supports const input.
StatusOr<GenerateCmkResult> GenerateCmk(overalls::Overalls& overalls,
                                        TSS_HCONTEXT tpm_context,
                                        TSS_HTPM tpm_handle,
                                        TSS_HKEY srk_handle,
                                        Blob msa_composite_digest,
                                        Blob ma_approval_ticket) {
  // Create the Certified Migratable Key object. Note that the actual key
  // generation isn't happening at this point yet.
  ScopedTssKey cmk_handle(overalls, tpm_context);
  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls.Ospi_Context_CreateObject(
          tpm_context, TSS_OBJECT_TYPE_RSAKEY,
          TSS_KEY_STRUCT_KEY12 | TSS_KEY_VOLATILE | TSS_KEY_TYPE_STORAGE |
              TSS_KEY_AUTHORIZATION | TSS_KEY_MIGRATABLE |
              TSS_KEY_CERTIFIED_MIGRATABLE | kCmkKeySizeFlag,
          cmk_handle.ptr())))
      .WithStatus<TPMError>("Failed to create TSS_OBJECT_TYPE_RSAKEY");

  // Set the parameter to make the created CMK associated with the protection
  // public key (via the TPM_MSA_COMPOSITE digest).
  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls.Ospi_SetAttribData(
          cmk_handle, TSS_TSPATTRIB_KEY_CMKINFO,
          TSS_TSPATTRIB_KEYINFO_CMK_MA_DIGEST, msa_composite_digest.size(),
          msa_composite_digest.data())))
      .WithStatus<TPMError>(
          "Failed to set TSS_TSPATTRIB_KEYINFO_CMK_MA_DIGEST");

  // Set the parameter to pass the migration authority approval ticket to the
  // CMK creation procedure.
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Ospi_SetAttribData(
                      cmk_handle, TSS_TSPATTRIB_KEY_CMKINFO,
                      TSS_TSPATTRIB_KEYINFO_CMK_MA_APPROVAL,
                      ma_approval_ticket.size(), ma_approval_ticket.data())))
      .WithStatus<TPMError>(
          "Failed to set TSS_TSPATTRIB_KEYINFO_CMK_MA_APPROVAL");

  // Add the usage policy to the CMK. The policy will effectively disallow the
  // usage of the CMK for signing/decryption, as the policy's password is
  // discarded.
  ScopedTssPolicy usage_policy_handle(overalls, tpm_context);
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Ospi_Context_CreateObject(
                      tpm_context, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE,
                      usage_policy_handle.ptr())))
      .WithStatus<TPMError>("Failed to create TSS_POLICY_USAGE");

  SecureBlob usage_password =
      CreateSecureRandomBlob(kDefaultDiscardableWrapPasswordLength);
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Ospi_Policy_SetSecret(
                      usage_policy_handle, TSS_SECRET_MODE_PLAIN,
                      usage_password.size(), usage_password.data())))
      .WithStatus<TPMError>("Failed to set secret for TSS_POLICY_USAGE");

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Ospi_Policy_AssignToObject(
                      usage_policy_handle, cmk_handle)))
      .WithStatus<TPMError>("Failed to assign TSS_POLICY_USAGE");

  // Add the migration policy to the CMK. The policy will effectively disallow
  // the usage of the CMK for non-certified migration, as the policy's password
  // is discarded.
  ScopedTssPolicy migration_policy_handle(overalls, tpm_context);
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Ospi_Context_CreateObject(
                      tpm_context, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_MIGRATION,
                      migration_policy_handle.ptr())))
      .WithStatus<TPMError>("Failed to create TSS_POLICY_MIGRATION");

  SecureBlob migration_password =
      CreateSecureRandomBlob(kDefaultDiscardableWrapPasswordLength);
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Ospi_Policy_SetSecret(
                      migration_policy_handle, TSS_SECRET_MODE_PLAIN,
                      migration_password.size(), migration_password.data())))
      .WithStatus<TPMError>("Failed to set secret for TSS_POLICY_MIGRATION");

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Ospi_Policy_AssignToObject(
                      migration_policy_handle, cmk_handle)))
      .WithStatus<TPMError>("Failed to assign TSS_POLICY_MIGRATION");

  // Trigger the CMK generation and extract the resulting blobs.
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Ospi_Key_CreateKey(
                      cmk_handle, srk_handle, /*hPcrComposite=*/0)))
      .WithStatus<TPMError>("Failed to call Ospi_Key_CreateKey");

  uint32_t cmk_pubkey_size = 0;
  ScopedTssMemory cmk_pubkey_buf(overalls, tpm_context);
  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls.Ospi_GetAttribData(
          cmk_handle, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,
          &cmk_pubkey_size, cmk_pubkey_buf.ptr())))
      .WithStatus<TPMError>("Failed to get TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY");
  Blob cmk_pubkey(cmk_pubkey_buf.value(),
                  cmk_pubkey_buf.value() + cmk_pubkey_size);

  uint32_t srk_wrapped_cmk_size = 0;
  ScopedTssMemory srk_wrapped_cmk_buf(overalls, tpm_context);
  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls.Ospi_GetAttribData(
          cmk_handle, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_BLOB,
          &srk_wrapped_cmk_size, srk_wrapped_cmk_buf.ptr())))
      .WithStatus<TPMError>("Failed to get TSS_TSPATTRIB_KEYBLOB_BLOB");
  Blob srk_wrapped_cmk(srk_wrapped_cmk_buf.value(),
                       srk_wrapped_cmk_buf.value() + srk_wrapped_cmk_size);

  return GenerateCmkResult{
      .cmk_pubkey = std::move(cmk_pubkey),
      .srk_wrapped_cmk = std::move(srk_wrapped_cmk),
  };
}

struct MigrateCmkResult {
  // The TPM_KEY12 blob of the migrated CMK.
  Blob migrated_cmk_key12;
  // The migration random XOR mask (see ExtractCmkPrivateKeyFromMigratedBlob()
  // for the details).
  Blob migration_random;
};

// Performs the migration of the CMK, passed in |srk_wrapped_cmk|, onto the key
// specified by |migration_destination_key_pubkey|, using the migration
// authorization from |migration_authorization_blob| and the CMK migration
// signature ticket from |cmk_migration_signature_ticket| for authorizing the
// migration. Returns MigrateCmkResult.
StatusOr<MigrateCmkResult> MigrateCmk(overalls::Overalls& overalls,
                                      TSS_HCONTEXT tpm_context,
                                      TSS_HTPM tpm_handle,
                                      TSS_HKEY srk_handle,
                                      Blob srk_wrapped_cmk,
                                      Blob migration_destination_key_pubkey,
                                      Blob cmk_pubkey,
                                      Blob protection_key_pubkey,
                                      Blob migration_authorization_blob,
                                      Blob cmk_migration_signature_ticket) {
  // Load the wrapped CMK into Trousers.
  ScopedTssObject<TSS_HMIGDATA> wrapped_cmk_handle(overalls, tpm_context);

  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls.Ospi_Context_CreateObject(
          tpm_context, TSS_OBJECT_TYPE_RSAKEY, 0, wrapped_cmk_handle.ptr())))
      .WithStatus<TPMError>("Failed to create TSS_OBJECT_TYPE_RSAKEY");

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Ospi_SetAttribData(
                      wrapped_cmk_handle, TSS_TSPATTRIB_KEY_BLOB,
                      TSS_TSPATTRIB_KEYBLOB_BLOB, srk_wrapped_cmk.size(),
                      srk_wrapped_cmk.data())))
      .WithStatus<TPMError>("Failed to set TSS_TSPATTRIB_KEYBLOB_BLOB");

  // Prepare the parameters object for the migration command.
  ScopedTssObject<TSS_HMIGDATA> migdata_handle(overalls, tpm_context);

  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls.Ospi_Context_CreateObject(
          tpm_context, TSS_OBJECT_TYPE_MIGDATA, 0, migdata_handle.ptr())))
      .WithStatus<TPMError>("Failed to create TSS_OBJECT_TYPE_MIGDATA");

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Ospi_SetAttribData(
                      migdata_handle, TSS_MIGATTRIB_MIGRATIONBLOB,
                      TSS_MIGATTRIB_MIG_DESTINATION_PUBKEY_BLOB,
                      migration_destination_key_pubkey.size(),
                      migration_destination_key_pubkey.data())))
      .WithStatus<TPMError>(
          "Failed to set TSS_MIGATTRIB_MIG_DESTINATION_PUBKEY_BLOB");

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Ospi_SetAttribData(
                      migdata_handle, TSS_MIGATTRIB_MIGRATIONBLOB,
                      TSS_MIGATTRIB_MIG_SOURCE_PUBKEY_BLOB, cmk_pubkey.size(),
                      cmk_pubkey.data())))
      .WithStatus<TPMError>(
          "Failed to set TSS_MIGATTRIB_MIG_SOURCE_PUBKEY_BLOB");

  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls.Ospi_SetAttribData(
          migdata_handle, TSS_MIGATTRIB_MIGRATIONBLOB,
          TSS_MIGATTRIB_MIG_AUTHORITY_PUBKEY_BLOB, protection_key_pubkey.size(),
          protection_key_pubkey.data())))
      .WithStatus<TPMError>(
          "Failed to set TSS_MIGATTRIB_MIG_AUTHORITY_PUBKEY_BLOB");

  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls.Ospi_SetAttribData(
          migdata_handle, TSS_MIGATTRIB_MIGRATIONBLOB,
          TSS_MIGATTRIB_MIG_MSALIST_PUBKEY_BLOB, protection_key_pubkey.size(),
          protection_key_pubkey.data())))
      .WithStatus<TPMError>(
          "Failed to set TSS_MIGATTRIB_MIG_MSALIST_PUBKEY_BLOB");

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Ospi_SetAttribData(
                      migdata_handle, TSS_MIGATTRIB_MIGRATIONTICKET, 0,
                      migration_authorization_blob.size(),
                      migration_authorization_blob.data())))
      .WithStatus<TPMError>("Failed to set TSS_MIGATTRIB_MIGRATIONTICKET");

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Ospi_SetAttribData(
                      migdata_handle, TSS_MIGATTRIB_TICKET_DATA,
                      TSS_MIGATTRIB_TICKET_SIG_TICKET,
                      cmk_migration_signature_ticket.size(),
                      cmk_migration_signature_ticket.data())))
      .WithStatus<TPMError>("Failed to set TSS_MIGATTRIB_TICKET_SIG_TICKET");

  // Perform the migration and extract the resulting data.
  uint32_t migration_random_size = 0;
  ScopedTssMemory migration_random_buf(overalls, tpm_context);
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Ospi_Key_CMKCreateBlob(
                      wrapped_cmk_handle, srk_handle, migdata_handle,
                      &migration_random_size, migration_random_buf.ptr())))
      .WithStatus<TPMError>("Failed to call Ospi_Key_CMKCreateBlob");

  Blob migration_random(migration_random_buf.value(),
                        migration_random_buf.value() + migration_random_size);

  uint32_t migrated_cmk_key12_size = 0;
  ScopedTssMemory migrated_cmk_key12_buf(overalls, tpm_context);
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Ospi_GetAttribData(
                      migdata_handle, TSS_MIGATTRIB_MIGRATIONBLOB,
                      TSS_MIGATTRIB_MIG_XOR_BLOB, &migrated_cmk_key12_size,
                      migrated_cmk_key12_buf.ptr())))
      .WithStatus<TPMError>("Failed to get TSS_MIGATTRIB_MIG_XOR_BLOB");

  Blob migrated_cmk_key12(
      migrated_cmk_key12_buf.value(),
      migrated_cmk_key12_buf.value() + migrated_cmk_key12_size);

  return MigrateCmkResult{
      .migrated_cmk_key12 = migrated_cmk_key12,
      .migration_random = migration_random,
  };
}

StatusOr<Blob> MakePcrBoundSecret(SealingTpm1& sealing_backend,
                                  OperationPolicySetting policy,
                                  const SecureBlob& secret_value,
                                  const SecureBlob& auth_value) {
  if (policy.permission.auth_value.has_value()) {
    return MakeStatus<TPMError>("Need empty auth value policy",
                                TPMRetryAction::kNoRetry);
  }

  // Add auth value into the policy
  policy.permission.auth_value = auth_value;

  ASSIGN_OR_RETURN(Blob sealed_data, sealing_backend.Seal(policy, secret_value),
                   _.WithStatus<TPMError>("Failed to seal the data"));

  return sealed_data;
}

// Loads the migration destination public key into Trousers. The loaded key
// handle is returned via |key_handle|.
StatusOr<ScopedKey> LoadMigrationDestinationPublicKey(
    KeyManagementTpm1& key_management, const RSA& migration_destination_rsa) {
  ASSIGN_OR_RETURN(Blob key_modulus, GetRsaModulus(migration_destination_rsa));

  return key_management.CreateRsaPublicKeyObject(
      key_modulus,
      TSS_KEY_VOLATILE | TSS_KEY_TYPE_STORAGE |
          kMigrationDestinationKeySizeFlag,
      TSS_SS_NONE, TSS_ES_RSAESOAEP_SHA1_MGF1);
}

// Obtains via the TPM_AuthorizeMigrationKey command the migration authorization
// blob for the given migration destination key. Returns the authorization blob.
StatusOr<Blob> ObtainMigrationAuthorization(
    overalls::Overalls& overalls,
    TSS_HCONTEXT tpm_context,
    TSS_HTPM tpm_handle,
    TSS_HKEY migration_destination_key_handle) {
  uint32_t migration_authorization_blob_size = 0;
  ScopedTssMemory migration_authorization_blob_buf(overalls, tpm_context);
  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls.Ospi_TPM_AuthorizeMigrationTicket(
          tpm_handle, migration_destination_key_handle,
          TSS_MS_RESTRICT_APPROVE_DOUBLE, &migration_authorization_blob_size,
          migration_authorization_blob_buf.ptr())))
      .WithStatus<TPMError>("Failed to call Ospi_TPM_AuthorizeMigrationTicket");

  return Blob(migration_authorization_blob_buf.value(),
              migration_authorization_blob_buf.value() +
                  migration_authorization_blob_size);
}

// Obtains via the TPM_CMK_CreateTicket command the CMK migration signature
// ticket for the signature of the challenge. Returns the ticket via
// |cmk_migration_signature_ticket|.
StatusOr<Blob> ObtainCmkMigrationSignatureTicket(
    overalls::Overalls& overalls,
    TSS_HCONTEXT tpm_context,
    TSS_HTPM tpm_handle,
    TSS_HKEY protection_key_handle,
    Blob migration_destination_key_pubkey,
    Blob cmk_pubkey,
    Blob protection_key_pubkey,
    Blob signed_challenge_value) {
  ScopedTssObject<TSS_HMIGDATA> migdata_handle(overalls, tpm_context);

  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls.Ospi_Context_CreateObject(
          tpm_context, TSS_OBJECT_TYPE_MIGDATA, 0, migdata_handle.ptr())))
      .WithStatus<TPMError>("Failed to create TSS_OBJECT_TYPE_MIGDATA");

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Ospi_SetAttribData(
                      migdata_handle, TSS_MIGATTRIB_MIGRATIONBLOB,
                      TSS_MIGATTRIB_MIG_DESTINATION_PUBKEY_BLOB,
                      migration_destination_key_pubkey.size(),
                      migration_destination_key_pubkey.data())))
      .WithStatus<TPMError>(
          "Failed to set TSS_MIGATTRIB_MIG_DESTINATION_PUBKEY_BLOB");

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Ospi_SetAttribData(
                      migdata_handle, TSS_MIGATTRIB_MIGRATIONBLOB,
                      TSS_MIGATTRIB_MIG_SOURCE_PUBKEY_BLOB, cmk_pubkey.size(),
                      cmk_pubkey.data())))
      .WithStatus<TPMError>(
          "Failed to set TSS_MIGATTRIB_MIG_SOURCE_PUBKEY_BLOB");

  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls.Ospi_SetAttribData(
          migdata_handle, TSS_MIGATTRIB_MIGRATIONBLOB,
          TSS_MIGATTRIB_MIG_AUTHORITY_PUBKEY_BLOB, protection_key_pubkey.size(),
          protection_key_pubkey.data())))
      .WithStatus<TPMError>(
          "Failed to set TSS_MIGATTRIB_MIG_AUTHORITY_PUBKEY_BLOB");

  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls.Ospi_SetAttribData(
          migdata_handle, TSS_MIGATTRIB_TICKET_DATA,
          TSS_MIGATTRIB_TICKET_SIG_VALUE, signed_challenge_value.size(),
          signed_challenge_value.data())))
      .WithStatus<TPMError>("Failed to set TSS_MIGATTRIB_TICKET_SIG_VALUE");

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Ospi_TPM_CMKCreateTicket(
                      tpm_handle, protection_key_handle, migdata_handle)))
      .WithStatus<TPMError>("Failed to call Ospi_TPM_CMKCreateTicket");

  uint32_t cmk_migration_signature_ticket_size = 0;
  ScopedTssMemory cmk_migration_signature_ticket_buf(overalls, tpm_context);
  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls.Ospi_GetAttribData(
          migdata_handle, TSS_MIGATTRIB_TICKET_DATA,
          TSS_MIGATTRIB_TICKET_SIG_TICKET, &cmk_migration_signature_ticket_size,
          cmk_migration_signature_ticket_buf.ptr())))
      .WithStatus<TPMError>("Failed to get TSS_MIGATTRIB_TICKET_SIG_TICKET");

  Blob cmk_migration_signature_ticket(
      cmk_migration_signature_ticket_buf.value(),
      cmk_migration_signature_ticket_buf.value() +
          cmk_migration_signature_ticket_size);

  return cmk_migration_signature_ticket;
}

}  // namespace

StatusOr<SignatureSealedData> SignatureSealingTpm1::Seal(
    const std::vector<OperationPolicySetting>& policies,
    const SecureBlob& unsealed_data,
    const Blob& public_key_spki_der,
    const std::vector<Algorithm>& key_algorithms) {
  // Drop the existing challenge if we have any.
  current_challenge_data_ = std::nullopt;

  if (policies.empty()) {
    return MakeStatus<TPMError>("No policy for signature sealing",
                                TPMRetryAction::kNoRetry);
  }

  // Only the |kRsassaPkcs1V15Sha1| algorithm is supported.
  if (std::find(key_algorithms.begin(), key_algorithms.end(),
                Algorithm::kRsassaPkcs1V15Sha1) == key_algorithms.end()) {
    return MakeStatus<TPMError>(
        "The key doesn't support RSASSA-PKCS1-v1_5 with SHA-1",
        TPMRetryAction::kNoRetry);
  }

  ASSIGN_OR_RETURN(TSS_HCONTEXT context, tss_helper_.GetTssContext());

  ASSIGN_OR_RETURN(ScopedTssObject<TSS_HTPM> tpm_handle,
                   tss_helper_.GetDelegateTpmHandle());

  // Load the protection public key onto the TPM.
  ASSIGN_OR_RETURN(
      ScopedKey protection_key,
      key_management_.LoadPublicKeyFromSpki(
          public_key_spki_der, TSS_SS_RSASSAPKCS1V15_SHA1, TSS_ES_NONE),
      _.WithStatus<TPMError>("Failed to load protection key"));

  ASSIGN_OR_RETURN(const KeyTpm1& protection_key_data,
                   key_management_.GetKeyData(protection_key.GetKey()));

  uint32_t size = 0;
  ScopedTssMemory protection_key_pubkey_buf(overalls_, context);
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_GetAttribData(
                      protection_key_data.key_handle, TSS_TSPATTRIB_KEY_BLOB,
                      TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, &size,
                      protection_key_pubkey_buf.ptr())))
      .WithStatus<TPMError>("Failed to get TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY");

  Blob protection_key_pubkey(protection_key_pubkey_buf.value(),
                             protection_key_pubkey_buf.value() + size);

  const Blob protection_key_pubkey_digest = Sha1(protection_key_pubkey);
  const Blob msa_composite_digest =
      BuildMsaCompositeDigest(protection_key_pubkey_digest);

  // Obtain the migration authority approval ticket for the TPM_MSA_COMPOSITE
  // structure.
  ASSIGN_OR_RETURN(
      const Blob& ma_approval_ticket,
      ObtainMaApprovalTicket(overalls_, context, tpm_handle.value(),
                             msa_composite_digest),
      _.WithStatus<TPMError>("Failed to obtain MA approval ticket"));

  // Load the SRK.
  ASSIGN_OR_RETURN(ScopedKey srk,
                   key_management_.GetPersistentKey(
                       KeyManagement::PersistentKeyType::kStorageRootKey));

  ASSIGN_OR_RETURN(const KeyTpm1& srk_data,
                   key_management_.GetKeyData(srk.GetKey()));

  // Generate the Certified Migratable Key, associated with the protection
  // public key (via the TPM_MSA_COMPOSITE digest). Obtain the resulting wrapped
  // CMK blob and the TPM_PUBKEY blob.
  ASSIGN_OR_RETURN(
      const GenerateCmkResult& cmk,
      GenerateCmk(overalls_, context, tpm_handle.value(), srk_data.key_handle,
                  msa_composite_digest, ma_approval_ticket),
      _.WithStatus<TPMError>("Failed to generate CMK"));

  ASSIGN_OR_RETURN(
      const SecureBlob& auth_data, random_.RandomSecureBlob(kAuthDataSizeBytes),
      _.WithStatus<TPMError>("Failed to generate random auth data"));

  if (auth_data.size() != kAuthDataSizeBytes) {
    return MakeStatus<TPMError>("Unexpected random auth data size",
                                TPMRetryAction::kNoRetry);
  }

  // Encrypt the AuthData value.
  ASSIGN_OR_RETURN(
      const crypto::ScopedRSA& cmk_rsa,
      ParseRsaFromTpmPubkeyBlob(overalls_, cmk.cmk_pubkey),
      _.WithStatus<TPMError>("Failed to parse RSA public key for CMK"));

  Blob cmk_wrapped_auth_data;
  if (!RsaOaepEncrypt(auth_data, cmk_rsa.get(), &cmk_wrapped_auth_data)) {
    return MakeStatus<TPMError>("Failed to encrypt authorization data",
                                TPMRetryAction::kNoRetry);
  }

  std::vector<Tpm12PcrBoundItem> pcr_bound_items;
  for (const OperationPolicySetting& policy : policies) {
    ASSIGN_OR_RETURN(
        const ConfigTpm1::PcrMap& setting,
        config_.ToSettingsPcrMap(policy.device_config_settings),
        _.WithStatus<TPMError>("Failed to convert setting to PCR map"));
    std::vector<Tpm12PcrValue> pcr_values;
    for (const auto& [index, value] : setting) {
      pcr_values.push_back(Tpm12PcrValue{
          .pcr_index = index,
          .pcr_value = value,
      });
    }

    ASSIGN_OR_RETURN(
        Blob && pcr_bound_secret,
        MakePcrBoundSecret(sealing_, policies[0], unsealed_data, auth_data),
        _.WithStatus<TPMError>("Failed to create default PCR bound secret"));

    pcr_bound_items.push_back(Tpm12PcrBoundItem{
        .pcr_values = std::move(pcr_values),
        .bound_secret = std::move(pcr_bound_secret),
    });
  }

  return Tpm12CertifiedMigratableKeyData{
      .public_key_spki_der = public_key_spki_der,
      .srk_wrapped_cmk = cmk.srk_wrapped_cmk,
      .cmk_pubkey = cmk.cmk_pubkey,
      .cmk_wrapped_auth_data = cmk_wrapped_auth_data,
      .pcr_bound_items = std::move(pcr_bound_items),
  };
}

StatusOr<SignatureSealingTpm1::ChallengeResult> SignatureSealingTpm1::Challenge(
    const OperationPolicy& policy,
    const SignatureSealedData& sealed_data,
    const Blob& public_key_spki_der,
    const std::vector<Algorithm>& key_algorithms) {
  // Validate the parameters.
  auto* sealed_data_ptr =
      std::get_if<Tpm12CertifiedMigratableKeyData>(&sealed_data);
  if (!sealed_data_ptr) {
    return MakeStatus<TPMError>(
        "Sealed data is empty or uses unexpected method",
        TPMRetryAction::kNoRetry);
  }
  const Tpm12CertifiedMigratableKeyData& data = *sealed_data_ptr;
  if (data.public_key_spki_der.empty()) {
    return MakeStatus<TPMError>("Empty public key", TPMRetryAction::kNoRetry);
  }
  if (data.srk_wrapped_cmk.empty()) {
    return MakeStatus<TPMError>("Empty SRK wrapped CMK",
                                TPMRetryAction::kNoRetry);
  }
  if (data.cmk_wrapped_auth_data.empty()) {
    return MakeStatus<TPMError>("Empty CMK wrapped auth data",
                                TPMRetryAction::kNoRetry);
  }
  if (data.cmk_pubkey.empty()) {
    return MakeStatus<TPMError>("Empty CMK public key",
                                TPMRetryAction::kNoRetry);
  }

  if (data.public_key_spki_der != public_key_spki_der) {
    return MakeStatus<TPMError>("Wrong subject public key info",
                                TPMRetryAction::kNoRetry);
  }
  if (std::find(key_algorithms.begin(), key_algorithms.end(),
                Algorithm::kRsassaPkcs1V15Sha1) == key_algorithms.end()) {
    return MakeStatus<TPMError>(
        "The key doesn't support RSASSA-PKCS1-v1_5 with SHA-1",
        TPMRetryAction::kNoRetry);
  }

  ASSIGN_OR_RETURN(const ConfigTpm1::PcrMap& current_pcr_value,
                   config_.ToCurrentPcrValueMap(policy.device_configs),
                   _.WithStatus<TPMError>("Failed to get current user status"));

  ASSIGN_OR_RETURN(const Blob& pcr_bound_secret,
                   FindBoundSecret(current_pcr_value, data.pcr_bound_items));

  if (pcr_bound_secret.empty()) {
    return MakeStatus<TPMError>("Empty PCR bound secret",
                                TPMRetryAction::kNoRetry);
  }

  ASSIGN_OR_RETURN(TSS_HCONTEXT context, tss_helper_.GetTssContext());

  ASSIGN_OR_RETURN(ScopedTssObject<TSS_HTPM> tpm_handle,
                   tss_helper_.GetDelegateTpmHandle());

  // Load the protection public key onto the TPM.
  ASSIGN_OR_RETURN(
      ScopedKey protection_key,
      key_management_.LoadPublicKeyFromSpki(
          public_key_spki_der, TSS_SS_RSASSAPKCS1V15_SHA1, TSS_ES_NONE),
      _.WithStatus<TPMError>("Failed to load protection key"));

  ASSIGN_OR_RETURN(const KeyTpm1& protection_key_data,
                   key_management_.GetKeyData(protection_key.GetKey()));

  uint32_t protection_key_pubkey_size = 0;
  ScopedTssMemory protection_key_pubkey_buf(overalls_, context);
  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls_.Ospi_GetAttribData(
          protection_key_data.key_handle, TSS_TSPATTRIB_KEY_BLOB,
          TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, &protection_key_pubkey_size,
          protection_key_pubkey_buf.ptr())))
      .WithStatus<TPMError>("Failed to get TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY");
  Blob protection_key_pubkey(
      protection_key_pubkey_buf.value(),
      protection_key_pubkey_buf.value() + protection_key_pubkey_size);

  // Generate the migration destination RSA key. Onto this key the CMK private
  // key will be migrated; to complete the unsealing, the decryption operation
  // using the migration destination key will be performed. The security
  // properties of the migration destination key aren't crucial, besides the
  // reasonable amount of entropy, therefore generating using OpenSSL is fine.
  crypto::ScopedRSA migration_destination_rsa(RSA_new());
  crypto::ScopedBIGNUM e(BN_new());
  if (!migration_destination_rsa || !e) {
    return MakeStatus<TPMError>(
        "Failed to allocate the migration destination key",
        TPMRetryAction::kNoRetry);
  }
  if (!BN_set_word(e.get(), kWellKnownExponent) ||
      !RSA_generate_key_ex(migration_destination_rsa.get(),
                           kMigrationDestinationKeySizeBits, e.get(),
                           nullptr)) {
    return MakeStatus<TPMError>(
        "Failed to generate the migration destination key parameters",
        TPMRetryAction::kNoRetry);
  }

  // Obtain the TPM_PUBKEY blob for the migration destination key.
  ASSIGN_OR_RETURN(const ScopedKey& migration_destination_key,
                   LoadMigrationDestinationPublicKey(
                       key_management_, *migration_destination_rsa));

  ASSIGN_OR_RETURN(
      const KeyTpm1& migration_destination_key_data,
      key_management_.GetKeyData(migration_destination_key.GetKey()));

  uint32_t migration_destination_key_pubkey_size = 0;
  ScopedTssMemory migration_destination_key_pubkey_buf(overalls_, context);
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_GetAttribData(
                      migration_destination_key_data.key_handle,
                      TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,
                      &migration_destination_key_pubkey_size,
                      migration_destination_key_pubkey_buf.ptr())))
      .WithStatus<TPMError>("Failed to get TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY");
  Blob migration_destination_key_pubkey(
      migration_destination_key_pubkey_buf.value(),
      migration_destination_key_pubkey_buf.value() +
          migration_destination_key_pubkey_size);

  Blob protection_key_pubkey_digest = Sha1(protection_key_pubkey);
  Blob migration_destination_key_pubkey_digest =
      Sha1(migration_destination_key_pubkey);
  Blob cmk_pubkey_digest = Sha1(data.cmk_pubkey);

  Blob challenge_value = brillo::CombineBlobs(
      {protection_key_pubkey_digest, migration_destination_key_pubkey_digest,
       cmk_pubkey_digest});

  ChallengeID challenge_id = static_cast<ChallengeID>(base::RandUint64());

  // We currently only allow one active challenge.
  current_challenge_data_ = InternalChallengeData{
      .challenge_id = challenge_id,
      .policy = policy,
      .srk_wrapped_cmk = data.srk_wrapped_cmk,
      .cmk_wrapped_auth_data = data.cmk_wrapped_auth_data,
      .pcr_bound_secret = pcr_bound_secret,
      .public_key_spki_der = public_key_spki_der,
      .cmk_pubkey = data.cmk_pubkey,
      .protection_key_pubkey = protection_key_pubkey,
      .migration_destination_rsa = std::move(migration_destination_rsa),
      .migration_destination_key_pubkey = migration_destination_key_pubkey,
  };

  return ChallengeResult{
      .challenge_id = challenge_id,
      .algorithm = Algorithm::kRsassaPkcs1V15Sha1,
      .challenge = std::move(challenge_value),
  };
}

StatusOr<SecureBlob> SignatureSealingTpm1::Unseal(
    ChallengeID challenge, const Blob& challenge_response) {
  if (!current_challenge_data_.has_value()) {
    return MakeStatus<TPMError>("No valid challenge data",
                                TPMRetryAction::kNoRetry);
  }

  const InternalChallengeData& challenge_data = current_challenge_data_.value();

  if (challenge != challenge_data.challenge_id) {
    return MakeStatus<TPMError>("Challenge ID mismatch",
                                TPMRetryAction::kNoRetry);
  }

  // Obtain the TPM context and handle with the required authorization.
  ASSIGN_OR_RETURN(TSS_HCONTEXT context, tss_helper_.GetTssContext());

  ASSIGN_OR_RETURN(ScopedTssObject<TSS_HTPM> tpm_handle,
                   tss_helper_.GetDelegateTpmHandle());

  // Load the protection public key onto the TPM.
  ASSIGN_OR_RETURN(ScopedKey protection_key,
                   key_management_.LoadPublicKeyFromSpki(
                       challenge_data.public_key_spki_der,
                       TSS_SS_RSASSAPKCS1V15_SHA1, TSS_ES_NONE),
                   _.WithStatus<TPMError>("Failed to load protection key"));

  ASSIGN_OR_RETURN(const KeyTpm1& protection_key_data,
                   key_management_.GetKeyData(protection_key.GetKey()));

  // Obtain the TPM_PUBKEY blob for the migration destination key.
  ASSIGN_OR_RETURN(
      const ScopedKey& migration_destination_key,
      LoadMigrationDestinationPublicKey(
          key_management_, *challenge_data.migration_destination_rsa));

  ASSIGN_OR_RETURN(
      const KeyTpm1& migration_destination_key_data,
      key_management_.GetKeyData(migration_destination_key.GetKey()));

  // Obtain the migration authorization blob for the migration destination key.
  ASSIGN_OR_RETURN(
      const Blob& migration_authorization_blob,
      ObtainMigrationAuthorization(overalls_, context, tpm_handle.value(),
                                   migration_destination_key_data.key_handle),
      _.WithStatus<TPMError>("Failed to obtain the migration authorization"));

  // Obtain the CMK migration signature ticket for the signed challenge blob.
  ASSIGN_OR_RETURN(
      const Blob& cmk_migration_signature_ticket,
      ObtainCmkMigrationSignatureTicket(
          overalls_, context, tpm_handle.value(),
          protection_key_data.key_handle,
          challenge_data.migration_destination_key_pubkey,
          challenge_data.cmk_pubkey, challenge_data.protection_key_pubkey,
          challenge_response),
      _.WithStatus<TPMError>(
          "Failed to obtain the CMK migration signature ticket"));

  // Load the SRK.
  ASSIGN_OR_RETURN(ScopedKey srk,
                   key_management_.GetPersistentKey(
                       KeyManagement::PersistentKeyType::kStorageRootKey));

  ASSIGN_OR_RETURN(const KeyTpm1& srk_data,
                   key_management_.GetKeyData(srk.GetKey()));

  // Perform the migration of the CMK onto the migration destination key.
  ASSIGN_OR_RETURN(
      const MigrateCmkResult& migrate_cmk,
      MigrateCmk(overalls_, context, tpm_handle.value(), srk_data.key_handle,
                 challenge_data.srk_wrapped_cmk,
                 challenge_data.migration_destination_key_pubkey,
                 challenge_data.cmk_pubkey,
                 challenge_data.protection_key_pubkey,
                 migration_authorization_blob, cmk_migration_signature_ticket),
      _.WithStatus<TPMError>("Failed to migrate the certified migratable key"));

  const Blob protection_key_pubkey_digest =
      Sha1(challenge_data.protection_key_pubkey);
  const Blob msa_composite_digest =
      BuildMsaCompositeDigest(protection_key_pubkey_digest);
  const Blob cmk_pubkey_digest = Sha1(challenge_data.cmk_pubkey);

  // Decrypt and decode the CMK private key.
  ASSIGN_OR_RETURN(
      crypto::ScopedRSA cmk_private_key,
      ExtractCmkPrivateKeyFromMigratedBlob(
          overalls_, migrate_cmk.migrated_cmk_key12,
          migrate_cmk.migration_random, challenge_data.cmk_pubkey,
          cmk_pubkey_digest, msa_composite_digest,
          *challenge_data.migration_destination_rsa),
      _.WithStatus<TPMError>(
          "Failed to extract the certified migratable private key"));

  // Decrypt the AuthData value.
  SecureBlob auth_data;
  if (!RsaOaepDecrypt(SecureBlob(challenge_data.cmk_wrapped_auth_data),
                      /*oaep_label=*/SecureBlob(), cmk_private_key.get(),
                      &auth_data)) {
    return MakeStatus<TPMError>("Failed to decrypt the authorization data",
                                TPMRetryAction::kNoRetry);
  }

  OperationPolicy policy = challenge_data.policy;
  if (policy.permission.auth_value.has_value()) {
    return MakeStatus<TPMError>("Need empty auth value policy",
                                TPMRetryAction::kNoRetry);
  }

  policy.permission.auth_value = auth_data;

  ASSIGN_OR_RETURN(SecureBlob unsealed_data,
                   sealing_.Unseal(policy, challenge_data.pcr_bound_secret,
                                   Sealing::UnsealOptions{}),
                   _.WithStatus<TPMError>("Failed to seal the data"));

  // Unseal succeeded, remove the internal data.
  current_challenge_data_ = std::nullopt;

  return unsealed_data;
}

}  // namespace hwsec
