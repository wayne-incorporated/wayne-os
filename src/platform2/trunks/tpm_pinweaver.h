// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_TPM_PINWEAVER_H_
#define TRUNKS_TPM_PINWEAVER_H_

extern "C" {
#define __packed __attribute((packed))
#define __aligned(x) __attribute((aligned(x)))
#include <pinweaver/pinweaver_types.h>
}

#include <map>
#include <optional>
#include <string>
#include <vector>

#include <base/command_line.h>
#include <brillo/brillo_export.h>
#include <brillo/secure_blob.h>

#include "trunks/error_codes.h"
#include "trunks/tpm_utility.h"

namespace trunks {

BRILLO_EXPORT TPM_RC Serialize_pw_ping_t(uint8_t request_version,
                                         std::string* buffer);

BRILLO_EXPORT TPM_RC Serialize_pw_reset_tree_t(uint8_t protocol_version,
                                               uint8_t bits_per_level,
                                               uint8_t height,
                                               std::string* buffer);

BRILLO_EXPORT TPM_RC
Serialize_pw_insert_leaf_t(uint8_t protocol_version,
                           uint64_t label,
                           const std::string& h_aux,
                           const brillo::SecureBlob& le_secret,
                           const brillo::SecureBlob& he_secret,
                           const brillo::SecureBlob& reset_secret,
                           const std::map<uint32_t, uint32_t>& delay_schedule,
                           const ValidPcrCriteria& valid_pcr_criteria,
                           std::optional<uint32_t> expiration_delay,
                           uint8_t leaf_type,
                           std::optional<uint8_t> auth_channel,
                           std::string* buffer);

BRILLO_EXPORT TPM_RC Serialize_pw_remove_leaf_t(uint8_t protocol_version,
                                                uint64_t label,
                                                const std::string& h_aux,
                                                const std::string& mac,
                                                std::string* buffer);

BRILLO_EXPORT TPM_RC
Serialize_pw_try_auth_t(uint8_t protocol_version,
                        const brillo::SecureBlob& le_secret,
                        const std::string& h_aux,
                        const std::string& cred_metadata,
                        std::string* buffer);

BRILLO_EXPORT TPM_RC
Serialize_pw_reset_auth_t(uint8_t protocol_version,
                          const brillo::SecureBlob& reset_secret,
                          bool strong_reset,
                          const std::string& h_aux,
                          const std::string& cred_metadata,
                          std::string* buffer);

BRILLO_EXPORT TPM_RC Serialize_pw_get_log_t(uint8_t protocol_version,
                                            const std::string& root,
                                            std::string* buffer);

BRILLO_EXPORT TPM_RC Serialize_pw_log_replay_t(uint8_t protocol_version,
                                               const std::string& log_root,
                                               const std::string& h_aux,
                                               const std::string& cred_metadata,
                                               std::string* buffer);

BRILLO_EXPORT TPM_RC Serialize_pw_sys_info_t(uint8_t protocol_version,
                                             std::string* buffer);

BRILLO_EXPORT TPM_RC
Serialize_pw_generate_ba_pk_t(uint8_t protocol_version,
                              uint8_t auth_channel,
                              const PinWeaverEccPoint& client_public_key,
                              std::string* buffer);

BRILLO_EXPORT TPM_RC
Serialize_pw_start_bio_auth_t(uint8_t protocol_version,
                              uint8_t auth_channel,
                              const brillo::Blob& client_nonce,
                              const std::string& h_aux,
                              const std::string& cred_metadata,
                              std::string* buffer);

BRILLO_EXPORT TPM_RC Serialize_pw_block_generate_ba_pk_t(
    uint8_t protocol_version, std::string* buffer);

// If TPM_RC_SUCCESS is returned, |result_code| and |root_hash| will be valid.
// The other fields generally will not be valid unless |result_code| is zero.
// Try auth has an exception for PW_ERR_LOWENT_AUTH_FAILED and
// PW_ERR_RATE_LIMIT_REACHED that have additional valid fields. Rather than
// using the return codes to determine which fields are valid, it is sufficient
// to determine a field is valid by checking that it is not empty.
BRILLO_EXPORT TPM_RC Parse_pw_response_header_t(const std::string& buffer,
                                                uint32_t* result_code,
                                                std::string* root_hash,
                                                uint16_t* data_length);

BRILLO_EXPORT TPM_RC Parse_pw_short_message(const std::string& buffer,
                                            uint32_t* result_code,
                                            std::string* root_hash);

BRILLO_EXPORT TPM_RC Parse_pw_pong_t(const std::string& buffer,
                                     uint8_t* protocol_version);

BRILLO_EXPORT TPM_RC Parse_pw_insert_leaf_t(const std::string& buffer,
                                            uint32_t* result_code,
                                            std::string* root_hash,
                                            std::string* cred_metadata,
                                            std::string* mac);

BRILLO_EXPORT TPM_RC Parse_pw_try_auth_t(const std::string& buffer,
                                         uint32_t* result_code,
                                         std::string* root_hash,
                                         uint32_t* seconds_to_wait,
                                         brillo::SecureBlob* he_secret,
                                         brillo::SecureBlob* reset_secret,
                                         std::string* cred_metadata_out,
                                         std::string* mac_out);

BRILLO_EXPORT TPM_RC Parse_pw_reset_auth_t(const std::string& buffer,
                                           uint32_t* result_code,
                                           std::string* root_hash,
                                           std::string* cred_metadata_out,
                                           std::string* mac_out);

BRILLO_EXPORT TPM_RC
Parse_pw_get_log_t(const std::string& buffer,
                   uint32_t* result_code,
                   std::string* root_hash,
                   std::vector<trunks::PinWeaverLogEntry>* log);

BRILLO_EXPORT TPM_RC Parse_pw_log_replay_t(const std::string& buffer,
                                           uint32_t* result_code,
                                           std::string* root_hash,
                                           std::string* cred_metadata_out,
                                           std::string* mac_out);

BRILLO_EXPORT TPM_RC Parse_pw_sys_info_t(const std::string& buffer,
                                         uint32_t* result_code,
                                         std::string* root_hash,
                                         uint32_t* boot_count,
                                         uint64_t* seconds_since_boot);

BRILLO_EXPORT TPM_RC
Parse_pw_generate_ba_pk_t(const std::string& buffer,
                          uint32_t* result_code,
                          std::string* root_hash,
                          PinWeaverEccPoint* server_public_key);

BRILLO_EXPORT TPM_RC
Parse_pw_ba_create_rate_limiter_t(const std::string& buffer,
                                  uint32_t* result_code,
                                  std::string* root_hash,
                                  std::string* cred_metadata,
                                  std::string* mac);

BRILLO_EXPORT TPM_RC
Parse_pw_start_bio_auth_t(const std::string& buffer,
                          uint32_t* result_code,
                          std::string* root_hash,
                          brillo::Blob* server_nonce,
                          brillo::Blob* encrypted_high_entropy_secret,
                          brillo::Blob* iv,
                          std::string* cred_metadata_out,
                          std::string* mac_out);
}  // namespace trunks

#endif  // TRUNKS_TPM_PINWEAVER_H_
