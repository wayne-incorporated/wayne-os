// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/tpm_pinweaver.h"

#include <endian.h>

#include <algorithm>

#include <base/logging.h>
#include <base/sys_byteorder.h>
#include <pinweaver/pinweaver_types.h>

namespace trunks {
namespace {

void Serialize(const void* value, size_t length, std::string* buffer) {
  const char* value_bytes = reinterpret_cast<const char*>(value);
  buffer->append(value_bytes, length);
}

void Serialize_pw_request_header_t(uint8_t protocol_version,
                                   uint8_t message_type,
                                   uint16_t data_length,
                                   std::string* buffer) {
  struct pw_request_header_t header = {
      protocol_version, {message_type}, htole16(data_length)};
  Serialize(&header, sizeof(header), buffer);
}

TPM_RC Parse_unimported_leaf_data_t(std::string::const_iterator begin,
                                    std::string::const_iterator end,
                                    std::string* cred_metadata,
                                    std::string* mac) {
  auto size = end - begin;
  if (size < sizeof(unimported_leaf_data_t))
    return SAPI_RC_BAD_SIZE;

  const struct unimported_leaf_data_t* unimported_leaf_data =
      reinterpret_cast<const struct unimported_leaf_data_t*>(&*begin);
  if (size != sizeof(unimported_leaf_data_t) +
                  unimported_leaf_data->head.pub_len +
                  unimported_leaf_data->head.sec_len) {
    return SAPI_RC_BAD_SIZE;
  }

  if (cred_metadata)
    cred_metadata->assign(begin, end);
  if (mac) {
    mac->assign(
        unimported_leaf_data->hmac,
        unimported_leaf_data->hmac + sizeof(unimported_leaf_data->hmac));
  }
  return TPM_RC_SUCCESS;
}

TPM_RC Validate_cred_metadata(const std::string& cred_metadata) {
  return Parse_unimported_leaf_data_t(cred_metadata.begin(),
                                      cred_metadata.end(), nullptr, nullptr);
}

}  // namespace

TPM_RC Serialize_pw_ping_t(uint8_t request_version, std::string* buffer) {
  buffer->reserve(buffer->size() + sizeof(pw_request_header_t));

  Serialize_pw_request_header_t(request_version, PW_MT_INVALID, 0, buffer);
  return TPM_RC_SUCCESS;
}

TPM_RC Serialize_pw_reset_tree_t(uint8_t protocol_version,
                                 uint8_t bits_per_level,
                                 uint8_t height,
                                 std::string* buffer) {
  struct pw_request_reset_tree00_t data = {{bits_per_level}, {height}};
  buffer->reserve(buffer->size() + sizeof(pw_request_header_t) + sizeof(data));

  Serialize_pw_request_header_t(protocol_version, PW_RESET_TREE, sizeof(data),
                                buffer);
  Serialize(&data, sizeof(data), buffer);
  return TPM_RC_SUCCESS;
}

TPM_RC Serialize_pw_insert_leaf_t(
    uint8_t protocol_version,
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
    std::string* buffer) {
  if (h_aux.length() > PW_MAX_PATH_SIZE || le_secret.size() != PW_SECRET_SIZE ||
      he_secret.size() != PW_SECRET_SIZE ||
      reset_secret.size() != PW_SECRET_SIZE ||
      delay_schedule.size() > PW_SCHED_COUNT ||
      valid_pcr_criteria.valid_pcr_values_size() > PW_MAX_PCR_CRITERIA_COUNT) {
    return SAPI_RC_BAD_PARAMETER;
  }

  struct pw_request_insert_leaf02_t data = {};
  int pcr_criteria_size =
      sizeof(struct valid_pcr_value_t) * PW_MAX_PCR_CRITERIA_COUNT;
  int data_size = sizeof(data);
  if (protocol_version == 0) {
    data_size -= pcr_criteria_size;
  }
  if (protocol_version <= 1) {
    size_t delta_in_bytes = offsetof(pw_request_insert_leaf02_t, path_hashes) -
                            offsetof(pw_request_insert_leaf01_t, path_hashes);
    data_size -= delta_in_bytes;
  }

  buffer->reserve(buffer->size() + sizeof(pw_request_header_t) + data_size +
                  h_aux.size());

  data.label = {htole64(label)};
  size_t x = 0;
  for (const auto& itr : delay_schedule) {
    data.delay_schedule[x].attempt_count = {htole32(itr.first)};
    data.delay_schedule[x].time_diff = {htole32(itr.second)};
    ++x;
  }

  if (protocol_version > 0) {
    x = 0;
    for (const ValidPcrValue& value : valid_pcr_criteria.valid_pcr_values()) {
      data.valid_pcr_criteria[x].bitmask[0] = value.bitmask()[0];
      data.valid_pcr_criteria[x].bitmask[1] = value.bitmask()[1];
      if (value.digest().size() > sizeof(data.valid_pcr_criteria[0].digest))
        return SAPI_RC_BAD_PARAMETER;
      std::copy(value.digest().begin(), value.digest().end(),
                data.valid_pcr_criteria[x].digest);
      ++x;
    }
    for (; x < PW_MAX_PCR_CRITERIA_COUNT; ++x) {
      memset(data.valid_pcr_criteria[x].bitmask, 0,
             sizeof(data.valid_pcr_criteria[x].bitmask));
    }
  } else if (valid_pcr_criteria.valid_pcr_values_size() > 0) {
    return SAPI_RC_BAD_PARAMETER;
  }

  if (protocol_version > 1) {
    data.expiration_delay_s.v =
        expiration_delay.has_value() ? *expiration_delay : 0;
    data.leaf_type.v = leaf_type;
    if (leaf_type == PW_LEAF_TYPE_BIOMETRICS) {
      data.auth_channel = *auth_channel;
    }
  } else if (expiration_delay.has_value() || leaf_type != PW_LEAF_TYPE_NORMAL) {
    return SAPI_RC_BAD_PARAMETER;
  }

  std::copy(le_secret.begin(), le_secret.end(), data.low_entropy_secret);
  std::copy(he_secret.begin(), he_secret.end(), data.high_entropy_secret);
  std::copy(reset_secret.begin(), reset_secret.end(), data.reset_secret);

  Serialize_pw_request_header_t(protocol_version, PW_INSERT_LEAF,
                                data_size + h_aux.size(), buffer);
  Serialize(&data, data_size, buffer);

  buffer->append(h_aux);
  return TPM_RC_SUCCESS;
}

TPM_RC Serialize_pw_remove_leaf_t(uint8_t protocol_version,
                                  uint64_t label,
                                  const std::string& h_aux,
                                  const std::string& mac,
                                  std::string* buffer) {
  if (h_aux.length() > PW_MAX_PATH_SIZE || mac.size() != PW_HASH_SIZE) {
    return SAPI_RC_BAD_PARAMETER;
  }

  struct pw_request_remove_leaf00_t data = {};
  buffer->reserve(buffer->size() + sizeof(pw_request_header_t) + sizeof(data) +
                  h_aux.size());

  data.leaf_location = {htole64(label)};
  std::copy(mac.begin(), mac.end(), data.leaf_hmac);

  Serialize_pw_request_header_t(protocol_version, PW_REMOVE_LEAF,
                                sizeof(data) + h_aux.size(), buffer);
  Serialize(&data, sizeof(data), buffer);
  buffer->append(h_aux);
  return TPM_RC_SUCCESS;
}

TPM_RC Serialize_pw_try_auth_t(uint8_t protocol_version,
                               const brillo::SecureBlob& le_secret,
                               const std::string& h_aux,
                               const std::string& cred_metadata,
                               std::string* buffer) {
  if (le_secret.size() != PW_SECRET_SIZE || h_aux.length() > PW_MAX_PATH_SIZE ||
      Validate_cred_metadata(cred_metadata) != TPM_RC_SUCCESS) {
    return SAPI_RC_BAD_PARAMETER;
  }

  buffer->reserve(buffer->size() + sizeof(pw_request_header_t) +
                  sizeof(pw_request_try_auth00_t) +
                  (cred_metadata.size() - sizeof(unimported_leaf_data_t)) +
                  h_aux.size());

  Serialize_pw_request_header_t(
      protocol_version, PW_TRY_AUTH,
      le_secret.size() + cred_metadata.size() + h_aux.size(), buffer);

  buffer->append(le_secret.to_string());
  buffer->append(cred_metadata);
  buffer->append(h_aux);
  return TPM_RC_SUCCESS;
}

TPM_RC Serialize_pw_reset_auth_t(uint8_t protocol_version,
                                 const brillo::SecureBlob& reset_secret,
                                 bool strong_reset,
                                 const std::string& h_aux,
                                 const std::string& cred_metadata,
                                 std::string* buffer) {
  if (reset_secret.size() != PW_SECRET_SIZE ||
      h_aux.length() > PW_MAX_PATH_SIZE ||
      Validate_cred_metadata(cred_metadata) != TPM_RC_SUCCESS) {
    return SAPI_RC_BAD_PARAMETER;
  }

  struct pw_request_reset_auth02_t data = {};
  size_t data_size =
      sizeof(pw_request_reset_auth02_t) - sizeof(unimported_leaf_data_t);
  if (protocol_version <= 1) {
    // Prior to version 2, the strong_reset field, which is 1 byte, doesn't
    // exist.
    data_size -= 1;
  }

  buffer->reserve(buffer->size() + sizeof(pw_request_header_t) + data_size +
                  cred_metadata.size() + h_aux.size());

  std::copy(reset_secret.begin(), reset_secret.end(), data.reset_secret);
  if (protocol_version > 1) {
    data.strong_reset = static_cast<uint8_t>(strong_reset);
  } else if (strong_reset) {
    return SAPI_RC_BAD_PARAMETER;
  }

  Serialize_pw_request_header_t(protocol_version, PW_RESET_AUTH,
                                data_size + cred_metadata.size() + h_aux.size(),
                                buffer);
  Serialize(&data, data_size, buffer);

  buffer->append(cred_metadata);
  buffer->append(h_aux);
  return TPM_RC_SUCCESS;
}

TPM_RC Serialize_pw_get_log_t(uint8_t protocol_version,
                              const std::string& root,
                              std::string* buffer) {
  if (root.size() != PW_HASH_SIZE) {
    return SAPI_RC_BAD_PARAMETER;
  }

  Serialize_pw_request_header_t(protocol_version, PW_GET_LOG,
                                sizeof(struct pw_request_get_log00_t), buffer);
  buffer->append(root);
  return TPM_RC_SUCCESS;
}

TPM_RC Serialize_pw_log_replay_t(uint8_t protocol_version,
                                 const std::string& log_root,
                                 const std::string& h_aux,
                                 const std::string& cred_metadata,
                                 std::string* buffer) {
  if (log_root.size() != PW_HASH_SIZE || h_aux.length() > PW_MAX_PATH_SIZE ||
      Validate_cred_metadata(cred_metadata) != TPM_RC_SUCCESS) {
    return SAPI_RC_BAD_PARAMETER;
  }

  buffer->reserve(buffer->size() + sizeof(pw_request_header_t) +
                  sizeof(pw_request_log_replay00_t) +
                  (cred_metadata.size() - sizeof(unimported_leaf_data_t)) +
                  h_aux.size());

  Serialize_pw_request_header_t(protocol_version, PW_LOG_REPLAY,
                                sizeof(pw_request_log_replay00_t) -
                                    sizeof(struct unimported_leaf_data_t) +
                                    cred_metadata.size() + h_aux.size(),
                                buffer);
  buffer->append(log_root);
  buffer->append(cred_metadata);
  buffer->append(h_aux);
  return TPM_RC_SUCCESS;
}

TPM_RC Serialize_pw_sys_info_t(uint8_t protocol_version, std::string* buffer) {
  if (protocol_version <= 1) {
    return SAPI_RC_BAD_PARAMETER;
  }

  buffer->reserve(buffer->size() + sizeof(pw_request_header_t));
  Serialize_pw_request_header_t(protocol_version, PW_SYS_INFO, 0, buffer);
  return TPM_RC_SUCCESS;
}

TPM_RC Serialize_pw_generate_ba_pk_t(uint8_t protocol_version,
                                     uint8_t auth_channel,
                                     const PinWeaverEccPoint& client_public_key,
                                     std::string* buffer) {
  if (protocol_version <= 1) {
    return SAPI_RC_BAD_PARAMETER;
  }

  struct pw_request_generate_ba_pk02_t data = {};
  size_t data_size = sizeof(data);
  buffer->reserve(buffer->size() + sizeof(pw_request_header_t) + data_size);

  data.auth_channel = auth_channel;
  // Version 0 is the raw point format.
  data.client_pbk.version = 0;
  memcpy(data.client_pbk.pt.x, client_public_key.x, PW_BA_ECC_CORD_SIZE);
  memcpy(data.client_pbk.pt.y, client_public_key.y, PW_BA_ECC_CORD_SIZE);
  Serialize_pw_request_header_t(protocol_version, PW_GENERATE_BA_PK, data_size,
                                buffer);
  Serialize(&data, data_size, buffer);
  return TPM_RC_SUCCESS;
}

TPM_RC Serialize_pw_start_bio_auth_t(uint8_t protocol_version,
                                     uint8_t auth_channel,
                                     const brillo::Blob& client_nonce,
                                     const std::string& h_aux,
                                     const std::string& cred_metadata,
                                     std::string* buffer) {
  if (protocol_version <= 1 || auth_channel > PW_BA_PK_ENTRY_COUNT ||
      client_nonce.size() != PW_SECRET_SIZE) {
    return SAPI_RC_BAD_PARAMETER;
  }

  // A standard try_auth request is part of the start_bio_auth request,
  // so we call Serialize_pw_try_auth_t first then modify its body and
  // header.
  brillo::SecureBlob zeroed_secret(PW_SECRET_SIZE, 0);
  TPM_RC ret = Serialize_pw_try_auth_t(
      /*protocol_version=*/2, zeroed_secret, h_aux, cred_metadata, buffer);
  if (ret != TPM_RC_SUCCESS) {
    return ret;
  }

  if (buffer->size() <
      sizeof(pw_request_header_t) + sizeof(pw_request_try_auth00_t)) {
    return SAPI_RC_BAD_SIZE;
  }

  // Reserve space for the full start_bio_auth request.
  size_t offset = offsetof(pw_request_start_bio_auth02_t, uninit_request);
  buffer->insert(sizeof(pw_request_header_t), offset, '\0');

  // To prevent misalignment issues, memcpy to allocated structs, modify them
  // accordingly, then memcpy back.
  pw_request_header_t header;
  pw_request_start_bio_auth02_t request;
  memcpy(&header, buffer->data(), sizeof(pw_request_header_t));
  memcpy(&request, buffer->data() + sizeof(pw_request_header_t),
         sizeof(pw_request_start_bio_auth02_t));
  header.version = protocol_version;
  header.type.v = PW_START_BIO_AUTH;
  header.data_length += offset;
  request.auth_channel = auth_channel;
  memcpy(request.client_nonce, client_nonce.data(), PW_SECRET_SIZE);
  memcpy(buffer->data(), &header, sizeof(pw_request_header_t));
  memcpy(buffer->data() + sizeof(pw_request_header_t), &request,
         sizeof(pw_request_start_bio_auth02_t));

  return TPM_RC_SUCCESS;
}

TPM_RC Serialize_pw_block_generate_ba_pk_t(uint8_t protocol_version,
                                           std::string* buffer) {
  if (protocol_version <= 1) {
    return SAPI_RC_BAD_PARAMETER;
  }

  buffer->reserve(buffer->size() + sizeof(pw_request_header_t));

  Serialize_pw_request_header_t(protocol_version, PW_BLOCK_GENERATE_BA_PK, 0,
                                buffer);
  return TPM_RC_SUCCESS;
}

TPM_RC Parse_pw_response_header_t(const std::string& buffer,
                                  uint32_t* result_code,
                                  std::string* root_hash,
                                  uint16_t* data_length) {
  *result_code = 0;
  if (root_hash)
    root_hash->clear();
  *data_length = 0;

  if (buffer.empty()) {
    return SAPI_RC_INSUFFICIENT_BUFFER;
  }

  uint8_t version = (uint8_t)buffer[0];
  if (version > PW_PROTOCOL_VERSION) {
    LOG(ERROR) << "Pinweaver protocol version mismatch: got "
               << static_cast<uint32_t>(version) << " expected "
               << PW_PROTOCOL_VERSION << " or lower.";
    return SAPI_RC_ABI_MISMATCH;
  }

  if (buffer.size() < sizeof(struct pw_response_header_t)) {
    LOG(ERROR) << "Pinweaver response contained an unexpected number of bytes.";
    return SAPI_RC_INSUFFICIENT_BUFFER;
  }

  const struct pw_response_header_t* header =
      reinterpret_cast<const struct pw_response_header_t*>(buffer.data());
  *result_code = le32toh(header->result_code);
  if (root_hash)
    root_hash->assign(header->root, header->root + sizeof(header->root));
  *data_length = le16toh(header->data_length);

  if (buffer.size() != sizeof(struct pw_response_header_t) + *data_length) {
    LOG(ERROR) << "Pinweaver response contained " << buffer.size()
               << " instead of "
               << sizeof(struct pw_response_header_t) + *data_length
               << "bytes.";
    return SAPI_RC_BAD_SIZE;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC Parse_pw_short_message(const std::string& buffer,
                              uint32_t* result_code,
                              std::string* root_hash) {
  uint16_t data_length;
  TPM_RC rc =
      Parse_pw_response_header_t(buffer, result_code, root_hash, &data_length);
  if (rc != TPM_RC_SUCCESS)
    return rc;

  if (data_length != 0) {
    LOG(ERROR) << "Pinweaver error contained an unexpected number of bytes.";
    return SAPI_RC_BAD_SIZE;
  }

  return TPM_RC_SUCCESS;
}

TPM_RC Parse_pw_pong_t(const std::string& buffer, uint8_t* protocol_version) {
  uint32_t result_code;
  TPM_RC rc = Parse_pw_short_message(buffer, &result_code, nullptr);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (result_code != PW_ERR_TYPE_INVALID &&
      result_code != PW_ERR_VERSION_MISMATCH)
    return SAPI_RC_ABI_MISMATCH;
  *protocol_version = (uint8_t)buffer[0];
  return TPM_RC_SUCCESS;
}

TPM_RC Parse_pw_insert_leaf_t(const std::string& buffer,
                              uint32_t* result_code,
                              std::string* root_hash,
                              std::string* cred_metadata,
                              std::string* mac) {
  cred_metadata->clear();
  mac->clear();

  uint16_t response_length;
  TPM_RC rc = Parse_pw_response_header_t(buffer, result_code, root_hash,
                                         &response_length);
  if (rc != TPM_RC_SUCCESS)
    return rc;

  if (*result_code != 0) {
    return response_length == 0 ? TPM_RC_SUCCESS : SAPI_RC_BAD_SIZE;
  }

  return Parse_unimported_leaf_data_t(
      buffer.begin() + sizeof(pw_response_header_t), buffer.end(),
      cred_metadata, mac);
}

TPM_RC Parse_pw_try_auth_t(const std::string& buffer,
                           uint32_t* result_code,
                           std::string* root_hash,
                           uint32_t* seconds_to_wait,
                           brillo::SecureBlob* he_secret,
                           brillo::SecureBlob* reset_secret,
                           std::string* cred_metadata_out,
                           std::string* mac_out) {
  *seconds_to_wait = 0;
  he_secret->clear();
  reset_secret->clear();
  cred_metadata_out->clear();
  mac_out->clear();

  uint16_t response_length;
  TPM_RC rc = Parse_pw_response_header_t(buffer, result_code, root_hash,
                                         &response_length);
  if (rc != TPM_RC_SUCCESS)
    return rc;

  // For EC_SUCCESS, PW_ERR_RATE_LIMIT_REACHED, PW_ERR_LOWENT_AUTH_FAILED, and
  // PW_ERR_EXPIRED a full size response is sent. However, only particular
  // fields are valid.
  if (*result_code != 0 && *result_code != PW_ERR_RATE_LIMIT_REACHED &&
      *result_code != PW_ERR_LOWENT_AUTH_FAILED &&
      *result_code != PW_ERR_EXPIRED) {
    return response_length == 0 ? TPM_RC_SUCCESS : SAPI_RC_BAD_SIZE;
  }

  if (response_length < sizeof(pw_response_try_auth01_t))
    return SAPI_RC_BAD_SIZE;

  // For PW_ERR_EXPIRED, no fields from the response are valid.
  if (*result_code == PW_ERR_EXPIRED)
    return TPM_RC_SUCCESS;

  auto itr = buffer.begin() + sizeof(pw_response_header_t);
  // This field may not be aligned so it is retrieved in a way that will work
  // regardless of platform. PinWeaver commands are little endian.
  *seconds_to_wait = static_cast<uint32_t>(itr[0]) |
                     (static_cast<uint32_t>(itr[1]) << 8) |
                     (static_cast<uint32_t>(itr[2]) << 16) |
                     (static_cast<uint32_t>(itr[3]) << 24);
  itr += 4;

  // he_secret is only valid for EC_SUCCESS.
  if (*result_code == 0) {
    he_secret->assign(itr, itr + PW_SECRET_SIZE);
    // reset_secret is present only starting from protocol_version = 1.
    if ((uint8_t)buffer[0] > 0) {
      reset_secret->assign(itr + PW_SECRET_SIZE, itr + 2 * PW_SECRET_SIZE);
    }
  }
  if ((uint8_t)buffer[0] > 0) {
    itr += 2 * PW_SECRET_SIZE;
  } else {
    itr += PW_SECRET_SIZE;
  }

  // For PW_ERR_RATE_LIMIT_REACHED the only valid result field is
  // seconds_to_wait.
  if (*result_code == PW_ERR_RATE_LIMIT_REACHED)
    return TPM_RC_SUCCESS;

  return Parse_unimported_leaf_data_t(itr, buffer.end(), cred_metadata_out,
                                      mac_out);
}

TPM_RC Parse_pw_reset_auth_t(const std::string& buffer,
                             uint32_t* result_code,
                             std::string* root_hash,
                             std::string* cred_metadata_out,
                             std::string* mac_out) {
  cred_metadata_out->clear();
  mac_out->clear();

  uint16_t response_length;
  TPM_RC rc = Parse_pw_response_header_t(buffer, result_code, root_hash,
                                         &response_length);
  if (rc != TPM_RC_SUCCESS)
    return rc;

  if (*result_code != 0) {
    return response_length == 0 ? TPM_RC_SUCCESS : SAPI_RC_BAD_SIZE;
  }

  // Need this check before we read the version byte.
  if (response_length < 1) {
    LOG(ERROR) << "Pinweaver pw_response_reset_auth contained an unexpected "
                  "number of bytes.";
    return SAPI_RC_BAD_SIZE;
  }
  uint8_t protocol_version = static_cast<uint8_t>(buffer[0]);
  size_t expected_response_length = protocol_version <= 1
                                        ? sizeof(pw_response_reset_auth00_t)
                                        : sizeof(pw_response_reset_auth02_t);
  if (response_length < expected_response_length) {
    LOG(ERROR) << "Pinweaver pw_response_reset_auth contained an unexpected "
                  "number of bytes.";
    return SAPI_RC_BAD_SIZE;
  }

  auto itr = buffer.begin() + sizeof(pw_response_header_t);
  if (protocol_version <= 1) {
    // HE secret is included in the response prior to v2, but we don't parse it.
    itr += PW_SECRET_SIZE;
  }

  return Parse_unimported_leaf_data_t(itr, buffer.end(), cred_metadata_out,
                                      mac_out);
}

TPM_RC Parse_pw_get_log_t(const std::string& buffer,
                          uint32_t* result_code,
                          std::string* root_hash,
                          std::vector<trunks::PinWeaverLogEntry>* log) {
  log->clear();

  uint16_t response_length;
  TPM_RC rc = Parse_pw_response_header_t(buffer, result_code, root_hash,
                                         &response_length);
  if (rc != TPM_RC_SUCCESS)
    return rc;

  if (*result_code != 0) {
    return response_length == 0 ? TPM_RC_SUCCESS : SAPI_RC_BAD_SIZE;
  }

  if (response_length % sizeof(struct pw_get_log_entry_t) != 0)
    return SAPI_RC_BAD_SIZE;

  log->resize(response_length / sizeof(struct pw_get_log_entry_t));
  TPM_RC ret = TPM_RC_SUCCESS;
  size_t x = 0;
  for (auto itr = buffer.begin() + sizeof(struct pw_response_header_t);
       itr < buffer.end(); itr += sizeof(struct pw_get_log_entry_t)) {
    const struct pw_get_log_entry_t* entry =
        reinterpret_cast<const struct pw_get_log_entry_t*>(&*itr);
    trunks::PinWeaverLogEntry* proto_entry = &(*log)[x];
    proto_entry->set_label(entry->label.v);
    proto_entry->set_root(entry->root, PW_HASH_SIZE);
    switch (entry->type.v) {
      case LOG_PW_INSERT_LEAF00:
        proto_entry->mutable_insert_leaf()->set_hmac(entry->leaf_hmac,
                                                     PW_HASH_SIZE);
        break;
      case LOG_PW_REMOVE_LEAF00:
        proto_entry->mutable_remove_leaf();
        break;
      case LOG_PW_TRY_AUTH00:
      case LOG_PW_TRY_AUTH02:
        proto_entry->mutable_auth();
        break;
      case LOG_PW_RESET_TREE00:
        proto_entry->mutable_reset_tree();
        break;
      default:
        // The entries that don't match any known types will be treated
        // as type invalid. We don't want to return an error here because
        // it's sometimes expected behavior to receive unknown entries when
        // the server rollbacks the version. The log entry can still be used
        // for parsing root hash, though it can't be replayed.
        break;
    }
    ++x;
  }
  return ret;
}

TPM_RC Parse_pw_log_replay_t(const std::string& buffer,
                             uint32_t* result_code,
                             std::string* root_hash,
                             std::string* cred_metadata_out,
                             std::string* mac_out) {
  cred_metadata_out->clear();
  mac_out->clear();

  uint16_t response_length;
  TPM_RC rc = Parse_pw_response_header_t(buffer, result_code, root_hash,
                                         &response_length);
  if (rc != TPM_RC_SUCCESS)
    return rc;

  if (*result_code != 0) {
    return response_length == 0 ? TPM_RC_SUCCESS : SAPI_RC_BAD_SIZE;
  }

  if (response_length < sizeof(struct pw_response_reset_auth00_t))
    return SAPI_RC_BAD_SIZE;

  auto itr = buffer.begin() + sizeof(struct pw_response_header_t);

  return Parse_unimported_leaf_data_t(itr, buffer.end(), cred_metadata_out,
                                      mac_out);
}

TPM_RC Parse_pw_sys_info_t(const std::string& buffer,
                           uint32_t* result_code,
                           std::string* root_hash,
                           uint32_t* boot_count,
                           uint64_t* seconds_since_boot) {
  *boot_count = 0;
  *seconds_since_boot = 0;

  uint16_t response_length;
  TPM_RC rc = Parse_pw_response_header_t(buffer, result_code, root_hash,
                                         &response_length);
  if (rc != TPM_RC_SUCCESS)
    return rc;

  if (*result_code != 0) {
    return response_length == 0 ? TPM_RC_SUCCESS : SAPI_RC_BAD_SIZE;
  }

  if (response_length < sizeof(struct pw_response_sys_info02_t))
    return SAPI_RC_BAD_SIZE;

  auto itr = buffer.begin() + sizeof(struct pw_response_header_t);

  memcpy(boot_count, &*itr, 4);
  itr += 4;
  *boot_count = base::ByteSwapToLE32(*boot_count);
  memcpy(seconds_since_boot, &*itr, 8);
  *seconds_since_boot = base::ByteSwapToLE64(*seconds_since_boot);

  return TPM_RC_SUCCESS;
}

TPM_RC Parse_pw_generate_ba_pk_t(const std::string& buffer,
                                 uint32_t* result_code,
                                 std::string* root_hash,
                                 PinWeaverEccPoint* server_public_key) {
  uint16_t response_length;
  TPM_RC rc = Parse_pw_response_header_t(buffer, result_code, root_hash,
                                         &response_length);
  if (rc != TPM_RC_SUCCESS)
    return rc;

  if (*result_code != 0) {
    return response_length == 0 ? TPM_RC_SUCCESS : SAPI_RC_BAD_SIZE;
  }

  if (response_length < sizeof(struct pw_response_generate_ba_pk02_t))
    return SAPI_RC_BAD_SIZE;

  const auto* pbk = reinterpret_cast<const struct pw_ba_pbk_t*>(
      buffer.data() + sizeof(struct pw_response_header_t));
  if (pbk->version != 0)
    return SAPI_RC_BAD_SEQUENCE;

  memcpy(server_public_key->x, pbk->pt.x, PW_BA_ECC_CORD_SIZE);
  memcpy(server_public_key->y, pbk->pt.y, PW_BA_ECC_CORD_SIZE);

  return TPM_RC_SUCCESS;
}

TPM_RC
Parse_pw_start_bio_auth_t(const std::string& buffer,
                          uint32_t* result_code,
                          std::string* root_hash,
                          brillo::Blob* server_nonce,
                          brillo::Blob* encrypted_high_entropy_secret,
                          brillo::Blob* iv,
                          std::string* cred_metadata_out,
                          std::string* mac_out) {
  server_nonce->clear();
  encrypted_high_entropy_secret->clear();
  iv->clear();
  cred_metadata_out->clear();
  mac_out->clear();

  uint16_t response_length;
  TPM_RC rc = Parse_pw_response_header_t(buffer, result_code, root_hash,
                                         &response_length);
  if (rc != TPM_RC_SUCCESS)
    return rc;

  // For EC_SUCCESS and PW_ERR_LOWENT_AUTH_FAILED a full size response is sent.
  // However, only particular fields are valid.
  if (*result_code != 0 && *result_code != PW_ERR_LOWENT_AUTH_FAILED) {
    return response_length == 0 ? TPM_RC_SUCCESS : SAPI_RC_BAD_SIZE;
  }

  if (response_length < sizeof(pw_response_start_bio_auth02_t))
    return SAPI_RC_BAD_SIZE;

  auto itr = buffer.begin() + sizeof(pw_response_header_t);

  // secrets are only valid for EC_SUCCESS.
  if (*result_code == 0) {
    server_nonce->assign(itr, itr + PW_SECRET_SIZE);
    encrypted_high_entropy_secret->assign(itr + PW_SECRET_SIZE,
                                          itr + 2 * PW_SECRET_SIZE);
    iv->assign(itr + 2 * PW_SECRET_SIZE,
               itr + 2 * PW_SECRET_SIZE + PW_WRAP_BLOCK_SIZE);
  }
  itr += 2 * PW_SECRET_SIZE + PW_WRAP_BLOCK_SIZE;

  return Parse_unimported_leaf_data_t(itr, buffer.end(), cred_metadata_out,
                                      mac_out);
}

}  // namespace trunks
