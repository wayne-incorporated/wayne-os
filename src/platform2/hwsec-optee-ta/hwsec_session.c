// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-optee-ta/hwsec_session.h"

#include <stdint.h>
#include <string.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <tpm2/tpm_generated.h>

#include "hwsec-optee-ta/hwsec_cmd.h"

#define HWSEC_PTA_UUID                               \
  {                                                  \
    0x721f4da9, 0xda05, 0x40d4, {                    \
      0xa1, 0xa3, 0x83, 0x77, 0xc1, 0xe0, 0x8b, 0x0a \
    }                                                \
  }

#define KEY_MAX_BITS 256
#define SALT_BUFFER_SIZE 68
#define HWSEC_NONCE_MIN_SIZE 16
#define HWSEC_NONCE_MAX_SIZE (sizeof(TPM2B_NONCE))

#define TPM_AUTH_KEY_INDEX 0x81000002
#define TPM_AUTH_PUB_MAX_LEN 128
#define GET_PUBKEY 0

static uint8_t buffer[HWSEC_COMMAND_MAX_LEN];

static TEE_Result get_auth_pubkey(uint8_t* auth_pubkey, int32_t* length) {
  static const TEE_UUID uuid = HWSEC_PTA_UUID;

  TEE_Result res = TEE_ERROR_GENERIC;

  TEE_TASessionHandle sess;
  res = TEE_OpenTASession(&uuid, TEE_TIMEOUT_INFINITE, 0, NULL, &sess, NULL);
  if (res != TEE_SUCCESS) {
    EMSG("TEE_OpenTASession failed with code 0x%x", res);
    return res;
  }

  uint32_t ptypes =
      TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT, TEE_PARAM_TYPE_VALUE_OUTPUT,
                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

  TEE_Param params[TEE_NUM_PARAMS];
  params[0].memref.size = *length;
  params[0].memref.buffer = auth_pubkey;

  res = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE, GET_PUBKEY, ptypes,
                            params, NULL);
  if (res != TEE_SUCCESS) {
    EMSG("TEE_InvokeTACommand failed with code 0x%x", res);
    goto cleanup_sess;
  }

  *length = params[1].value.a;

cleanup_sess:
  TEE_CloseTASession(sess);

  return res;
}

static TEE_Result InitHmacSha256Operation(TEE_OperationHandle* op,
                                          uint8_t* key_data,
                                          uint32_t key_len) {
  TEE_Result res = TEE_ERROR_GENERIC;
  TEE_ObjectHandle key = TEE_HANDLE_NULL;

  TEE_Attribute hmac_key_attr;
  TEE_InitRefAttribute(&hmac_key_attr, TEE_ATTR_SECRET_VALUE, key_data,
                       key_len);

  res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, KEY_MAX_BITS, &key);
  if (res != TEE_SUCCESS) {
    EMSG("TEE_AllocateTransientObject failed with code 0x%x", res);
    return res;
  }

  res = TEE_PopulateTransientObject(key, &hmac_key_attr, 1);
  if (res != TEE_SUCCESS) {
    EMSG("TEE_PopulateTransientObject failed with code 0x%x", res);
    goto cleanup_key;
  }

  res = TEE_AllocateOperation(op, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC,
                              KEY_MAX_BITS);
  if (res != TEE_SUCCESS) {
    EMSG("TEE_AllocateOperation failed with code 0x%x", res);
    goto cleanup_key;
  }

  res = TEE_SetOperationKey(*op, key);

  if (res != TEE_SUCCESS) {
    EMSG("TEE_SetOperationKey failed with code 0x%x", res);
    goto cleanup_op;
  }

  TEE_MACInit(*op, NULL, 0);

  res = TEE_SUCCESS;
  // We don't clean up the "op" here.
  goto cleanup_key;

cleanup_op:
  TEE_FreeOperation(*op);

cleanup_key:
  TEE_FreeTransientObject(key);

  return res;
}

static TEE_Result GenerateSalt(uint8_t salt[SHA256_DIGEST_SIZE],
                               TPM2B_ENCRYPTED_SECRET* encrypted_secret) {
  TEE_Result res = TEE_ERROR_GENERIC;
  TPM_RC tpm_rc;

  int32_t tpm_auth_pub_len;
  uint8_t tpm_auth_pub[TPM_AUTH_PUB_MAX_LEN];
  uint8_t* tpm_auth_pub_ptr;
  TPM2B_PUBLIC pub;
  TPMS_ECC_POINT ephemeral_point;

  uint32_t temp_len;
  uint8_t z_value[SHA256_DIGEST_SIZE];
  uint8_t party_u_info[SHA256_DIGEST_SIZE];
  uint8_t party_v_info[SHA256_DIGEST_SIZE];

  tpm_auth_pub_len = TPM_AUTH_PUB_MAX_LEN;
  res = get_auth_pubkey(tpm_auth_pub, &tpm_auth_pub_len);
  if (res != TEE_SUCCESS) {
    EMSG("get_auth_pubkey failed with code 0x%x", res);
    return res;
  }

  tpm_auth_pub_ptr = tpm_auth_pub;
  tpm_rc = TPM2B_PUBLIC_Unmarshal(&pub, &tpm_auth_pub_ptr, &tpm_auth_pub_len);
  if (tpm_rc != TPM_RC_SUCCESS) {
    EMSG("TPM2B_PUBLIC_Unmarshal failed with code 0x%x", tpm_rc);
    return TEE_ERROR_BAD_FORMAT;
  }

  if (pub.t.publicArea.type != TPM_ALG_ECC) {
    EMSG("Invalid salting key type.");
    return TEE_ERROR_NOT_SUPPORTED;
  }

  if (pub.t.publicArea.nameAlg != TPM_ALG_SHA256 ||
      pub.t.publicArea.unique.ecc.x.t.size != SHA256_DIGEST_SIZE ||
      pub.t.publicArea.unique.ecc.y.t.size != SHA256_DIGEST_SIZE) {
    EMSG("Invalid ECC salting key attributes.");
    return TEE_ERROR_NOT_SUPPORTED;
  }

  memcpy(party_v_info, pub.t.publicArea.unique.ecc.x.t.buffer,
         SHA256_DIGEST_SIZE);

  TEE_Attribute curv_attr;
  TEE_InitValueAttribute(&curv_attr, TEE_ATTR_ECC_CURVE,
                         TEE_ECC_CURVE_NIST_P256, 0);

  TEE_ObjectHandle key = TEE_HANDLE_NULL;

  res = TEE_AllocateTransientObject(TEE_TYPE_ECDH_KEYPAIR, KEY_MAX_BITS, &key);
  if (res != TEE_SUCCESS) {
    EMSG("TEE_AllocateTransientObject failed with code 0x%x", res);
    return res;
  }

  res = TEE_GenerateKey(key, KEY_MAX_BITS, &curv_attr, 1);
  if (res != TEE_SUCCESS) {
    EMSG("TEE_GenerateKey failed with code 0x%x", res);
    goto cleanup_key;
  }

  temp_len = SHA256_DIGEST_SIZE;
  res = TEE_GetObjectBufferAttribute(key, TEE_ATTR_ECC_PUBLIC_VALUE_X,
                                     ephemeral_point.x.t.buffer, &temp_len);
  if (res != TEE_SUCCESS) {
    EMSG("TEE_GetObjectBufferAttribute failed with code 0x%x", res);
    goto cleanup_key;
  } else if (temp_len > SHA256_DIGEST_SIZE) {
    EMSG("Unsupported ephemeral_point_x length %u", temp_len);
    res = TEE_ERROR_NOT_SUPPORTED;
    goto cleanup_key;
  } else if (temp_len < SHA256_DIGEST_SIZE) {
    uint32_t diff = SHA256_DIGEST_SIZE - temp_len;
    for (uint32_t i = 0; i < temp_len; i++) {
      ephemeral_point.x.t.buffer[SHA256_DIGEST_SIZE - 1 - i] =
          ephemeral_point.x.t.buffer[SHA256_DIGEST_SIZE - 1 - i - diff];
    }
    for (uint32_t i = 0; i < diff; i++) {
      ephemeral_point.x.t.buffer[i] = 0;
    }
  }

  ephemeral_point.x.t.size = SHA256_DIGEST_SIZE;

  temp_len = SHA256_DIGEST_SIZE;
  res = TEE_GetObjectBufferAttribute(key, TEE_ATTR_ECC_PUBLIC_VALUE_Y,
                                     ephemeral_point.y.t.buffer, &temp_len);
  if (res != TEE_SUCCESS) {
    EMSG("TEE_GetObjectBufferAttribute failed with code 0x%x", res);
    goto cleanup_key;
  } else if (temp_len > SHA256_DIGEST_SIZE) {
    EMSG("Unsupported ephemeral_point_y length %u", temp_len);
    res = TEE_ERROR_NOT_SUPPORTED;
    goto cleanup_key;
  } else if (temp_len < SHA256_DIGEST_SIZE) {
    uint32_t diff = SHA256_DIGEST_SIZE - temp_len;
    for (uint32_t i = 0; i < temp_len; i++) {
      ephemeral_point.y.t.buffer[SHA256_DIGEST_SIZE - 1 - i] =
          ephemeral_point.y.t.buffer[SHA256_DIGEST_SIZE - 1 - i - diff];
    }
    for (uint32_t i = 0; i < diff; i++) {
      ephemeral_point.y.t.buffer[i] = 0;
    }
  }

  ephemeral_point.y.t.size = SHA256_DIGEST_SIZE;
  memcpy(party_u_info, ephemeral_point.x.t.buffer, SHA256_DIGEST_SIZE);

  uint8_t encrypted_salt[SALT_BUFFER_SIZE];
  int32_t encrypted_salt_len;
  uint8_t* encrypted_salt_ptr;

  encrypted_salt_ptr = encrypted_salt;

  encrypted_salt_len = SALT_BUFFER_SIZE;
  temp_len = TPMS_ECC_POINT_Marshal(&ephemeral_point, &encrypted_salt_ptr,
                                    &encrypted_salt_len);
  if (temp_len != SALT_BUFFER_SIZE) {
    EMSG("Unsupported encrypted_salt length %u", encrypted_salt_len);
    res = TEE_ERROR_NOT_SUPPORTED;
    goto cleanup_key;
  }

  memcpy(encrypted_secret->t.secret, encrypted_salt, temp_len);
  encrypted_secret->t.size = temp_len;

  TEE_OperationHandle op = TEE_HANDLE_NULL;
  res = TEE_AllocateOperation(&op, TEE_ALG_ECDH_P256, TEE_MODE_DERIVE,
                              KEY_MAX_BITS);
  if (res != TEE_SUCCESS) {
    EMSG("TEE_AllocateOperation failed with code 0x%x", res);
    goto cleanup_key;
  }

  res = TEE_SetOperationKey(op, key);
  if (res != TEE_SUCCESS) {
    EMSG("TEE_SetOperationKey failed with code 0x%x", res);
    goto cleanup_op_and_key;
  }

  // Free the previous key.
  TEE_FreeTransientObject(key);

  TEE_Attribute pubkey_attr[2];

  TEE_InitRefAttribute(&pubkey_attr[0], TEE_ATTR_ECC_PUBLIC_VALUE_X,
                       pub.t.publicArea.unique.ecc.x.t.buffer,
                       pub.t.publicArea.unique.ecc.x.t.size);

  TEE_InitRefAttribute(&pubkey_attr[1], TEE_ATTR_ECC_PUBLIC_VALUE_Y,
                       pub.t.publicArea.unique.ecc.y.t.buffer,
                       pub.t.publicArea.unique.ecc.y.t.size);

  res =
      TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET, KEY_MAX_BITS, &key);
  if (res != TEE_SUCCESS) {
    EMSG("TEE_AllocateTransientObject failed with code 0x%x", res);
    goto cleanup_op;
  }

  TEE_DeriveKey(op, pubkey_attr, 2, key);

  temp_len = SHA256_DIGEST_SIZE;
  res = TEE_GetObjectBufferAttribute(key, TEE_ATTR_SECRET_VALUE, z_value,
                                     &temp_len);
  if (res != TEE_SUCCESS) {
    EMSG("TEE_GetObjectBufferAttribute failed with code 0x%x", res);
    goto cleanup_op_and_key;
  } else if (temp_len > SHA256_DIGEST_SIZE) {
    EMSG("Unsupported z_value length %u", temp_len);
    res = TEE_ERROR_NOT_SUPPORTED;
    goto cleanup_op_and_key;
  } else if (temp_len < SHA256_DIGEST_SIZE) {
    uint32_t diff = SHA256_DIGEST_SIZE - temp_len;
    for (uint32_t i = 0; i < temp_len; i++) {
      z_value[SHA256_DIGEST_SIZE - 1 - i] =
          z_value[SHA256_DIGEST_SIZE - 1 - i - diff];
    }
    for (uint32_t i = 0; i < diff; i++) {
      z_value[i] = 0;
    }
  }

  // Free the previous op.
  TEE_FreeOperation(op);

  res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
  if (res != TEE_SUCCESS) {
    EMSG("TEE_AllocateOperation failed with code 0x%x", res);
    goto cleanup_key;
  }

  // Big-Endian 32-bit 1.
  uint8_t marshaled_counter[4] = {0, 0, 0, 1};

  TEE_DigestUpdate(op, marshaled_counter, 4);
  TEE_DigestUpdate(op, z_value, SHA256_DIGEST_SIZE);
  // The label constant for RSAES-OAEP and ECDH session secret generation,
  // defined in the TPM 2.0 specs, Part 1, Annex B.10.2 and C.6.2.
  TEE_DigestUpdate(op, "SECRET", 7);
  TEE_DigestUpdate(op, party_u_info, SHA256_DIGEST_SIZE);

  temp_len = SHA256_DIGEST_SIZE;
  res =
      TEE_DigestDoFinal(op, party_v_info, SHA256_DIGEST_SIZE, salt, &temp_len);

  if (res != TEE_SUCCESS) {
    EMSG("TEE_DigestDoFinal failed with code 0x%x", res);
    goto cleanup_op_and_key;
  } else if (temp_len != SHA256_DIGEST_SIZE) {
    EMSG("Unsupported seed length %u", temp_len);
    res = TEE_ERROR_NOT_SUPPORTED;
    goto cleanup_op_and_key;
  }

  res = TEE_SUCCESS;

cleanup_op_and_key:
  TEE_FreeOperation(op);

cleanup_key:
  TEE_FreeTransientObject(key);

  return res;

cleanup_op:
  TEE_FreeOperation(op);

  return res;
}

TEE_Result OpenHwsecSession(TpmSession* session) {
  TEE_Result res = TEE_ERROR_GENERIC;
  TPM_RC tpm_rc;

  uint8_t salt[SHA256_DIGEST_SIZE];
  TPM2B_ENCRYPTED_SECRET encrypted_secret;

  res = GenerateSalt(salt, &encrypted_secret);
  if (res != TEE_SUCCESS) {
    EMSG("GenerateSalt failed with code 0x%x", res);
    return res;
  }

  session->nonce_caller.t.size = SHA1_DIGEST_SIZE;
  TEE_GenerateRandom(session->nonce_caller.t.buffer,
                     session->nonce_caller.t.size);

  uint8_t* cmd_ptr = buffer;
  int32_t remaining = HWSEC_COMMAND_MAX_LEN;

  UINT32 command_size = 0;

  TPMI_ST_COMMAND_TAG tag = TPM_ST_NO_SESSIONS;
  TPM_CC cc = TPM_CC_StartAuthSession;
  TPMI_DH_OBJECT tpm_key = TPM_AUTH_KEY_INDEX;
  TPMI_DH_ENTITY bind = TPM_RH_NULL;
  TPM_SE session_type = TPM_SE_HMAC;
  TPMT_SYM_DEF symmetric = {
      .algorithm = TPM_ALG_NULL,
  };
  TPMI_ALG_HASH auth_hash = TPM_ALG_SHA256;

  command_size += TPMI_ST_COMMAND_TAG_Marshal(&tag, &cmd_ptr, &remaining);
  command_size += UINT32_Marshal(&command_size, &cmd_ptr, &remaining);
  command_size += TPM_CC_Marshal(&cc, &cmd_ptr, &remaining);
  command_size += TPM_HANDLE_Marshal(&tpm_key, &cmd_ptr, &remaining);
  command_size += TPM_HANDLE_Marshal(&bind, &cmd_ptr, &remaining);
  command_size +=
      TPM2B_NONCE_Marshal(&session->nonce_caller, &cmd_ptr, &remaining);
  command_size +=
      TPM2B_ENCRYPTED_SECRET_Marshal(&encrypted_secret, &cmd_ptr, &remaining);
  command_size += UINT8_Marshal(&session_type, &cmd_ptr, &remaining);
  command_size += TPMT_SYM_DEF_Marshal(&symmetric, &cmd_ptr, &remaining);
  command_size += TPMI_ALG_HASH_Marshal(&auth_hash, &cmd_ptr, &remaining);

  // Fix the command size.
  cmd_ptr = buffer + 2;
  remaining = HWSEC_COMMAND_MAX_LEN - 2;
  UINT32_Marshal(&command_size, &cmd_ptr, &remaining);

  size_t data_out = HWSEC_COMMAND_MAX_LEN;
  res = SendHwsecRawCommand(buffer, HWSEC_COMMAND_MAX_LEN, &data_out);
  if (res != TEE_SUCCESS) {
    EMSG("Start session failed with code 0x%x", res);
    return res;
  }

  remaining = data_out;
  cmd_ptr = buffer;

  tpm_rc = TPMI_ST_COMMAND_TAG_Unmarshal(&tag, &cmd_ptr, &remaining);
  if (tpm_rc != TPM_RC_SUCCESS) {
    EMSG("TPMI_ST_COMMAND_TAG_Unmarshal failed with code 0x%x", tpm_rc);
    return TEE_ERROR_BAD_FORMAT;
  } else if (tag != TPM_ST_NO_SESSIONS) {
    EMSG("Unknown tag");
    return TEE_ERROR_CORRUPT_OBJECT;
  }

  tpm_rc = UINT32_Unmarshal(&command_size, &cmd_ptr, &remaining);
  if (tpm_rc != TPM_RC_SUCCESS) {
    EMSG("UINT32_Unmarshal failed with code 0x%x", tpm_rc);
    return TEE_ERROR_BAD_FORMAT;
  } else if (command_size != data_out) {
    EMSG("Command output mismatch");
    return TEE_ERROR_CORRUPT_OBJECT;
  }

  tpm_rc = UINT32_Unmarshal(&cc, &cmd_ptr, &remaining);
  if (tpm_rc != TPM_RC_SUCCESS) {
    EMSG("UINT32_Unmarshal failed with code 0x%x", tpm_rc);
    return TEE_ERROR_BAD_FORMAT;
  } else if (cc != TPM_RC_SUCCESS) {
    EMSG("Start auth session failed with code 0x%x", cc);
    return TEE_ERROR_BAD_STATE;
  }

  tpm_rc = TPM_HANDLE_Unmarshal(&session->session_handle, &cmd_ptr, &remaining);
  if (tpm_rc != TPM_RC_SUCCESS) {
    EMSG("TPM_HANDLE_Unmarshal failed with code 0x%x", tpm_rc);
    return TEE_ERROR_BAD_FORMAT;
  }

  tpm_rc = TPM2B_NONCE_Unmarshal(&session->nonce_tpm, &cmd_ptr, &remaining);
  if (tpm_rc != TPM_RC_SUCCESS) {
    EMSG("TPM2B_NONCE_Unmarshal failed with code 0x%x", tpm_rc);
    return TEE_ERROR_BAD_FORMAT;
  }

  if (remaining != 0) {
    EMSG("Remaining unknown data in start session response");
    return TEE_ERROR_CORRUPT_OBJECT;
  }

  TEE_OperationHandle op = TEE_HANDLE_NULL;

  res = InitHmacSha256Operation(&op, salt, SHA256_DIGEST_SIZE);
  if (res != TEE_SUCCESS) {
    EMSG("InitHmacSha256Operation failed with code 0x%x", res);
    return res;
  }

  // Big-Endian 32-bit 1.
  uint8_t marshaled_counter[4] = {0, 0, 0, 1};

  // Big-Endian 32-bit 256.
  uint8_t digest_size_bits[4] = {0, 0, 1, 0};

  TEE_MACUpdate(op, marshaled_counter, 4);
  // The label constant for session key creation,
  // defined in the TPM 2.0 specs, Part 1, Annex 19.6.8.
  TEE_MACUpdate(op, "ATH", 4);
  TEE_MACUpdate(op, session->nonce_tpm.t.buffer, session->nonce_tpm.t.size);
  TEE_MACUpdate(op, session->nonce_caller.t.buffer,
                session->nonce_caller.t.size);

  uint32_t temp_len = SHA256_DIGEST_SIZE;
  res = TEE_MACComputeFinal(op, digest_size_bits, 4, session->session_key,
                            &temp_len);

  if (res != TEE_SUCCESS) {
    EMSG("TEE_MACComputeFinal failed with code 0x%x", res);
    goto cleanup_op;
  } else if (temp_len != SHA256_DIGEST_SIZE) {
    EMSG("Unsupported session_key length %u", temp_len);
    res = TEE_ERROR_NOT_SUPPORTED;
    goto cleanup_op;
  }

  res = TEE_SUCCESS;

cleanup_op:
  TEE_FreeOperation(op);

  return res;
}

TEE_Result CloseHwsecSession(TpmSession* session) {
  TEE_Result res = TEE_ERROR_GENERIC;

  uint8_t* cmd_ptr = buffer;
  int32_t remaining = HWSEC_COMMAND_MAX_LEN;

  UINT32 command_size = 0;

  TPMI_ST_COMMAND_TAG tag = TPM_ST_NO_SESSIONS;
  TPM_CC cc = TPM_CC_FlushContext;
  TPMI_DH_CONTEXT tpm_key = session->session_handle;

  command_size += TPMI_ST_COMMAND_TAG_Marshal(&tag, &cmd_ptr, &remaining);
  command_size += UINT32_Marshal(&command_size, &cmd_ptr, &remaining);
  command_size += TPM_CC_Marshal(&cc, &cmd_ptr, &remaining);
  command_size += TPM_HANDLE_Marshal(&tpm_key, &cmd_ptr, &remaining);

  // Fix the command size.
  cmd_ptr = buffer + 2;
  remaining = HWSEC_COMMAND_MAX_LEN - 2;
  UINT32_Marshal(&command_size, &cmd_ptr, &remaining);

  size_t data_out = HWSEC_COMMAND_MAX_LEN;
  res = SendHwsecRawCommand(buffer, HWSEC_COMMAND_MAX_LEN, &data_out);
  if (res != TEE_SUCCESS) {
    EMSG("Close session failed with code 0x%x", res);
    return res;
  }

  return TEE_SUCCESS;
}

TEE_Result GetCommandAuthorization(TpmSession* session,
                                   uint8_t command_hash[SHA256_DIGEST_SIZE],
                                   TPMS_AUTH_COMMAND* auth) {
  TEE_Result res = TEE_ERROR_GENERIC;

  auth->sessionHandle = session->session_handle;

  TPMA_SESSION session_attrs = {.continueSession = 1};
  auth->sessionAttributes = session_attrs;

  session->nonce_caller.t.size = SHA1_DIGEST_SIZE;
  TEE_GenerateRandom(session->nonce_caller.t.buffer,
                     session->nonce_caller.t.size);

  memcpy(&auth->nonce, &session->nonce_caller, sizeof(TPM2B_NONCE));

  TEE_OperationHandle op = TEE_HANDLE_NULL;

  res = InitHmacSha256Operation(&op, session->session_key, SHA256_DIGEST_SIZE);
  if (res != TEE_SUCCESS) {
    EMSG("InitHmacSha256Operation failed with code 0x%x", res);
    return res;
  }

  TEE_MACUpdate(op, command_hash, SHA256_DIGEST_SIZE);
  TEE_MACUpdate(op, session->nonce_caller.t.buffer,
                session->nonce_caller.t.size);
  TEE_MACUpdate(op, session->nonce_tpm.t.buffer, session->nonce_tpm.t.size);

  uint32_t temp_len = SHA256_DIGEST_SIZE;
  res = TEE_MACComputeFinal(op, &auth->sessionAttributes, 1,
                            auth->hmac.t.buffer, &temp_len);

  if (res != TEE_SUCCESS) {
    EMSG("TEE_MACComputeFinal failed with code 0x%x", res);
    goto cleanup_op;
  } else if (temp_len != SHA256_DIGEST_SIZE) {
    EMSG("Unsupported session_key length %u", temp_len);
    res = TEE_ERROR_NOT_SUPPORTED;
    goto cleanup_op;
  }

  auth->hmac.t.size = SHA256_DIGEST_SIZE;

  res = TEE_SUCCESS;

cleanup_op:
  TEE_FreeOperation(op);

  return res;
}

TEE_Result CheckResponseAuthorization(TpmSession* session,
                                      uint8_t response_hash[SHA256_DIGEST_SIZE],
                                      TPMS_AUTH_RESPONSE* auth) {
  TEE_Result res = TEE_ERROR_GENERIC;

  if (auth->hmac.t.size != SHA256_DIGEST_SIZE) {
    EMSG("Unsupported hmac length %u", auth->hmac.t.size);
    return TEE_ERROR_NOT_SUPPORTED;
  }

  if (auth->nonce.t.size < HWSEC_NONCE_MIN_SIZE ||
      auth->nonce.t.size > HWSEC_NONCE_MAX_SIZE) {
    EMSG("Unsupported nonce length %u", auth->nonce.t.size);
    return TEE_ERROR_NOT_SUPPORTED;
  }

  memcpy(session->nonce_tpm.t.buffer, auth->nonce.t.buffer, auth->nonce.t.size);
  session->nonce_tpm.t.size = auth->nonce.t.size;

  uint8_t* buffer_ptr = buffer;
  int32_t remaining = HWSEC_COMMAND_MAX_LEN;
  UINT32 size = 0;

  size +=
      TPMA_SESSION_Marshal(&auth->sessionAttributes, &buffer_ptr, &remaining);

  TEE_OperationHandle op = TEE_HANDLE_NULL;
  res = InitHmacSha256Operation(&op, session->session_key, SHA256_DIGEST_SIZE);
  if (res != TEE_SUCCESS) {
    EMSG("InitHmacSha256Operation failed with code 0x%x", res);
    return res;
  }

  TEE_MACUpdate(op, response_hash, SHA256_DIGEST_SIZE);
  TEE_MACUpdate(op, session->nonce_tpm.t.buffer, session->nonce_tpm.t.size);
  TEE_MACUpdate(op, session->nonce_caller.t.buffer,
                session->nonce_caller.t.size);

  res = TEE_MACCompareFinal(op, buffer, size, auth->hmac.t.buffer,
                            auth->hmac.t.size);
  if (res != TEE_SUCCESS) {
    EMSG("TEE_MACCompareFinal failed with code 0x%x", res);
    goto cleanup_op;
  }

  res = TEE_SUCCESS;

cleanup_op:
  TEE_FreeOperation(op);

  return res;
}
