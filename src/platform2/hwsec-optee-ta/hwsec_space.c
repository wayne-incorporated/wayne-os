// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-optee-ta/hwsec_space.h"

#include <stdint.h>
#include <string.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <tpm2/tpm_generated.h>

#include "hwsec-optee-ta/hwsec_cmd.h"
#include "hwsec-optee-ta/hwsec_session.h"

#define NAME_CACHE_SIZE 2

static uint8_t buffer[HWSEC_COMMAND_MAX_LEN];

typedef struct NameCache {
  TPMI_RH_NV_INDEX index;
  TPM2B_NAME name;
} NameCache;

static NameCache name_caches[NAME_CACHE_SIZE];

static TEE_Result Sha256(uint8_t* buf,
                         uint32_t size,
                         uint8_t digest[SHA256_DIGEST_SIZE]) {
  TEE_Result res = TEE_ERROR_GENERIC;

  TEE_OperationHandle op = TEE_HANDLE_NULL;
  res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);

  if (res != TEE_SUCCESS) {
    EMSG("Create operation failed with code 0x%x", res);
    return res;
  }

  uint32_t temp_len = SHA256_DIGEST_SIZE;

  res = TEE_DigestDoFinal(op, buf, size, digest, &temp_len);

  if (res != TEE_SUCCESS) {
    EMSG("DigestDoFinal failed with code 0x%x", res);
  } else if (temp_len != SHA256_DIGEST_SIZE) {
    EMSG("Unsupported digest length %u", temp_len);
    res = TEE_ERROR_NOT_SUPPORTED;
  }

  TEE_FreeOperation(op);

  return res;
}

static TEE_Result VerifyName(TPM2B_NV_PUBLIC* pub, TPM2B_NAME* name) {
  TEE_Result res = TEE_ERROR_GENERIC;
  TPM_ALG_ID alg = TPM_ALG_SHA256;

  if (pub->t.nvPublic.nameAlg != alg) {
    EMSG("Unsupported name hash algorithm 0x%x", pub->t.nvPublic.nameAlg);
    return TEE_ERROR_NOT_SUPPORTED;
  }

  if (name->t.size != sizeof(TPM_ALG_ID) + SHA256_DIGEST_SIZE) {
    EMSG("Unsupported name length %d", name->t.size);
    return TEE_ERROR_NOT_SUPPORTED;
  }

  uint8_t* buffer_ptr = buffer;
  int32_t remaining = HWSEC_COMMAND_MAX_LEN;
  uint16_t size;

  size = TPM_ALG_ID_Marshal(&alg, &buffer_ptr, &remaining);
  if (size != 2) {
    EMSG("Unsupported ALG_ID length %d", size);
    return TEE_ERROR_NOT_SUPPORTED;
  }

  if (memcmp(buffer, name->b.buffer, sizeof(TPM_ALG_ID)) != 0) {
    EMSG("Name hash algorithm mismatch");
    return TEE_ERROR_SECURITY;
  }

  buffer_ptr = buffer;
  remaining = HWSEC_COMMAND_MAX_LEN;
  size = TPMS_NV_PUBLIC_Marshal(&pub->t.nvPublic, &buffer_ptr, &remaining);

  uint8_t digest[SHA256_DIGEST_SIZE];
  res = Sha256(buffer, size, digest);
  if (res != TEE_SUCCESS) {
    EMSG("Sha256 failed with code 0x%x", res);
    return res;
  }

  if (memcmp(digest, name->b.buffer + sizeof(TPM_ALG_ID), SHA256_DIGEST_SIZE) !=
      0) {
    EMSG("Name hash mismatch");
    return TEE_ERROR_SECURITY;
  }

  return TEE_SUCCESS;
}

static TEE_Result GetVerifiedSpacePublic(TPMI_RH_NV_INDEX index,
                                         TPM2B_NV_PUBLIC* pub,
                                         TPM2B_NAME* name) {
  TEE_Result res = TEE_ERROR_GENERIC;
  TPM_RC tpm_rc;

  uint8_t* cmd_ptr = buffer;
  int32_t remaining = HWSEC_COMMAND_MAX_LEN;

  UINT32 command_size = 0;

  TPMI_ST_COMMAND_TAG tag = TPM_ST_NO_SESSIONS;
  TPM_CC cc = TPM_CC_NV_ReadPublic;

  command_size += TPMI_ST_COMMAND_TAG_Marshal(&tag, &cmd_ptr, &remaining);
  command_size += UINT32_Marshal(&command_size, &cmd_ptr, &remaining);
  command_size += TPM_CC_Marshal(&cc, &cmd_ptr, &remaining);
  command_size += TPM_HANDLE_Marshal(&index, &cmd_ptr, &remaining);

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

  tpm_rc = TPM2B_NV_PUBLIC_Unmarshal(pub, &cmd_ptr, &remaining);
  if (tpm_rc != TPM_RC_SUCCESS) {
    EMSG("TPM2B_NV_PUBLIC_Unmarshal failed with code 0x%x", tpm_rc);
    return TEE_ERROR_BAD_FORMAT;
  }

  tpm_rc = TPM2B_NAME_Unmarshal(name, &cmd_ptr, &remaining);
  if (tpm_rc != TPM_RC_SUCCESS) {
    EMSG("TPM2B_NAME_Unmarshal failed with code 0x%x", tpm_rc);
    return TEE_ERROR_BAD_FORMAT;
  }

  res = VerifyName(pub, name);
  if (res != TEE_SUCCESS) {
    EMSG("VerifyName failed with code 0x%x", res);
    return res;
  }

  if (remaining != 0) {
    EMSG("Remaining unknown data in start session response");
    return TEE_ERROR_CORRUPT_OBJECT;
  }

  return TEE_SUCCESS;
}

static TEE_Result InitNVName(TPMI_RH_NV_INDEX index, TPM2B_NAME* name) {
  TEE_Result res = TEE_ERROR_GENERIC;

  TPM2B_NV_PUBLIC pub;
  res = GetVerifiedSpacePublic(index, &pub, name);
  if (res != TEE_SUCCESS) {
    EMSG("GetVerifiedSpacePublic failed with code 0x%x", res);
    memset(name, 0, sizeof(TPM2B_NAME));
    return res;
  }

  // TODO(yich): Verify the NV attributes.

  return TEE_SUCCESS;
}

static TEE_Result GetVerifiedCounterName(TPMI_RH_NV_INDEX index,
                                         TPM2B_NAME* name) {
  TEE_Result res = TEE_ERROR_GENERIC;

  for (int i = 0; i < NAME_CACHE_SIZE; i++) {
    if (name_caches[i].name.t.size != 0 && name_caches[i].index == index) {
      memcpy(name, &name_caches[i].name, sizeof(TPM2B_NAME));
      return TEE_SUCCESS;
    }
  }

  for (int i = 1; i < NAME_CACHE_SIZE; i++) {
    memcpy(&name_caches[i], &name_caches[i - 1], sizeof(NameCache));
  }

  name_caches[0].index = index;
  res = InitNVName(index, &name_caches[0].name);
  if (res != TEE_SUCCESS) {
    EMSG("InitNVName failed with code 0x%x", res);
    return res;
  }

  memcpy(name, &name_caches[0].name, sizeof(TPM2B_NAME));
  return TEE_SUCCESS;
}

TEE_Result GetVerifiedCounterData(TpmSession* session,
                                  TPMI_RH_NV_INDEX index,
                                  UINT16 nv_size,
                                  TPM2B_MAX_NV_BUFFER* data) {
  TEE_Result res = TEE_ERROR_GENERIC;
  TPM_RC tpm_rc;

  TPM2B_NAME name;
  res = GetVerifiedCounterName(index, &name);
  if (res != TEE_SUCCESS) {
    EMSG("GetVerifiedCounterName failed with code 0x%x", res);
    return res;
  }

  uint8_t* buffer_ptr = buffer;
  int32_t remaining = HWSEC_COMMAND_MAX_LEN;

  UINT32 buffer_size = 0;

  TPMI_ST_COMMAND_TAG tag = TPM_ST_SESSIONS;
  TPM_CC cc = TPM_CC_NV_Read;
  TPMI_RH_NV_AUTH auth_handle = index;
  TPMI_RH_NV_INDEX nv_index = index;
  UINT16 size = nv_size;
  UINT16 offset = 0;

  buffer_size += TPM_CC_Marshal(&cc, &buffer_ptr, &remaining);
  for (int i = 0; i < name.t.size; i++) {
    buffer_size += BYTE_Marshal(&name.t.name[i], &buffer_ptr, &remaining);
  }
  for (int i = 0; i < name.t.size; i++) {
    buffer_size += BYTE_Marshal(&name.t.name[i], &buffer_ptr, &remaining);
  }
  buffer_size += UINT16_Marshal(&size, &buffer_ptr, &remaining);
  buffer_size += UINT16_Marshal(&offset, &buffer_ptr, &remaining);

  uint8_t digest[SHA256_DIGEST_SIZE];
  res = Sha256(buffer, buffer_size, digest);
  if (res != TEE_SUCCESS) {
    EMSG("Sha256 failed with code 0x%x", res);
    return res;
  }

  buffer_size = 0;
  buffer_ptr = buffer;
  remaining = HWSEC_COMMAND_MAX_LEN;

  buffer_size += TPMI_ST_COMMAND_TAG_Marshal(&tag, &buffer_ptr, &remaining);
  buffer_size += UINT32_Marshal(&buffer_size, &buffer_ptr, &remaining);
  buffer_size += TPM_CC_Marshal(&cc, &buffer_ptr, &remaining);
  buffer_size += TPM_HANDLE_Marshal(&auth_handle, &buffer_ptr, &remaining);
  buffer_size += TPM_HANDLE_Marshal(&nv_index, &buffer_ptr, &remaining);

  TPMS_AUTH_COMMAND auth;
  res = GetCommandAuthorization(session, digest, &auth);
  if (res != TEE_SUCCESS) {
    EMSG("GetCommandAuthorization failed with code 0x%x", res);
    return res;
  }

  uint8_t* auth_cmd_ptr = buffer_ptr + sizeof(UINT32);
  int32_t auth_cmd_remaining = remaining - sizeof(UINT32);
  UINT32 auth_cmd_size =
      TPMS_AUTH_COMMAND_Marshal(&auth, &auth_cmd_ptr, &auth_cmd_remaining);

  buffer_size += UINT32_Marshal(&auth_cmd_size, &buffer_ptr, &remaining);

  buffer_size += auth_cmd_size;
  buffer_ptr = auth_cmd_ptr;
  remaining = auth_cmd_remaining;

  buffer_size += UINT16_Marshal(&size, &buffer_ptr, &remaining);
  buffer_size += UINT16_Marshal(&offset, &buffer_ptr, &remaining);

  // Fix the command size.
  buffer_ptr = buffer + 2;
  remaining = HWSEC_COMMAND_MAX_LEN - 2;
  UINT32_Marshal(&buffer_size, &buffer_ptr, &remaining);

  size_t data_out = HWSEC_COMMAND_MAX_LEN;
  res = SendHwsecRawCommand(buffer, HWSEC_COMMAND_MAX_LEN, &data_out);
  if (res) {
    EMSG("Read NV failed with code 0x%x", res);
    return res;
  }

  remaining = data_out;
  buffer_ptr = buffer;

  tpm_rc = TPMI_ST_COMMAND_TAG_Unmarshal(&tag, &buffer_ptr, &remaining);
  if (tpm_rc != TPM_RC_SUCCESS) {
    EMSG("TPMI_ST_COMMAND_TAG_Unmarshal failed with code 0x%x", tpm_rc);
    return TEE_ERROR_BAD_FORMAT;
  } else if (tag != TPM_ST_SESSIONS) {
    EMSG("Unknown tag");
    return TEE_ERROR_CORRUPT_OBJECT;
  }

  tpm_rc = UINT32_Unmarshal(&buffer_size, &buffer_ptr, &remaining);
  if (tpm_rc != TPM_RC_SUCCESS) {
    EMSG("UINT32_Unmarshal failed with code 0x%x", tpm_rc);
    return TEE_ERROR_BAD_FORMAT;
  } else if (buffer_size != data_out) {
    EMSG("Command output mismatch");
    return TEE_ERROR_CORRUPT_OBJECT;
  }

  TPM_RC rc;
  tpm_rc = UINT32_Unmarshal(&rc, &buffer_ptr, &remaining);
  if (tpm_rc != TPM_RC_SUCCESS) {
    EMSG("UINT32_Unmarshal failed with code 0x%x", tpm_rc);
    return TEE_ERROR_BAD_FORMAT;
  } else if (rc != TPM_RC_SUCCESS) {
    EMSG("Read NV failed with code 0x%x", rc);
    return TEE_ERROR_BAD_STATE;
  }

  UINT32 parameter_size;
  tpm_rc = UINT32_Unmarshal(&parameter_size, &buffer_ptr, &remaining);
  if (tpm_rc != TPM_RC_SUCCESS) {
    EMSG("UINT32_Unmarshal failed with code 0x%x", tpm_rc);
    return TEE_ERROR_BAD_FORMAT;
  } else if ((int32_t)parameter_size > remaining) {
    EMSG("Parameter size(%d) is larger than remaining data(%d)", parameter_size,
         remaining);
    return TEE_ERROR_CORRUPT_OBJECT;
  }

  uint8_t* parameter_ptr = buffer_ptr;
  int32_t parameter_remaining = parameter_size;

  tpm_rc =
      TPM2B_MAX_NV_BUFFER_Unmarshal(data, &parameter_ptr, &parameter_remaining);
  if (tpm_rc != TPM_RC_SUCCESS) {
    EMSG("TPM2B_MAX_NV_BUFFER_Unmarshal failed with code 0x%x", tpm_rc);
    res = TEE_ERROR_BAD_FORMAT;
    goto cleanup_data;
  } else if (parameter_remaining != 0) {
    EMSG("Unknown remain parameter(%d)", parameter_remaining);
    res = TEE_ERROR_CORRUPT_OBJECT;
    goto cleanup_data;
  }

  // Use the same buffer, because we will not overlap the computation sections.
  auth_cmd_ptr = buffer_ptr + parameter_size;
  auth_cmd_size = remaining - parameter_size;
  auth_cmd_remaining = auth_cmd_size;

  buffer_size = 0;
  buffer_ptr = buffer;
  remaining = auth_cmd_ptr - buffer;

  buffer_size += UINT32_Marshal(&rc, &buffer_ptr, &remaining);
  buffer_size += UINT32_Marshal(&cc, &buffer_ptr, &remaining);
  buffer_size += TPM2B_MAX_NV_BUFFER_Marshal(data, &buffer_ptr, &remaining);

  res = Sha256(buffer, buffer_size, digest);
  if (res != TEE_SUCCESS) {
    EMSG("Sha256 failed with code 0x%x", res);
    goto cleanup_data;
  }

  TPMS_AUTH_RESPONSE auth_res;
  tpm_rc = TPMS_AUTH_RESPONSE_Unmarshal(&auth_res, &auth_cmd_ptr,
                                        &auth_cmd_remaining);
  if (tpm_rc != TPM_RC_SUCCESS) {
    EMSG("TPMS_AUTH_RESPONSE_Unmarshal failed with code 0x%x", tpm_rc);
    res = TEE_ERROR_BAD_FORMAT;
    goto cleanup_data;
  } else if (auth_cmd_remaining != 0) {
    EMSG("Unknown remain auth response(%d)", auth_cmd_remaining);
    res = TEE_ERROR_CORRUPT_OBJECT;
    goto cleanup_data;
  }

  res = CheckResponseAuthorization(session, digest, &auth_res);
  if (res != TEE_SUCCESS) {
    EMSG("CheckResponseAuthorization failed with code 0x%x", res);
    goto cleanup_data;
  }

  return TEE_SUCCESS;

cleanup_data:
  memset(data, 0, sizeof(TPM2B_MAX_NV_BUFFER));

  return res;
}

TEE_Result IncreaseVerifiedCounter(TpmSession* session,
                                   TPMI_RH_NV_INDEX index) {
  TEE_Result res = TEE_ERROR_GENERIC;
  TPM_RC tpm_rc;

  TPM2B_NAME name;
  res = GetVerifiedCounterName(index, &name);
  if (res != TEE_SUCCESS) {
    EMSG("GetVerifiedCounterName failed with code 0x%x", res);
    return res;
  }

  uint8_t* buffer_ptr = buffer;
  int32_t remaining = HWSEC_COMMAND_MAX_LEN;

  UINT32 buffer_size = 0;

  TPMI_ST_COMMAND_TAG tag = TPM_ST_SESSIONS;
  TPM_CC cc = TPM_CC_NV_Increment;
  TPMI_RH_NV_AUTH auth_handle = index;
  TPMI_RH_NV_INDEX nv_index = index;

  buffer_size += TPM_CC_Marshal(&cc, &buffer_ptr, &remaining);
  for (int i = 0; i < name.t.size; i++) {
    buffer_size += BYTE_Marshal(&name.t.name[i], &buffer_ptr, &remaining);
  }
  for (int i = 0; i < name.t.size; i++) {
    buffer_size += BYTE_Marshal(&name.t.name[i], &buffer_ptr, &remaining);
  }

  uint8_t digest[SHA256_DIGEST_SIZE];
  res = Sha256(buffer, buffer_size, digest);
  if (res != TEE_SUCCESS) {
    EMSG("Sha256 failed with code 0x%x", res);
    return res;
  }

  buffer_size = 0;
  buffer_ptr = buffer;
  remaining = HWSEC_COMMAND_MAX_LEN;

  buffer_size += TPMI_ST_COMMAND_TAG_Marshal(&tag, &buffer_ptr, &remaining);
  buffer_size += UINT32_Marshal(&buffer_size, &buffer_ptr, &remaining);
  buffer_size += TPM_CC_Marshal(&cc, &buffer_ptr, &remaining);
  buffer_size += TPM_HANDLE_Marshal(&auth_handle, &buffer_ptr, &remaining);
  buffer_size += TPM_HANDLE_Marshal(&nv_index, &buffer_ptr, &remaining);

  TPMS_AUTH_COMMAND auth;
  res = GetCommandAuthorization(session, digest, &auth);
  if (res != TEE_SUCCESS) {
    EMSG("GetCommandAuthorization failed with code 0x%x", res);
    return res;
  }

  uint8_t* auth_cmd_ptr = buffer_ptr + sizeof(UINT32);
  int32_t auth_cmd_remaining = remaining - sizeof(UINT32);
  UINT32 auth_cmd_size =
      TPMS_AUTH_COMMAND_Marshal(&auth, &auth_cmd_ptr, &auth_cmd_remaining);

  buffer_size += UINT32_Marshal(&auth_cmd_size, &buffer_ptr, &remaining);

  buffer_size += auth_cmd_size;
  buffer_ptr = auth_cmd_ptr;
  remaining = auth_cmd_remaining;

  // Fix the command size.
  buffer_ptr = buffer + 2;
  remaining = HWSEC_COMMAND_MAX_LEN - 2;
  UINT32_Marshal(&buffer_size, &buffer_ptr, &remaining);

  size_t data_out = HWSEC_COMMAND_MAX_LEN;
  res = SendHwsecRawCommand(buffer, HWSEC_COMMAND_MAX_LEN, &data_out);
  if (res) {
    EMSG("Increase NV failed with code 0x%x", res);
    return res;
  }

  remaining = data_out;
  buffer_ptr = buffer;

  tpm_rc = TPMI_ST_COMMAND_TAG_Unmarshal(&tag, &buffer_ptr, &remaining);
  if (tpm_rc != TPM_RC_SUCCESS) {
    EMSG("TPMI_ST_COMMAND_TAG_Unmarshal failed with code 0x%x", tpm_rc);
    return TEE_ERROR_BAD_FORMAT;
  } else if (tag != TPM_ST_SESSIONS) {
    EMSG("Unknown tag");
    return TEE_ERROR_CORRUPT_OBJECT;
  }

  tpm_rc = UINT32_Unmarshal(&buffer_size, &buffer_ptr, &remaining);
  if (tpm_rc != TPM_RC_SUCCESS) {
    EMSG("UINT32_Unmarshal failed with code 0x%x", tpm_rc);
    return TEE_ERROR_BAD_FORMAT;
  } else if (buffer_size != data_out) {
    EMSG("Command output mismatch");
    return TEE_ERROR_CORRUPT_OBJECT;
  }

  TPM_RC rc;
  tpm_rc = UINT32_Unmarshal(&rc, &buffer_ptr, &remaining);
  if (tpm_rc != TPM_RC_SUCCESS) {
    EMSG("UINT32_Unmarshal failed with code 0x%x", tpm_rc);
    return TEE_ERROR_BAD_FORMAT;
  } else if (rc != TPM_RC_SUCCESS) {
    EMSG("Read NV failed with code 0x%x", rc);
    return TEE_ERROR_BAD_STATE;
  }

  UINT32 parameter_size;
  tpm_rc = UINT32_Unmarshal(&parameter_size, &buffer_ptr, &remaining);
  if (tpm_rc != TPM_RC_SUCCESS) {
    EMSG("UINT32_Unmarshal failed with code 0x%x", tpm_rc);
    return TEE_ERROR_BAD_FORMAT;
  } else if ((int32_t)parameter_size > remaining) {
    EMSG("Parameter size(%d) is larger than remaining data(%d)", parameter_size,
         remaining);
    return TEE_ERROR_CORRUPT_OBJECT;
  }

  if (parameter_size != 0) {
    EMSG("Unknown parameter size(%d)", parameter_size);
    return TEE_ERROR_CORRUPT_OBJECT;
  }

  // Use the same buffer, because we will no overlap the computation sections.
  auth_cmd_ptr = buffer_ptr + parameter_size;
  auth_cmd_size = remaining - parameter_size;
  auth_cmd_remaining = auth_cmd_size;

  buffer_size = 0;
  buffer_ptr = buffer;
  remaining = auth_cmd_ptr - buffer;

  buffer_size += UINT32_Marshal(&rc, &buffer_ptr, &remaining);
  buffer_size += UINT32_Marshal(&cc, &buffer_ptr, &remaining);

  res = Sha256(buffer, buffer_size, digest);
  if (res != TEE_SUCCESS) {
    EMSG("Sha256 failed with code 0x%x", res);
    return res;
  }

  TPMS_AUTH_RESPONSE auth_res;
  tpm_rc = TPMS_AUTH_RESPONSE_Unmarshal(&auth_res, &auth_cmd_ptr,
                                        &auth_cmd_remaining);
  if (tpm_rc != TPM_RC_SUCCESS) {
    EMSG("TPMS_AUTH_RESPONSE_Unmarshal failed with code 0x%x", tpm_rc);
    return TEE_ERROR_BAD_FORMAT;
  } else if (auth_cmd_remaining != 0) {
    EMSG("Unknown remain auth response(%d)", auth_cmd_remaining);
    return TEE_ERROR_CORRUPT_OBJECT;
  }

  res = CheckResponseAuthorization(session, digest, &auth_res);
  if (res != TEE_SUCCESS) {
    EMSG("CheckResponseAuthorization failed with code 0x%x", res);
    return res;
  }

  return TEE_SUCCESS;
}
