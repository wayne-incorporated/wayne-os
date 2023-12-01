// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-optee-ta/hwsec_ta_service.h"

#include <stdint.h>
#include <string.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <tpm2/tpm_generated.h>

#include "hwsec-optee-ta/hwsec_cmd.h"
#include "hwsec-optee-ta/hwsec_session.h"
#include "hwsec-optee-ta/hwsec_space.h"

TEE_Result HwsecSelfTest(uint32_t param_types,
                         TEE_Param params[TEE_NUM_PARAMS]) {
  uint32_t ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

  if (param_types != ptypes) {
    EMSG("Selftest failed with unsupported param types");
    return TEE_ERROR_NOT_SUPPORTED;
  }

  TEE_Result res = TEE_ERROR_GENERIC;
  uint8_t cmd[12] = "\200\1\0\0\0\v\0\0\1C\0";
  size_t out_len = 0;

  res = SendHwsecRawCommand(cmd, sizeof(cmd), &out_len);
  if (res) {
    EMSG("Selftest failed with code 0x%x", res);
  }

  return res;
}

TEE_Result HwsecReadCounter(uint32_t param_types,
                            TEE_Param params[TEE_NUM_PARAMS]) {
  TEE_Result res = TEE_ERROR_GENERIC;

  // Param 0 = index
  // Param 1 = size
  // Param 2 = out_buffer

  uint32_t ptypes =
      TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_VALUE_INPUT,
                      TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE);

  if (param_types != ptypes) {
    EMSG("ReadCounter failed with unsupported param types");
    return TEE_ERROR_NOT_SUPPORTED;
  }

  if (params[1].value.a > params[2].memref.size) {
    EMSG("Output buffer is not large enough");
    return TEE_ERROR_SHORT_BUFFER;
  }

  TpmSession session;

  res = OpenHwsecSession(&session);
  if (res != TEE_SUCCESS) {
    EMSG("OpenHwsecSession failed with code 0x%x", res);
    goto cleanup_session;
  }

  TPM2B_MAX_NV_BUFFER data;
  res = GetVerifiedCounterData(&session, params[0].value.a, params[1].value.a,
                               &data);
  if (res != TEE_SUCCESS) {
    EMSG("GetVerifiedCounterData failed with code 0x%x", res);
    goto cleanup_session;
  }

  if (data.t.size > params[1].value.a) {
    EMSG("GetVerifiedCounterData result is too large");
    res = TEE_ERROR_SHORT_BUFFER;
    goto cleanup_session;
  }

  params[2].memref.size = data.t.size;
  memcpy(params[2].memref.buffer, data.t.buffer, data.t.size);

  res = TEE_SUCCESS;

cleanup_session:
  if (CloseHwsecSession(&session) != TEE_SUCCESS) {
    EMSG("CloseHwsecSession failed");
  }

  return res;
}

TEE_Result HwsecIncreaseCounter(uint32_t param_types,
                                TEE_Param params[TEE_NUM_PARAMS]) {
  TEE_Result res = TEE_ERROR_GENERIC;

  // Param 0 = index

  uint32_t ptypes =
      TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

  if (param_types != ptypes) {
    EMSG("ReadCounter failed with unsupported param types");
    return TEE_ERROR_NOT_SUPPORTED;
  }

  TpmSession session;

  res = OpenHwsecSession(&session);
  if (res != TEE_SUCCESS) {
    EMSG("OpenHwsecSession failed with code 0x%x", res);
    goto cleanup_session;
  }

  res = IncreaseVerifiedCounter(&session, params[0].value.a);
  if (res != TEE_SUCCESS) {
    EMSG("IncreaseVerifiedCounter failed with code 0x%x", res);
    goto cleanup_session;
  }

  res = TEE_SUCCESS;

cleanup_session:
  if (CloseHwsecSession(&session) != TEE_SUCCESS) {
    EMSG("CloseHwsecSession failed");
  }

  return res;
}
