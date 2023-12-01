// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-optee-ta/hwsec_ta.h"

#include <stdint.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "hwsec-optee-ta/hwsec_ta_service.h"

#define SELF_TEST_CMD 0
#define READ_COUNTER_CMD 1
#define INCREASE_COUNTER_CMD 2

TEE_Result TA_CreateEntryPoint(void) {
  return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                    TEE_Param params[TEE_NUM_PARAMS],
                                    void** sess_ctx) {
  return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void* sess_ctx) {}

TEE_Result TA_InvokeCommandEntryPoint(void* sess_ctx,
                                      uint32_t cmd_id,
                                      uint32_t param_types,
                                      TEE_Param params[TEE_NUM_PARAMS]) {
  switch (cmd_id) {
    case SELF_TEST_CMD:
      return HwsecSelfTest(param_types, params);
    case READ_COUNTER_CMD:
      return HwsecReadCounter(param_types, params);
    case INCREASE_COUNTER_CMD:
      return HwsecIncreaseCounter(param_types, params);
    default:
      return TEE_ERROR_BAD_PARAMETERS;
  }
}
