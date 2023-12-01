// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-optee-ta/hwsec_cmd.h"

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#define HWSEC_PLUGIN_UUID                            \
  {                                                  \
    0x69b7c987, 0x4a1a, 0x4953, {                    \
      0xb6, 0x47, 0x0c, 0xf7, 0x9e, 0xb3, 0x97, 0xb9 \
    }                                                \
  }

#define SEND_RAW_COMMAND 0

TEE_Result SendHwsecRawCommand(uint8_t* data,
                               size_t data_len,
                               size_t* out_len) {
  TEE_Result res = TEE_ERROR_GENERIC;
  TEE_UUID hwsec_plugin_uuid = HWSEC_PLUGIN_UUID;

  res = tee_invoke_supp_plugin(&hwsec_plugin_uuid, SEND_RAW_COMMAND, 0, data,
                               data_len, out_len);
  if (res) {
    EMSG("invoke plugin failed with code 0x%x", res);
  }

  return res;
}
