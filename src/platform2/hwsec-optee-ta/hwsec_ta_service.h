// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HWSEC_OPTEE_TA_HWSEC_TA_SERVICE_H_
#define HWSEC_OPTEE_TA_HWSEC_TA_SERVICE_H_

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

// Run a simple self test to check the hwsec plugin connection.
// There is no input & output for this function.
TEE_Result HwsecSelfTest(uint32_t param_types,
                         TEE_Param params[TEE_NUM_PARAMS]);

// Read the counter value with a specific index.
// Param 0: index
// Param 1: size, the common size of it is 8 bytes.
// Param 2: out_buffer, the output buffer should not smaller than the size.
TEE_Result HwsecReadCounter(uint32_t param_types,
                            TEE_Param params[TEE_NUM_PARAMS]);

// Increase the counter value with a specific index.
// Param 0: index
TEE_Result HwsecIncreaseCounter(uint32_t param_types,
                                TEE_Param params[TEE_NUM_PARAMS]);

#endif  // HWSEC_OPTEE_TA_HWSEC_TA_SERVICE_H_
