// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HWSEC_OPTEE_TA_HWSEC_CMD_H_
#define HWSEC_OPTEE_TA_HWSEC_CMD_H_

#include <stddef.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#define HWSEC_COMMAND_MAX_LEN 1024

TEE_Result SendHwsecRawCommand(uint8_t* data, size_t data_len, size_t* out_len);

#endif  // HWSEC_OPTEE_TA_HWSEC_CMD_H_
