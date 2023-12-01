// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HWSEC_OPTEE_TA_HWSEC_SPACE_H_
#define HWSEC_OPTEE_TA_HWSEC_SPACE_H_

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <tpm2/tpm_generated.h>

#include "hwsec-optee-ta/hwsec_session.h"

TEE_Result GetVerifiedCounterData(TpmSession* session,
                                  TPMI_RH_NV_INDEX index,
                                  UINT16 nv_size,
                                  TPM2B_MAX_NV_BUFFER* data);

TEE_Result IncreaseVerifiedCounter(TpmSession* session, TPMI_RH_NV_INDEX index);

#endif  // HWSEC_OPTEE_TA_HWSEC_SPACE_H_
