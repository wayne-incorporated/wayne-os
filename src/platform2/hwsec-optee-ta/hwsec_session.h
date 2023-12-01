// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HWSEC_OPTEE_TA_HWSEC_SESSION_H_
#define HWSEC_OPTEE_TA_HWSEC_SESSION_H_

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <tpm2/tpm_generated.h>

typedef struct TpmSession {
  TPMI_SH_AUTH_SESSION session_handle;
  TPM2B_NONCE nonce_tpm;
  TPM2B_NONCE nonce_caller;
  uint8_t session_key[SHA256_DIGEST_SIZE];
} TpmSession;

TEE_Result OpenHwsecSession(TpmSession* session);
TEE_Result CloseHwsecSession(TpmSession* session);
TEE_Result GetCommandAuthorization(TpmSession* session,
                                   uint8_t command_hash[SHA256_DIGEST_SIZE],
                                   TPMS_AUTH_COMMAND* auth);
TEE_Result CheckResponseAuthorization(TpmSession* session,
                                      uint8_t response_hash[SHA256_DIGEST_SIZE],
                                      TPMS_AUTH_RESPONSE* auth);

#endif  // HWSEC_OPTEE_TA_HWSEC_SESSION_H_
