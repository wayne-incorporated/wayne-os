// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/real_command_parser.h"

#include <string>

#include <base/logging.h>

#include "trunks/tpm_generated.h"

// TODO(b/230343588): Use `TpmStructureParser` to re-implement these methods.
// Cureently the function signatures is intended to be
// `trunks::Parse_XXX()-like, so it takes an in/out `std::string` pointer, but
// that might not be the best decision for the consumers (in particular, vtpm).
// Once we revisit the signatures and we can determine if `TpmStructureParser`
// is a better alternatives than hard-codeds sequence of those command parsing
// methods.
namespace trunks {

namespace {

TPM_RC ParseAuthSection(std::string* command, TPMS_AUTH_COMMAND* auth) {
  UINT32 size;
  TPM_RC rc = Parse_UINT32(command, &size, nullptr);
  if (rc) {
    return rc;
  }
  if (size > command->size()) {
    return TPM_RC_AUTHSIZE;
  }

  std::string auth_section = command->substr(0, size);

  rc = Parse_TPMS_AUTH_COMMAND(&auth_section, auth, nullptr);
  if (rc) {
    return rc;
  }

  // Remove the authorization section from the input.
  *command = command->substr(size);
  return TPM_RC_SUCCESS;
}

}  // namespace

TPM_RC RealCommandParser::ParseHeader(std::string* command,
                                      TPMI_ST_COMMAND_TAG* tag,
                                      UINT32* size,
                                      TPM_CC* cc) {
  const UINT32 command_size = command->size();
  TPM_RC rc = Parse_TPMI_ST_COMMAND_TAG(command, tag, nullptr);
  if (rc) {
    return rc;
  }
  if (*tag != TPM_ST_SESSIONS && *tag != TPM_ST_NO_SESSIONS) {
    return TPM_RC_BAD_TAG;
  }
  rc = Parse_UINT32(command, size, nullptr);
  if (rc) {
    return rc;
  }
  if (command_size != *size) {
    return TPM_RC_COMMAND_SIZE;
  }
  return Parse_TPM_CC(command, cc, nullptr);
}

TPM_RC RealCommandParser::ParseCommandGetCapability(std::string* command,
                                                    TPM_CAP* cap,
                                                    UINT32* property,
                                                    UINT32* property_count) {
  TPMI_ST_COMMAND_TAG tag;
  UINT32 size;
  TPM_CC cc;
  TPM_RC rc = ParseHeader(command, &tag, &size, &cc);
  if (rc) {
    return rc;
  }

  if (cc != TPM_CC_GetCapability) {
    LOG(DFATAL) << __func__
                << ": Expecting command code: " << TPM_CC_GetCapability
                << "; got " << cc;
    return TPM_RC_COMMAND_CODE;
  }

  rc = Parse_TPM_CAP(command, cap, nullptr);
  if (rc) {
    return rc;
  }

  // Note that validation of `cap` is not implemented in this parser because we
  // don't have the usecase.

  rc = Parse_UINT32(command, property, nullptr);
  if (rc) {
    return rc;
  }
  rc = Parse_UINT32(command, property_count, nullptr);
  if (rc) {
    return rc;
  }

  if (!command->empty()) {
    rc = TPM_RC_SIZE;
  }
  return rc;
}

TPM_RC RealCommandParser::ParseCommandNvRead(std::string* command,
                                             TPMI_RH_NV_AUTH* auth_handle,
                                             TPMI_RH_NV_INDEX* nv_index,
                                             TPMS_AUTH_COMMAND* auth,
                                             UINT16* nv_size,
                                             UINT16* offset) {
  TPMI_ST_COMMAND_TAG tag;
  UINT32 size;
  TPM_CC cc;
  TPM_RC rc = ParseHeader(command, &tag, &size, &cc);
  if (rc) {
    return rc;
  }

  if (cc != TPM_CC_NV_Read) {
    LOG(DFATAL) << __func__ << ": Expecting command code: " << TPM_CC_NV_Read
                << "; got " << cc;
    return TPM_RC_COMMAND_CODE;
  }

  if (tag == TPM_ST_NO_SESSIONS) {
    return TPM_RC_AUTH_MISSING;
  }

  rc = Parse_TPMI_RH_NV_AUTH(command, auth_handle, nullptr);
  if (rc) {
    return rc;
  }
  rc = Parse_TPMI_RH_NV_INDEX(command, nv_index, nullptr);
  if (rc) {
    return rc;
  }
  rc = ParseAuthSection(command, auth);
  if (rc) {
    return rc;
  }
  rc = Parse_UINT16(command, nv_size, nullptr);
  if (rc) {
    return rc;
  }
  rc = Parse_UINT16(command, offset, nullptr);
  if (rc) {
    return rc;
  }

  return command->empty() ? TPM_RC_SUCCESS : TPM_RC_SIZE;
}

TPM_RC RealCommandParser::ParseCommandNvReadPublic(std::string* command,
                                                   TPMI_RH_NV_INDEX* nv_index) {
  TPMI_ST_COMMAND_TAG tag;
  UINT32 size;
  TPM_CC cc;
  TPM_RC rc = ParseHeader(command, &tag, &size, &cc);
  if (rc) {
    return rc;
  }

  if (cc != TPM_CC_NV_ReadPublic) {
    LOG(DFATAL) << __func__
                << ": Expecting command code: " << TPM_CC_NV_ReadPublic
                << "; got " << cc;
    return TPM_RC_COMMAND_CODE;
  }

  // Session is not supported.
  if (tag != TPM_ST_NO_SESSIONS) {
    return TPM_RC_BAD_TAG;
  }

  rc = Parse_TPMI_RH_NV_INDEX(command, nv_index, nullptr);
  if (rc) {
    return rc;
  }

  if (!command->empty()) {
    rc = TPM_RC_SIZE;
  }
  return rc;
}

}  // namespace trunks
