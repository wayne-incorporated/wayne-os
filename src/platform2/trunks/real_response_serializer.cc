// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/real_response_serializer.h"

#include <string>

#include <base/logging.h>

#include "trunks/authorization_delegate.h"
#include "trunks/command_parser.h"
#include "trunks/tpm_generated.h"
#include "trunks/trunks_export.h"

namespace trunks {

void RealResponseSerializer::SerializeHeaderOnlyResponse(
    TPM_RC rc, std::string* response) {
  const TPMI_ST_COMMAND_TAG tag =
      (rc == TPM_RC_BAD_TAG ? TPM_ST_RSP_COMMAND : TPM_ST_NO_SESSIONS);
  Serialize_TPMI_ST_COMMAND_TAG(tag, response);
  Serialize_UINT32(kHeaderSize, response);
  Serialize_TPM_RC(rc, response);
}

void RealResponseSerializer::SerializeResponseGetCapability(
    TPMI_YES_NO has_more,
    const TPMS_CAPABILITY_DATA& cap_data,
    std::string* response) {
  std::string buffer;
  Serialize_TPMI_YES_NO(has_more, &buffer);
  Serialize_TPMS_CAPABILITY_DATA(cap_data, &buffer);
  const UINT32 size = kHeaderSize + buffer.size();
  // Session is not supported.
  Serialize_TPMI_ST_COMMAND_TAG(TPM_ST_NO_SESSIONS, response);
  Serialize_UINT32(size, response);
  Serialize_TPM_RC(TPM_RC_SUCCESS, response);
  response->append(buffer);
}

void RealResponseSerializer::SerializeResponseNvRead(
    const TPM2B_MAX_NV_BUFFER& data, std::string* response) {
  std::string parameter;
  Serialize_TPM2B_MAX_NV_BUFFER(data, &parameter);
  // For now, only password session is supported, so just hard-code the logic.
  TPMS_AUTH_RESPONSE auth = {};
  auth.session_attributes = kContinueSession;
  std::string auth_section;
  Serialize_TPMS_AUTH_RESPONSE(auth, &auth_section);
  std::string parameter_size;
  Serialize_UINT32(parameter.size(), &parameter_size);

  const UINT32 size = kHeaderSize + parameter_size.size() + parameter.size() +
                      auth_section.size();
  // Serialize header.
  std::string header;
  // Session is required.
  Serialize_TPMI_ST_COMMAND_TAG(TPM_ST_SESSIONS, &header);
  Serialize_UINT32(size, &header);
  Serialize_TPM_RC(TPM_RC_SUCCESS, &header);

  *response = header + parameter_size + parameter + auth_section;
}

void RealResponseSerializer::SerializeResponseNvReadPublic(
    const TPM2B_NV_PUBLIC& nv_public,
    const TPM2B_NAME& nv_name,
    std::string* response) {
  std::string buffer;
  Serialize_TPM2B_NV_PUBLIC(nv_public, &buffer);
  Serialize_TPM2B_NAME(nv_name, &buffer);
  const UINT32 size = kHeaderSize + buffer.size();
  // Session is not supported.
  Serialize_TPMI_ST_COMMAND_TAG(TPM_ST_NO_SESSIONS, response);
  Serialize_UINT32(size, response);
  Serialize_TPM_RC(TPM_RC_SUCCESS, response);
  response->append(buffer);
}

}  // namespace trunks
