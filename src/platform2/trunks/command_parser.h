// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_COMMAND_PARSER_H_
#define TRUNKS_COMMAND_PARSER_H_

#include <string>

#include "trunks/tpm_generated.h"
#include "trunks/trunks_export.h"

namespace trunks {

// TPM message header size.
inline constexpr size_t kHeaderSize = 10;

// A class that parses TPM commands.
class TRUNKS_EXPORT CommandParser {
 public:
  virtual ~CommandParser() = default;

  // Parses TPM command headers, including the session tag, the request size,
  // and the command code.
  virtual TPM_RC ParseHeader(std::string* command,
                             TPMI_ST_COMMAND_TAG* tag,
                             UINT32* command_size,
                             TPM_CC* cc) = 0;

  // Parses a `TPM2_GetCapability` command, and set `cap`, `property`, and
  // `property_count` to the corresponding values in the command.
  // If `command` doesn't have `TPM2_GetCapability` command code, the eror
  // handling is implementation defined.
  virtual TPM_RC ParseCommandGetCapability(std::string* command,
                                           TPM_CAP* cap,
                                           UINT32* property,
                                           UINT32* property_count) = 0;

  // Parses a `TPM2_NV_Read` command, and set `auth_handle`, `nv_index`, `auth`,
  // `size`, and `offset` to the corresponding values in the command.
  // If `command` doesn't have `TPM2_NV_Read` command code, the error
  // handling is implementation defined.
  virtual TPM_RC ParseCommandNvRead(std::string* command,
                                    TPMI_RH_NV_AUTH* auth_handle,
                                    TPMI_RH_NV_INDEX* nv_index,
                                    TPMS_AUTH_COMMAND* auth,
                                    UINT16* size,
                                    UINT16* offset) = 0;

  // Parses a `TPM2_NV_ReadPublic` command, and set `nv_index` to the
  // corresponding value in the command. If `command` doesn't have
  // `TPM2_NV_ReadPublic` command code, the error handling is implementation
  // defined.
  virtual TPM_RC ParseCommandNvReadPublic(std::string* command,
                                          TPMI_RH_NV_INDEX* nv_index) = 0;
};

}  // namespace trunks

#endif  // TRUNKS_COMMAND_PARSER_H_
