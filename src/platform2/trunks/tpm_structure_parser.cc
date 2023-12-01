// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/tpm_structure_parser.h"

#define __TRUNKS_TPM_STRUCTURE_PARSER_DEFINE_PARSE_SINGLE(TYPE)         \
  template <>                                                           \
  TPM_RC internal::TpmStructureSingleParserImpl<TYPE>::Parse(TYPE& out) \
      const {                                                           \
    return Parse_##TYPE(&payload_, &out, nullptr);                      \
  }

namespace trunks {

TpmStructureParser::TpmStructureParser(const std::string& payload)
    : payload_(payload) {}

__TRUNKS_TPM_STRUCTURE_PARSER_DEFINE_PARSE_SINGLE(UINT8)
__TRUNKS_TPM_STRUCTURE_PARSER_DEFINE_PARSE_SINGLE(UINT16)
__TRUNKS_TPM_STRUCTURE_PARSER_DEFINE_PARSE_SINGLE(UINT32)

}  // namespace trunks
