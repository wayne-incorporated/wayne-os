// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_TPM_STRUCTURE_PARSER_H_
#define TRUNKS_TPM_STRUCTURE_PARSER_H_

#include <string>

#include "trunks/tpm_generated.h"
#include "trunks/trunks_export.h"

// HOW TO USE: See the comment of the class `TpmStructureParser`.

namespace trunks {

// Internal implementation of the arbitrary parser.
// DO NOT USE ANYTHING INSIDE DIRECTLY.
namespace internal {

template <typename Type>
class TRUNKS_EXPORT TpmStructureSingleParserImpl {
 public:
  explicit TpmStructureSingleParserImpl(std::string& payload)
      : payload_(payload) {}
  TPM_RC Parse(Type& out) const;

 private:
  std::string& payload_;
};

template <typename... Types>
class TRUNKS_EXPORT TpmStructureParserImpl;

template <typename FirstType, typename... Types>
class TRUNKS_EXPORT TpmStructureParserImpl<FirstType, Types...> {
 public:
  explicit TpmStructureParserImpl(std::string& payload) : payload_(payload) {}
  TPM_RC Parse(FirstType& first_out, Types&... outs) const {
    TPM_RC rc =
        TpmStructureSingleParserImpl<FirstType>(payload_).Parse(first_out);
    if (rc) {
      return rc;
    }
    return TpmStructureParserImpl<Types...>(payload_).Parse(outs...);
  }

 private:
  std::string& payload_;
};

template <>
class TRUNKS_EXPORT TpmStructureParserImpl<> {
 public:
  explicit TpmStructureParserImpl(std::string& /*payload*/) {}
  TPM_RC Parse() const { return TPM_RC_SUCCESS; }
};

}  // namespace internal

// A parser class that provides the unified `Parse()` interface that deisnged to
// unify the `trunks::Parse_TYPE(std::string*,TYPE*,std::string*)`.
// For the example of the parser, see the unittests.
// For the example of adding a supported type for parsing, seethe macro
// `__TRUNKS_TPM_STRUCTURE_PARSER_DEFINE_PARSE_SINGLE` in the source file.
class TRUNKS_EXPORT TpmStructureParser {
 public:
  // Copies `payload` into `payload_` for further use.
  explicit TpmStructureParser(const std::string& payload);
  // Consumes `payload_` and parses it into `outs...` in sequence.
  template <typename... Types>
  TPM_RC Parse(Types&... outs) {
    return internal::TpmStructureParserImpl<Types...>(payload_).Parse(outs...);
  }
  // Gets the current `payload_`. It is useful to check there is unexpected
  // leftover, for example.
  std::string payload() { return payload_; }

 private:
  std::string payload_;
};

}  // namespace trunks

#endif  // TRUNKS_TPM_STRUCTURE_PARSER_H_
