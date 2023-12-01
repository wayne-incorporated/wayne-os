// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_VARIANT_UTILS_H_
#define DEBUGD_SRC_VARIANT_UTILS_H_

#include <string>
#include <base/check.h>
#include <brillo/errors/error.h>
#include <brillo/process/process.h>
#include <brillo/type_name_undecorate.h>
#include <brillo/variant_dictionary.h>

#include "debugd/src/error_utils.h"
#include "debugd/src/process_with_id.h"

namespace debugd {

const char kOptionParsingErrorString[] =
    "org.chromium.debugd.error.OptionParsing";

enum class ParseResult {
  NOT_PRESENT,
  PARSE_ERROR,
  PARSED,
};

// Looks up an option in the |options| dictionary. If the
// option is not present, returns NOT_PRESENT. If parsing
// fails (i.e. the supplied option is the wrong type) then
// add to the error chain in |error| and return PARSE_ERROR.
// If the option is present and of the right type, return
// PARSED.
template <typename T>
ParseResult GetOption(const brillo::VariantDictionary& options,
                      const std::string& key,
                      T* value,
                      brillo::ErrorPtr* error) {
  DCHECK(value);

  const auto& it = options.find(key);
  if (it == options.end())
    return ParseResult::NOT_PRESENT;

  if (!it->second.GetValue(value)) {
    std::string expected = brillo::GetUndecoratedTypeName<T>();
    std::string got = it->second.GetUndecoratedTypeName();
    DEBUGD_ADD_ERROR_FMT(
        error, kOptionParsingErrorString,
        "Option \"%s\" has the wrong type (expected %s, got %s)", key.c_str(),
        expected.c_str(), got.c_str());
    return ParseResult::PARSE_ERROR;
  }
  return ParseResult::PARSED;
}

// Looks up an option in the |options| dictionary. If it exists and
// isn't an integer, returns false. Otherwise, returns true, and if it
// exists in the dictionary adds it to the command line for |process|
// as the value for key |flag_name|.
bool AddIntOption(SandboxedProcess* process,
                  const brillo::VariantDictionary& options,
                  const std::string& key,
                  const std::string& flag_name,
                  brillo::ErrorPtr* error);

// Looks up an option in the |options| dictionary. If it exists and
// isn't a boolean, returns false. Otherwise, returns true, and if it
// exists in the dictionary adds it to the command line for |process|.
bool AddBoolOption(SandboxedProcess* process,
                   const brillo::VariantDictionary& options,
                   const std::string& key,
                   const std::string& flag_name,
                   brillo::ErrorPtr* error);

}  // namespace debugd

#endif  // DEBUGD_SRC_VARIANT_UTILS_H_
