// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/variant_utils.h"

namespace debugd {

bool AddIntOption(SandboxedProcess* process,
                  const brillo::VariantDictionary& options,
                  const std::string& key,
                  const std::string& flag_name,
                  brillo::ErrorPtr* error) {
  int value;
  ParseResult result = GetOption(options, key, &value, error);
  if (result == ParseResult::PARSED)
    process->AddIntOption(flag_name, value);

  return result != ParseResult::PARSE_ERROR;
}

bool AddBoolOption(SandboxedProcess* process,
                   const brillo::VariantDictionary& options,
                   const std::string& key,
                   const std::string& flag_name,
                   brillo::ErrorPtr* error) {
  int value;
  ParseResult result = GetOption(options, key, &value, error);
  if (result == ParseResult::PARSED && value)
    process->AddArg(flag_name);

  return result != ParseResult::PARSE_ERROR;
}

}  // namespace debugd
