// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/json_utils.h"

#include <base/check.h>
#include <base/json/json_reader.h>
#include <base/logging.h>
#include <base/values.h>

namespace diagnostics {
namespace wilco {

bool IsJsonValid(base::StringPiece json, std::string* json_error_message) {
  DCHECK(json_error_message);
  auto result = base::JSONReader::ReadAndReturnValueWithError(
      json, base::JSONParserOptions::JSON_ALLOW_TRAILING_COMMAS);
  if (!result.has_value()) {
    *json_error_message = result.error().message;
  }
  return result.has_value();
}

}  // namespace wilco
}  // namespace diagnostics
