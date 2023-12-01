// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <base/strings/string_piece.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>

#include "runtime_probe/utils/type_utils.h"

namespace runtime_probe {

bool StringToDouble(base::StringPiece input, double* output) {
  base::StringPiece trimmed_input =
      TrimWhitespaceASCII(input, base::TrimPositions::TRIM_ALL);
  return base::StringToDouble(trimmed_input, output);
}

bool StringToInt(base::StringPiece input, int* output) {
  base::StringPiece trimmed_input =
      TrimWhitespaceASCII(input, base::TrimPositions::TRIM_ALL);
  return base::StringToInt(trimmed_input, output);
}

bool StringToInt64(base::StringPiece input, int64_t* output) {
  base::StringPiece trimmed_input =
      TrimWhitespaceASCII(input, base::TrimPositions::TRIM_ALL);
  return base::StringToInt64(trimmed_input, output);
}

bool HexStringToInt(base::StringPiece input, int* output) {
  base::StringPiece trimmed_input =
      TrimWhitespaceASCII(input, base::TrimPositions::TRIM_ALL);
  return base::HexStringToInt(trimmed_input, output);
}

bool HexStringToInt64(base::StringPiece input, int64_t* output) {
  base::StringPiece trimmed_input =
      TrimWhitespaceASCII(input, base::TrimPositions::TRIM_ALL);
  return base::HexStringToInt64(trimmed_input, output);
}

std::string ByteToHexString(const uint8_t byte) {
  return "0x" + base::HexEncode(&byte, 1);
}

}  // namespace runtime_probe
