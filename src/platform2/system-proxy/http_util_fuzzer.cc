// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <vector>

#include <base/logging.h>
#include <base/strings/string_piece.h>

#include <fuzzer/FuzzedDataProvider.h>

#include "system-proxy/http_util.h"

struct Environment {
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // Disable logging.
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  FuzzedDataProvider provider(data, size);
  std::string input_string = provider.ConsumeRandomLengthString(2000);
  base::StringPiece string_piece_input(input_string);
  system_proxy::IsEndingWithHttpEmptyLine(string_piece_input);
  system_proxy::GetUriAuthorityFromHttpHeader(string_piece_input);
  system_proxy::ParseAuthChallenge(string_piece_input);

  std::vector<char> vector_input = provider.ConsumeRemainingBytes<char>();
  std::vector<char> out;
  system_proxy::ExtractHTTPRequest(vector_input, /*out_http_request=*/&out,
                                   /*out_remaining_data=*/&out);
  return 0;
}
