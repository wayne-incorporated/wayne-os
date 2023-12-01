// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Fuzzer that tests parsing and serialization of key blobs.

#include <stddef.h>
#include <stdint.h>

#include <string>

#include "base/logging.h"
#include "trunks/blob_parser.h"

struct Environment {
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // Disable logging.
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 1)
    return 0;
  static Environment env;
  static trunks::BlobParser blob_parser;

  // Parse.
  std::string key_blob(reinterpret_cast<const char*>(data), size);
  trunks::TPM2B_PUBLIC public_info;
  trunks::TPM2B_PRIVATE private_info;

  if (!blob_parser.ParseKeyBlob(key_blob, &public_info, &private_info))
    return 0;  // Quit early on failure to avoid serializing unitialized data.

  // Serialize.
  std::string serialized;
  blob_parser.SerializeKeyBlob(public_info, private_info, &serialized);
  return 0;
}
