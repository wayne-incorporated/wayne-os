// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <base/logging.h>
#include <brillo/secure_blob.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>

class Environment {
 public:
  Environment() { logging::SetMinLogLevel(logging::LOGGING_FATAL); }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  brillo::Blob blob(data, data + size);
  auto ret = hwsec_foundation::BlobToHex(blob);
  return 0;
}
