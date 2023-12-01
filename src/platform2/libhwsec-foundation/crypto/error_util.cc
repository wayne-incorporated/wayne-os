// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/crypto/error_util.h"

#include <base/logging.h>
#include <base/strings/strcat.h>
#include <openssl/err.h>

namespace hwsec_foundation {

std::string GetOpenSSLErrors() {
  std::string message;
  int error_code;
  while ((error_code = ERR_get_error()) != 0) {
    char error_buf[256];
    error_buf[0] = 0;
    ERR_error_string_n(error_code, error_buf, sizeof(error_buf));
    base::StrAppend(&message, {error_buf, ";"});
  }
  return message;
}

}  // namespace hwsec_foundation
