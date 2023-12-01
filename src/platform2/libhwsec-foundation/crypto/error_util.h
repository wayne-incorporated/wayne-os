// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_CRYPTO_ERROR_UTIL_H_
#define LIBHWSEC_FOUNDATION_CRYPTO_ERROR_UTIL_H_

#include <string>

#include "libhwsec-foundation/hwsec-foundation_export.h"

namespace hwsec_foundation {

// Returns all errors in OpenSSL error queue delimited with a semicolon
// starting from the earliest. Returns empty string if there are no errors in
// the queue. Clears the queue.
HWSEC_FOUNDATION_EXPORT std::string GetOpenSSLErrors();

}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_CRYPTO_ERROR_UTIL_H_
