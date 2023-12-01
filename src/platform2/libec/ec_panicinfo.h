// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_EC_PANICINFO_H_
#define LIBEC_EC_PANICINFO_H_

#include <stdio.h>
#include <string>
#include <vector>

#include <base/containers/span.h>
#include <base/types/expected.h>
#include <brillo/brillo_export.h>
#include <chromeos/ec/panic_defs.h>

namespace ec {

// Return the parsed panic information from |data|.
BRILLO_EXPORT
base::expected<std::string, std::string> ParsePanicInfo(
    base::span<const uint8_t> data);

// Return the data read from stdin. Data returned will not exceed |max_size|.
BRILLO_EXPORT
base::expected<std::vector<uint8_t>, std::string> GetPanicInput(
    size_t max_size);

}  // namespace ec

#endif  // LIBEC_EC_PANICINFO_H_
