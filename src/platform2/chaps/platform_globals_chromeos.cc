// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Per-platform global values
//

#include "chaps/platform_globals.h"

namespace chaps {

const char kChapsdProcessUser[] = "chaps";
const char kChapsdProcessGroup[] = "chronos-access";

const char kServiceRedirectProcessUser[] = "chronos";
const char kServiceRedirectProcessGroup[] = "pkcs11";

}  // namespace chaps
