// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_FACTOR_AUTH_FACTOR_LABEL_H_
#define CRYPTOHOME_AUTH_FACTOR_AUTH_FACTOR_LABEL_H_

#include <string>

namespace cryptohome {

// Returns whether the given string conforms to the format of auth factor
// labels. In particular, it makes this string safe for being used as a file
// name component.
//
// Note: it's a pure function; it does *not* check which factors are currently
// configured for users.
bool IsValidAuthFactorLabel(const std::string& label);

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_FACTOR_AUTH_FACTOR_LABEL_H_
