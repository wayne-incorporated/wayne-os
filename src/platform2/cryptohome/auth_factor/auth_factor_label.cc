// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor/auth_factor_label.h"

#include <algorithm>
#include <locale>

#include <base/logging.h>
#include <base/no_destructor.h>

namespace cryptohome {

namespace {

// An arbitrarily chosen constant, simply to prevent extremely long labels that
// can lead to any kind of problem at the file system layer.
constexpr int kMaxLabelLength = 1000;

// Checks whether the character belongs to the set: a-z, A-Z, 0-9, -, _.
bool IsAllowedCharacter(char c) {
  // Make sure the alphanumeric checks are using the C locale, so that we don't
  // accept anything beyond a-z, A-Z, 0-9. Cache the locale object as it might
  // be expensive to construct, and make it never-destructed as style guide
  // forbids dynamic destruction during shutdown.
  static base::NoDestructor<std::locale> locale("C");

  return std::isalnum(c, *locale) || c == '-' || c == '_';
}

}  // namespace

bool IsValidAuthFactorLabel(const std::string& label) {
  if (label.empty()) {
    LOG(ERROR) << "An empty auth factor label is invalid.";
    return false;
  }
  if (label.length() > kMaxLabelLength) {
    LOG(ERROR) << "An excessively long auth factor label: " << label.length()
               << " versus " << kMaxLabelLength << ".";
    return false;
  }
  if (!std::all_of(label.begin(), label.end(), IsAllowedCharacter)) {
    LOG(ERROR) << "Auth factor label contains forbidden characters.";
    return false;
  }
  return true;
}

}  // namespace cryptohome
