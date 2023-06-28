// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_FEATURE_FLAGS_UTIL_H_
#define LOGIN_MANAGER_FEATURE_FLAGS_UTIL_H_

#include <string>
#include <vector>

namespace login_manager {

// Maps a command line switch |switch_string| (as present in legacy feature
// flags device settings) to feature flags and appends these to the
// |feature_flags| vector. Note that one switch can expand to multiple feature
// flags in the case of --{enable,disable}-features. Returns true if the mapping
// was performed successfully and false in case the switch can't be parsed or is
// unknown.
bool MapSwitchToFeatureFlags(const std::string& switch_string,
                             std::vector<std::string>* feature_flags);

}  // namespace login_manager

#endif  // LOGIN_MANAGER_FEATURE_FLAGS_UTIL_H_
