// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_POLICY_AMBIENT_LIGHT_PREF_FUZZ_UTIL_H_
#define POWER_MANAGER_POWERD_POLICY_AMBIENT_LIGHT_PREF_FUZZ_UTIL_H_

#include <fuzzer/FuzzedDataProvider.h>

#include <string>

namespace power_manager::policy::test {

// Helper method to generate valid ambient light pref string
std::string GenerateAmbientLightPref(FuzzedDataProvider* data_provider,
                                     int max_step = 10,
                                     int lux_max = 20000);

}  // namespace power_manager::policy::test

#endif  // POWER_MANAGER_POWERD_POLICY_AMBIENT_LIGHT_PREF_FUZZ_UTIL_H_
