// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/strings/stringprintf.h>
#include <fuzzer/FuzzedDataProvider.h>

#include <algorithm>
#include <string>
#include <vector>

#include "power_manager/powerd/policy/ambient_light_pref_fuzz_util.h"

namespace power_manager::policy::test {

std::string GenerateAmbientLightPref(FuzzedDataProvider* data_provider,
                                     int max_step,
                                     int lux_max) {
  int num_step = data_provider->ConsumeIntegralInRange<int>(1, max_step);

  std::vector<double> ac;     // AC brightness in percent
  std::vector<double> dc;     // DC brightness in percent
  std::vector<int> lux;       // lux to use in lux_up / lux_down
  std::vector<int> lux_up;    // lux to step up
  std::vector<int> lux_down;  // lux to step down

  for (int i = 0; i < num_step; i++) {
    ac.push_back(data_provider->ConsumeFloatingPointInRange<double>(0.01, 100));
    dc.push_back(data_provider->ConsumeFloatingPointInRange<double>(0.01, 100));
  }
  std::sort(ac.begin(), ac.end());
  std::sort(dc.begin(), dc.end());

  for (int i = 1; i < num_step; i++) {
    lux.push_back(data_provider->ConsumeIntegralInRange<int>(0, lux_max));
    lux.push_back(data_provider->ConsumeIntegralInRange<int>(0, lux_max));
  }
  std::sort(lux.begin(), lux.end());

  lux_down.push_back(-1);  // Can't step down at lowest level
  for (int i = 0; i < num_step - 1; i++) {
    // lux_downdown[i+1] should be less than or equal to lux_up[i]
    lux_down.push_back(lux[i * 2]);
    lux_up.push_back(lux[i * 2 + 1]);
  }
  lux_up.push_back(-1);  // Can't step up at highest level

  std::string pref;
  for (int i = 0; i < num_step; i++) {
    base::StringAppendF(&pref, "%0.2f %0.2f %d %d\n", ac[i], dc[i], lux_down[i],
                        lux_up[i]);
  }
  pref.erase(pref.length() - 1);  // remove trailing new line
  return pref;
}

}  // namespace power_manager::policy::test
