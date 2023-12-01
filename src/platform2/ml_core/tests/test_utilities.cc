// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml_core/tests/test_utilities.h"
#include <cstdlib>
#include <iostream>

bool FuzzyBufferComparison(uint8_t* left,
                           uint8_t* right,
                           uint64_t buf_len,
                           int acceptable_pixel_delta,
                           int num_accept_outside_delta) {
  int cnt = 0;
  for (int i = 0; i < buf_len; ++i) {
    if (abs(left[i] - right[i]) > acceptable_pixel_delta)
      cnt += 1;
  }
  if (cnt > num_accept_outside_delta) {
    return false;
  }
  return true;
}
