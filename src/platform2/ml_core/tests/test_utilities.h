// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml_core/effects_pipeline.h"

#ifndef ML_CORE_TESTS_TEST_UTILITIES_H_
#define ML_CORE_TESTS_TEST_UTILITIES_H_

struct ImageFrame {
  uint8_t* frame_data;
  uint32_t frame_width;
  uint32_t frame_height;
  uint32_t stride;
};

bool FuzzyBufferComparison(uint8_t* left,
                           uint8_t* right,
                           uint64_t buf_len,
                           int acceptable_pixel_delta = 0,
                           int num_accept_outside_delta = 0);

#endif  // ML_CORE_TESTS_TEST_UTILITIES_H_
