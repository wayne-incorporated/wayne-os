// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <float.h>
#include <math.h>

#include <cstdint>

#include <base/time/time.h>
#include <brillo/flag_helper.h>

// Check the accuracy after executes one million floating-point operations.
bool CheckFloatingPointAccuracy() {
  // kIncrement is the result from 1.0 / 1024.0
  constexpr float kIncrement = 0.0009765625f;
  // Declare 16 variables which will map to 16 XMM registers on the
  // architecture where the SSE hardware is available.
  float a = 0.0f;
  float b = 0.0f;
  float c = 0.0f;
  float d = 0.0f;
  float e = 0.0f;
  float f = 0.0f;
  float g = 0.0f;
  float h = 0.0f;
  float i = 0.0f;
  float j = 0.0f;
  float k = 0.0f;
  float l = 0.0f;
  float m = 0.0f;
  float n = 0.0f;
  float o = 0.0f;
  float p = 0.0f;

  uint64_t x = 1e6;
  do {
    a += kIncrement;
    b += kIncrement;
    c += kIncrement;
    d += kIncrement;
    e += kIncrement;
    f += kIncrement;
    g += kIncrement;
    h += kIncrement;
    i += kIncrement;
    j += kIncrement;
    k += kIncrement;
    l += kIncrement;
    m += kIncrement;
    n += kIncrement;
    o += kIncrement;
    p += kIncrement;
  } while (--x);

  // Check the result of accuracy in the end.
  if (fabs(a - 976.5625f) > FLT_EPSILON || fabs(i - 976.5625f) > FLT_EPSILON ||
      fabs(b - 976.5625f) > FLT_EPSILON || fabs(j - 976.5625f) > FLT_EPSILON ||
      fabs(c - 976.5625f) > FLT_EPSILON || fabs(k - 976.5625f) > FLT_EPSILON ||
      fabs(d - 976.5625f) > FLT_EPSILON || fabs(l - 976.5625f) > FLT_EPSILON ||
      fabs(e - 976.5625f) > FLT_EPSILON || fabs(m - 976.5625f) > FLT_EPSILON ||
      fabs(f - 976.5625f) > FLT_EPSILON || fabs(n - 976.5625f) > FLT_EPSILON ||
      fabs(g - 976.5625f) > FLT_EPSILON || fabs(o - 976.5625f) > FLT_EPSILON ||
      fabs(h - 976.5625f) > FLT_EPSILON || fabs(p - 976.5625f) > FLT_EPSILON) {
    return false;
  }

  return true;
}

// 'floating-point-accuracy' command-line tool:
//
// Execute millions of floating-point operations by SSE instructions for
// a specified amount of time. Compare the result values of the operations
// with a known accurate result. The routine is passed when the result are
// the same.
int main(int argc, char** argv) {
  DEFINE_uint64(duration, 2, "duration in seconds to run routine for.");
  brillo::FlagHelper::Init(argc, argv,
                           "floating-point-accuracy - diagnostic routine.");

  const base::TimeTicks end_time =
      base::TimeTicks::Now() + base::Seconds(FLAGS_duration);
  do {
    if (CheckFloatingPointAccuracy() == false) {
      return EXIT_FAILURE;
    }
  } while (end_time > base::TimeTicks::Now());
  return EXIT_SUCCESS;
}
