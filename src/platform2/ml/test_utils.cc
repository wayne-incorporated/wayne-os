// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/test_utils.h"

#include <base/check_op.h>

namespace ml {

std::string GetTestModelDir() {
  const char* const temp_dir = getenv("T");
  CHECK_NE(temp_dir, nullptr);
  return std::string(temp_dir) + "/ml_models/";
}

std::string GetMlServicePath() {
  const char* const temp_dir = getenv("OUT");
  CHECK_NE(temp_dir, nullptr);
  return std::string(temp_dir) + "/ml_service";
}

}  // namespace ml
