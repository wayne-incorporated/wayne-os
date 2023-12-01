// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/shill_test_config.h"

#include <string>

#include "shill/logging.h"

#include <base/check.h>

namespace shill {

TestConfig::TestConfig() {
  CHECK(dir_.CreateUniqueTempDir());
}

TestConfig::~TestConfig() = default;

std::string TestConfig::GetRunDirectory() const {
  return dir_.GetPath().value();
}

std::string TestConfig::GetStorageDirectory() const {
  return dir_.GetPath().value();
}

std::string TestConfig::GetUserStorageDirectory() const {
  return dir_.GetPath().value();
}

}  // namespace shill
