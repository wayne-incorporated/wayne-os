// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_SHILL_TEST_CONFIG_H_
#define SHILL_SHILL_TEST_CONFIG_H_

#include <string>

#include <base/files/scoped_temp_dir.h>

#include "shill/shill_config.h"

namespace shill {

class TestConfig : public Config {
 public:
  TestConfig();
  TestConfig(const TestConfig&) = delete;
  TestConfig& operator=(const TestConfig&) = delete;

  ~TestConfig() override;

  std::string GetRunDirectory() const override;
  std::string GetStorageDirectory() const override;
  std::string GetUserStorageDirectory() const override;

 private:
  base::ScopedTempDir dir_;
};

}  // namespace shill

#endif  // SHILL_SHILL_TEST_CONFIG_H_
