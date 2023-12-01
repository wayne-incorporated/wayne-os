// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MIST_MOCK_CONFIG_LOADER_H_
#define MIST_MOCK_CONFIG_LOADER_H_

#include <gmock/gmock.h>

#include "mist/config_loader.h"

namespace mist {

class MockConfigLoader : public ConfigLoader {
 public:
  MockConfigLoader() = default;
  MockConfigLoader(const MockConfigLoader&) = delete;
  MockConfigLoader& operator=(const MockConfigLoader&) = delete;

  ~MockConfigLoader() override = default;

  MOCK_METHOD(bool, LoadDefaultConfig, (), (override));
  MOCK_METHOD(bool, LoadConfig, (const base::FilePath&), (override));
  MOCK_METHOD(const UsbModemInfo*,
              GetUsbModemInfo,
              (uint16_t, uint16_t),
              (const, override));
};

}  // namespace mist

#endif  // MIST_MOCK_CONFIG_LOADER_H_
