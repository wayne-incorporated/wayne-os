// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_PLATFORM_MOCK_PLATFORM_H_
#define LIBHWSEC_PLATFORM_MOCK_PLATFORM_H_

#include <string>

#include <base/files/file_path.h>
#include <gmock/gmock.h>

#include "libhwsec/hwsec_export.h"
#include "libhwsec/platform/platform.h"

namespace hwsec {

class HWSEC_EXPORT MockPlatform : public Platform {
 public:
  MockPlatform() = default;
  ~MockPlatform() override = default;

  MOCK_METHOD(bool,
              ReadFileToString,
              (const base::FilePath&, std::string*),
              (override));
};

}  // namespace hwsec

#endif  // LIBHWSEC_PLATFORM_MOCK_PLATFORM_H_
