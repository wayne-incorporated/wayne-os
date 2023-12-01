// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_NAMESPACES_MOCK_PLATFORM_H_
#define LIBBRILLO_BRILLO_NAMESPACES_MOCK_PLATFORM_H_

#include "brillo/namespaces/platform.h"

#include <string>

#include <base/files/file_path.h>
#include <gmock/gmock.h>

namespace brillo {

class MockPlatform : public Platform {
 public:
  MockPlatform() {}
  virtual ~MockPlatform() {}

  MOCK_METHOD(bool, Unmount, (const base::FilePath&, bool, bool*), (override));
  MOCK_METHOD(pid_t, Fork, (), (override));
  MOCK_METHOD(pid_t, Waitpid, (pid_t, int*), (override));
  MOCK_METHOD(int,
              Mount,
              (const std::string&,
               const std::string&,
               const std::string&,
               uint64_t,
               const void*),
              (override));
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_NAMESPACES_MOCK_PLATFORM_H_
