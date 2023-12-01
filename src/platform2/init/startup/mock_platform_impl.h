// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INIT_STARTUP_MOCK_PLATFORM_IMPL_H_
#define INIT_STARTUP_MOCK_PLATFORM_IMPL_H_

#include <string>

#include <gmock/gmock.h>

#include "init/startup/platform_impl.h"

namespace startup {

class MockPlatform : public Platform {
 public:
  MockPlatform() = default;

  MockPlatform(const MockPlatform&) = delete;
  MockPlatform& operator=(const MockPlatform&) = delete;

  MOCK_METHOD(bool,
              Stat,
              (const base::FilePath& path, struct stat* st),
              (override));
  MOCK_METHOD(bool,
              Mount,
              (const base::FilePath& src,
               const base::FilePath& dst,
               const std::string& type,
               unsigned long flags,  // NOLINT(runtime/int)
               const std::string& data),
              (override));
  MOCK_METHOD(bool,
              Mount,
              (const std::string& src,
               const base::FilePath& dst,
               const std::string& type,
               unsigned long flags,  // NOLINT(runtime/int)
               const std::string& data),
              (override));
  MOCK_METHOD(bool, Umount, (const base::FilePath& path), (override));
  MOCK_METHOD(base::ScopedFD,
              Open,
              (const base::FilePath& pathname, int flags),
              (override));
  MOCK_METHOD(int,
              Ioctl,
              // NOLINTNEXTLINE(runtime/int)
              (int fd, unsigned long request, int* arg1),
              (override));
  MOCK_METHOD(bool, Fchown, (int fd, uid_t owner, gid_t group), (override));
  MOCK_METHOD(bool,
              RunHiberman,
              (const base::FilePath& output_file),
              (override));
  MOCK_METHOD(void, RunProcess, (const base::FilePath& cmd_path), (override));
  MOCK_METHOD(std::optional<base::FilePath>,
              GetRootDevicePartitionPath,
              (const std::string& partition_label),
              (override));
};

}  // namespace startup

#endif  // INIT_STARTUP_MOCK_PLATFORM_IMPL_H_
