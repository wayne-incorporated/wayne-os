// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_MOCK_DISK_UTIL_H_
#define MINIOS_MOCK_DISK_UTIL_H_

#include <gmock/gmock.h>

#include "minios/disk_util.h"

namespace minios {

class MockDiskUtil : public DiskUtil {
 public:
  MockDiskUtil() = default;

  MockDiskUtil(const MockDiskUtil&) = delete;
  MockDiskUtil& operator=(const MockDiskUtil&) = delete;

  MOCK_METHOD(base::FilePath, GetFixedDrive, (), (override));

  MOCK_METHOD(base::FilePath,
              GetStatefulPartition,
              (const base::FilePath& drive),
              (override));
};

}  // namespace minios

#endif  // MINIOS_MOCK_DISK_UTIL_H_
