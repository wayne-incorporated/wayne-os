// Copyright 2010 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_PERSISTENT_INTEGER_MOCK_H_
#define METRICS_PERSISTENT_INTEGER_MOCK_H_

#include <string>

#include <gmock/gmock.h>

#include "base/files/file_path.h"
#include "metrics/persistent_integer.h"

namespace chromeos_metrics {

class PersistentIntegerMock : public PersistentInteger {
 public:
  explicit PersistentIntegerMock(const base::FilePath& backing_file_path)
      : PersistentInteger(backing_file_path) {}
  MOCK_METHOD(void, Add, (int64_t), (override));
  MOCK_METHOD(int64_t, GetAndClear, (), (override));
};

}  // namespace chromeos_metrics

#endif  // METRICS_PERSISTENT_INTEGER_MOCK_H_
