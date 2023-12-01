// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_STORAGE_ERROR_TEST_HELPERS_H_
#define CRYPTOHOME_STORAGE_ERROR_TEST_HELPERS_H_

#include <ostream>
#include <string>

#include <gmock/gmock.h>

#include "cryptohome/storage/error.h"

namespace cryptohome {
namespace storage {
namespace testing {

using ::testing::PrintToString;

MATCHER_P(IsError,
          val,
          std::string(negation ? "is not" : "is") + " equal to " +
              PrintToString(val)) {
  if (arg.ok()) {
    return false;
  }
  return val == arg.err_status()->error();
}

inline void PrintTo(const StorageStatus& status, std::ostream* os) {
  *os << PrintToString(status->error());
}

}  // namespace testing
}  // namespace storage
}  // namespace cryptohome

#endif  // CRYPTOHOME_STORAGE_ERROR_TEST_HELPERS_H_
