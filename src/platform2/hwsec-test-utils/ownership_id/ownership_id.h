// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HWSEC_TEST_UTILS_OWNERSHIP_ID_OWNERSHIP_ID_H_
#define HWSEC_TEST_UTILS_OWNERSHIP_ID_OWNERSHIP_ID_H_

#include <optional>
#include <string>

namespace hwsec_test_utils {

class OwnershipId {
 public:
  OwnershipId() = default;
  virtual ~OwnershipId() = default;

  // Empty string means the ownership haven't been taken.
  // std::nullopt means we failed to get the ID.
  virtual std::optional<std::string> Get() = 0;
};

}  // namespace hwsec_test_utils

#endif  // HWSEC_TEST_UTILS_OWNERSHIP_ID_OWNERSHIP_ID_H_
