// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HWSEC_TEST_UTILS_OWNERSHIP_ID_OWNERSHIP_ID_FACTORY_H_
#define HWSEC_TEST_UTILS_OWNERSHIP_ID_OWNERSHIP_ID_FACTORY_H_

#include <memory>

#include "hwsec-test-utils/ownership_id/ownership_id.h"

namespace hwsec_test_utils {

std::unique_ptr<OwnershipId> GetOwnershipId();

}  // namespace hwsec_test_utils

#endif  // HWSEC_TEST_UTILS_OWNERSHIP_ID_OWNERSHIP_ID_FACTORY_H_
