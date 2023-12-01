// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/mock_profile.h"

#include <string>

#include <base/memory/ref_counted.h>
#include <gmock/gmock.h>

#include "shill/refptr_types.h"

using testing::ReturnRef;

namespace shill {

MockProfile::MockProfile(Manager* manager) : MockProfile(manager, "mock") {}

MockProfile::MockProfile(Manager* manager, const std::string& identifier)
    : Profile(manager, Identifier(identifier), base::FilePath(), false) {
  ON_CALL(*this, GetRpcIdentifier()).WillByDefault(ReturnRef(rpcid_));
}

MockProfile::~MockProfile() = default;

}  // namespace shill
