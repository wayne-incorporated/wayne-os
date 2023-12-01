// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MOJO_SERVICE_MANAGER_DAEMON_SERVICE_POLICY_TEST_UTIL_H_
#define MOJO_SERVICE_MANAGER_DAEMON_SERVICE_POLICY_TEST_UTIL_H_

#include <map>
#include <set>
#include <string>
#include <utility>

#include "mojo_service_manager/daemon/service_policy.h"

namespace chromeos {
namespace mojo_service_manager {

// Creates ServicePolicyMap from braced-init-list. This avoid adding copy
// constructor to ServicePolicy.
ServicePolicyMap CreateServicePolicyMapForTest(
    const std::map<std::string, std::pair<std::string, std::set<std::string>>>&
        items);

// Creates ServicePolicy from defined sets.
ServicePolicy CreateServicePolicyForTest(
    const std::string& owner, const std::set<std::string>& requesters);

// Compares two ServicePolicy for testing.
bool operator==(const ServicePolicy& a, const ServicePolicy& b);

// Prints ServicePolicy in the error message of gtest.
std::ostream& operator<<(std::ostream& out, const ServicePolicy& policy);

}  // namespace mojo_service_manager
}  // namespace chromeos

#endif  // MOJO_SERVICE_MANAGER_DAEMON_SERVICE_POLICY_TEST_UTIL_H_
