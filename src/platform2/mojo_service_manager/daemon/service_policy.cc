// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "mojo_service_manager/daemon/service_policy.h"

#include <string>
#include <utility>

#include <base/check.h>
#include <base/logging.h>
#include <base/strings/string_util.h>

namespace chromeos {
namespace mojo_service_manager {

ServicePolicy::ServicePolicy() = default;

ServicePolicy::~ServicePolicy() = default;

ServicePolicy::ServicePolicy(ServicePolicy&&) = default;

ServicePolicy& ServicePolicy::operator=(ServicePolicy&&) = default;

void ServicePolicy::SetOwner(const std::string& security_context) {
  DCHECK(owner_.empty());
  owner_ = security_context;
}

void ServicePolicy::AddRequester(const std::string& security_context) {
  requesters_.insert(security_context);
}

bool ServicePolicy::Merge(ServicePolicy another) {
  bool res = true;
  if (!owner_.empty() && !another.owner_.empty()) {
    res = false;
    LOG(ERROR)
        << "Cannot merge ServicePolicy. Only allow one owner but got two ("
        << owner_ << " and " << another.owner_ << ").";
  } else if (!another.owner_.empty()) {
    owner_ = another.owner_;
  }
  requesters_.merge(another.requesters_);
  return res;
}

bool ServicePolicy::IsOwner(const std::string& security_context) const {
  return owner_ == security_context;
}

bool ServicePolicy::IsRequester(const std::string& security_context) const {
  return requesters_.count(security_context);
}

bool MergeServicePolicyMaps(ServicePolicyMap* from, ServicePolicyMap* to) {
  bool res = true;
  for (auto& item : *from) {
    auto& [service_name, policy_from] = item;
    ServicePolicy& policy_to = (*to)[service_name];
    if (!policy_to.Merge(std::move(policy_from))) {
      res = false;
      LOG(ERROR) << "Cannot merge ServicePolicy of the service: "
                 << service_name;
    }
  }
  return res;
}

bool ValidateServiceName(const std::string& service_name) {
  if (service_name.empty())
    return false;
  for (char c : service_name) {
    if (!base::IsAsciiAlpha(c) && !base::IsAsciiDigit(c)) {
      return false;
    }
  }
  return true;
}

bool ValidateSecurityContext(const std::string& security_context) {
  if (security_context.empty())
    return false;
  for (char c : security_context) {
    if (!base::IsAsciiLower(c) && !base::IsAsciiDigit(c) && c != '_' &&
        c != ':') {
      return false;
    }
  }
  return true;
}

}  // namespace mojo_service_manager
}  // namespace chromeos
