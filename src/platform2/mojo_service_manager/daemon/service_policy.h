// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MOJO_SERVICE_MANAGER_DAEMON_SERVICE_POLICY_H_
#define MOJO_SERVICE_MANAGER_DAEMON_SERVICE_POLICY_H_

#include <map>
#include <set>
#include <string>

namespace chromeos {
namespace mojo_service_manager {

// Stores the access policies of a service.
class ServicePolicy {
 public:
  ServicePolicy();
  ServicePolicy(const ServicePolicy&) = delete;
  ServicePolicy& operator=(const ServicePolicy&) = delete;
  ServicePolicy(ServicePolicy&&);
  ServicePolicy& operator=(ServicePolicy&&);
  ~ServicePolicy();

  // Sets a |security_context| as the owner of this service.
  void SetOwner(const std::string& security_context);

  // Adds a |security_context| as a requester of this service.
  void AddRequester(const std::string& security_context);

  // Merges another ServicePolicy into this one. Returns whether they can be
  // merged. This will try to merge all other fields even if a field cannot be
  // merged. The merge result of conflict fields are undefined.
  bool Merge(ServicePolicy another);

  // Returns whether |security_context| is an owner of this service.
  bool IsOwner(const std::string& security_context) const;

  // Returns whether |security_context| is a requester of this service.
  bool IsRequester(const std::string& security_context) const;

  // Gets the owner. It could be an empty string if the owner is not set.
  const std::string& owner() const { return owner_; }

  // Gets the requester set.
  const std::set<std::string>& requesters() const { return requesters_; }

 private:
  // The owner of this service.
  std::string owner_;
  // The requesters of this service.
  std::set<std::string> requesters_;

  // This accesses private fields to create ServicePolicy for testing.
  friend ServicePolicy CreateServicePolicyForTest(
      const std::string& owner, const std::set<std::string>& requesters);
};

// The map type which maps service names to service policies.
using ServicePolicyMap = std::map<std::string, ServicePolicy>;

// Merges two ServicePolicyMap. All the policies in |from| are extracted and are
// merged into |to|. Returns whether the all the policies are merged
// successfully. This will try to merge all other policies even if a policy
// cannot be merged.
bool MergeServicePolicyMaps(ServicePolicyMap* from, ServicePolicyMap* to);

// Validates a service name. This only checks the characters are valid and is
// equal to |[a-zA-Z0-9._-]+|.
bool ValidateServiceName(const std::string& service_name);

// Validates a security context. This only checks the characters are valid and
// is equal to |[a-z0-9_:]+|.
bool ValidateSecurityContext(const std::string& security_context);

}  // namespace mojo_service_manager
}  // namespace chromeos

#endif  // MOJO_SERVICE_MANAGER_DAEMON_SERVICE_POLICY_H_
