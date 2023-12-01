// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AUTHPOLICY_POLICY_EXTENSION_POLICY_ENCODER_H_
#define AUTHPOLICY_POLICY_EXTENSION_POLICY_ENCODER_H_

#include <memory>
#include <string>
#include <vector>

namespace authpolicy {
namespace protos {
class ExtensionPolicy;
}
}  // namespace authpolicy

namespace policy {

class RegistryDict;

using ExtensionPolicies = std::vector<authpolicy::protos::ExtensionPolicy>;

// Private helper class used to convert a RegistryDict into extension policy.
// Don't include directly, use |preg_policy_encoder.h| instead.
class ExtensionPolicyEncoder {
 public:
  explicit ExtensionPolicyEncoder(const RegistryDict* dict);

  // Toggles logging of policy values.
  void LogPolicyValues(bool enabled) { log_policy_values_ = enabled; }

  // Extracts all extension policies from |dict_| and puts them into |policies|.
  // The expected general structure of |dict_| is
  //   key <extension_id_1>
  //     key 'Policy'       <-- Mandatory policies
  //       value policy1    <-- E.g. bool or string policy
  //       value policy2
  //       key policy3      <-- String list policies
  //         value '1'
  //         value '2'
  //         value '3'
  //     key 'Recommended'  <-- Recommended policies
  //       ...
  //   key <extension_id_2>
  //     ...
  // This method converts everything below the extension IDs to a JSON blob and
  // stores it together with the extension IDs in |policies|.
  void EncodePolicy(ExtensionPolicies* policies) const;

 private:
  const RegistryDict* dict_ = nullptr;
  bool log_policy_values_ = false;
};

}  // namespace policy

#endif  // AUTHPOLICY_POLICY_EXTENSION_POLICY_ENCODER_H_
