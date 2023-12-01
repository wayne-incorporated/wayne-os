// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AUTHPOLICY_POLICY_POLICY_ENCODER_TEST_BASE_H_
#define AUTHPOLICY_POLICY_POLICY_ENCODER_TEST_BASE_H_

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/strings/string_number_conversions.h>
#include <base/values.h>
#include <components/policy/core/common/registry_dict.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace policy {

// Base class for UserPolicyEncoderTest and DevicePolicyEncoderTest. T_POLICY
// is the type of the policy and should either be
// enterprise_management::CloudPolicySettings or
// enterprise_management::ChromeDeviceSettingsProto.
template <typename T_POLICY>
class PolicyEncoderTestBase : public ::testing::Test {
 public:
  PolicyEncoderTestBase() {}
  PolicyEncoderTestBase(const PolicyEncoderTestBase&) = delete;
  PolicyEncoderTestBase& operator=(const PolicyEncoderTestBase&) = delete;
  ~PolicyEncoderTestBase() override {}

 protected:
  // Set registry key base path at which values are set (for extension policy).
  void SetPath(std::initializer_list<const char*> path) { path_ = path; }

  // Clears |policy|, encodes |value| as value for the boolean policy |key| and
  // marks |key| as handled.
  void EncodeBoolean(T_POLICY* policy, const char* key, bool value) {
    EncodeValue(policy, key, base::Value(value));
  }

  // Clears |policy|, encodes |value| as value for the integer policy |key| and
  // marks |key| as handled.
  void EncodeInteger(T_POLICY* policy, const char* key, int value) {
    EncodeValue(policy, key, base::Value(value));
  }

  // Clears |policy|, encodes |value| as value for the string policy |key| and
  // marks |key| as handled.
  void EncodeString(T_POLICY* policy,
                    const char* key,
                    const std::string& value) {
    EncodeValue(policy, key, base::Value(value));
  }

  // Clears |policy|, encodes |value| as value for the string list policy |key|
  // and marks |key| as handled.
  void EncodeStringList(T_POLICY* policy,
                        const char* key,
                        const std::vector<std::string>& value) {
    auto value_dict = std::make_unique<RegistryDict>();
    for (int n = 0; n < static_cast<int>(value.size()); ++n) {
      value_dict->SetValue(base::NumberToString(n + 1), base::Value(value[n]));
    }
    std::unique_ptr<RegistryDict> root_dict;
    RegistryDict* dict = MakeRegistryDictTree(&root_dict);
    dict->SetKey(key, std::move(value_dict));
    EncodeDict(policy, root_dict.get());
    MarkHandled(key);
  }

  // Called by all of the Encode* methods. Override to keep track of encoded
  // policies.
  virtual void MarkHandled(const char* /* key */) {}

  // Uses a policy encoder to write |dict| to |policy|.
  virtual void EncodeDict(T_POLICY* policy, const RegistryDict* dict) = 0;

 private:
  // Creates a RegistryDict sequence along |path_| with |root_dict| at the root
  // and the return value at the leaf.
  RegistryDict* MakeRegistryDictTree(std::unique_ptr<RegistryDict>* root_dict) {
    *root_dict = std::make_unique<RegistryDict>();
    RegistryDict* curr_dict = root_dict->get();
    for (const char* subkey : path_) {
      curr_dict->SetKey(subkey, std::make_unique<RegistryDict>());
      curr_dict = curr_dict->GetKey(subkey);
    }
    return curr_dict;
  }

  // Clears |policy|, encodes |value| as value for the given |key| and marks
  // |key| as handled.
  void EncodeValue(T_POLICY* policy, const char* key, base::Value value) {
    std::unique_ptr<RegistryDict> root_dict;
    RegistryDict* dict = MakeRegistryDictTree(&root_dict);
    dict->SetValue(key, std::move(value));
    EncodeDict(policy, root_dict.get());
    MarkHandled(key);
  }

  // Registry key path at which values are set, e.g.
  //   {"gihmafigllmhbppdfjnfecimiohcljba", "Policy"}
  // for extension policy.
  std::vector<const char*> path_;
};

}  // namespace policy

#endif  // AUTHPOLICY_POLICY_POLICY_ENCODER_TEST_BASE_H_
