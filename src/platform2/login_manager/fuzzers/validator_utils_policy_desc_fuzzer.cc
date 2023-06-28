// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h>

#include "login_manager/proto_bindings/policy_descriptor.pb.h"
#include "login_manager/validator_utils.h"

DEFINE_PROTO_FUZZER(const login_manager::PolicyDescriptor& desc) {
  login_manager::ValidatePolicyDescriptor(
      desc, login_manager::PolicyDescriptorUsage::kStore);
  login_manager::ValidatePolicyDescriptor(
      desc, login_manager::PolicyDescriptorUsage::kRetrieve);
  login_manager::ValidatePolicyDescriptor(
      desc, login_manager::PolicyDescriptorUsage::kList);
}
