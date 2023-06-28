// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/user_policy_service.h"

#include <stdint.h>
#include <sys/stat.h>

#include <string>
#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <chromeos/dbus/service_constants.h>

#include "bindings/device_management_backend.pb.h"
#include "login_manager/dbus_util.h"
#include "login_manager/policy_key.h"
#include "login_manager/policy_store.h"
#include "login_manager/system_utils.h"

namespace em = enterprise_management;

namespace login_manager {

UserPolicyService::UserPolicyService(const base::FilePath& policy_dir,
                                     std::unique_ptr<PolicyKey> policy_key,
                                     const base::FilePath& key_copy_path,
                                     SystemUtils* system_utils)
    : PolicyService(policy_dir, policy_key.get(), nullptr, false),
      scoped_policy_key_(std::move(policy_key)),
      key_copy_path_(key_copy_path),
      system_utils_(system_utils) {}

UserPolicyService::~UserPolicyService() = default;

void UserPolicyService::PersistKeyCopy() {
  // Create a copy at |key_copy_path_| that is readable by chronos.
  if (key_copy_path_.empty())
    return;
  if (scoped_policy_key_->IsPopulated()) {
    base::FilePath dir(key_copy_path_.DirName());
    base::CreateDirectory(dir);
    mode_t mode = S_IRWXU | S_IXGRP | S_IXOTH;
    chmod(dir.value().c_str(), mode);

    const std::vector<uint8_t>& key = scoped_policy_key_->public_key_der();
    system_utils_->AtomicFileWrite(key_copy_path_,
                                   std::string(key.begin(), key.end()));
    mode = S_IRUSR | S_IRGRP | S_IROTH;
    chmod(key_copy_path_.value().c_str(), mode);
  } else {
    // Remove the key if it has been cleared.
    system_utils_->RemoveFile(key_copy_path_);
  }
}

bool UserPolicyService::Store(const PolicyNamespace& ns,
                              const std::vector<uint8_t>& policy_blob,
                              int key_flags,
                              SignatureCheck signature_check,
                              const Completion& completion) {
  em::PolicyFetchResponse policy;
  em::PolicyData policy_data;
  if (!policy.ParseFromArray(policy_blob.data(), policy_blob.size()) ||
      !policy.has_policy_data() ||
      !policy_data.ParseFromString(policy.policy_data())) {
    completion.Run(CREATE_ERROR_AND_LOG(dbus_error::kSigDecodeFail,
                                        "Unable to parse policy protobuf."));
    return false;
  }

  // Allow to switch to unmanaged state even if no signature is present.
  if (policy_data.state() == em::PolicyData::UNMANAGED &&
      !policy.has_policy_data_signature()) {
    // Also clear the key.
    if (key()->IsPopulated()) {
      key()->ClobberCompromisedKey(std::vector<uint8_t>());
      PostPersistKeyTask();
    }

    GetOrCreateStore(ns)->Set(policy);
    PostPersistPolicyTask(ns, completion);
    return true;
  }

  return PolicyService::StorePolicy(ns, policy, key_flags, signature_check,
                                    completion);
}

void UserPolicyService::OnKeyPersisted(bool status) {
  if (status)
    PersistKeyCopy();
  // Only notify the delegate after writing the copy, so that chrome can find
  // the file after being notified that the key is ready.
  PolicyService::OnKeyPersisted(status);
}

}  // namespace login_manager
