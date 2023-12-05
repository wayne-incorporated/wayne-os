// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_RESILIENT_POLICY_STORE_H_
#define LOGIN_MANAGER_RESILIENT_POLICY_STORE_H_

#include "login_manager/policy_store.h"

#include <map>
#include <memory>
#include <utility>

#include <base/files/file_path.h>
#include <policy/device_policy_impl.h>

namespace login_manager {
class LoginMetrics;

// Extends PolicyStore adding the resilient features. That means the store tries
// to load the policy from the files one by one until a good file is read. Also
// persistence is done in a new file after each boot while the number of policy
// files is still limited.
class ResilientPolicyStore : public PolicyStore {
 public:
  // Expected to have non-null |metrics|.
  explicit ResilientPolicyStore(const base::FilePath& default_policy_path,
                                LoginMetrics* metrics);
  ResilientPolicyStore(const ResilientPolicyStore&) = delete;
  ResilientPolicyStore& operator=(const ResilientPolicyStore&) = delete;

  // Persist |policy_| to disk. If it's the first call after boot, as
  // established by the absense of |kCleanupDoneFileName| temporary file, then
  // the policy is persisted in a new policy file with next index. Otherwise the
  // latest policy file is overwritten. Logs UMA stats about the number of
  // invalid policy files identified.
  // Returns false if there's an error while writing data.
  bool Persist() override;

  void set_device_policy_for_testing(
      std::unique_ptr<policy::DevicePolicyImpl> device_policy) {
    device_policy_ = std::move(device_policy);
  }

 private:
  // Check the policy files from the most recent to the oldest until a valid
  // file is found. Loads the signed policy off of the valid file into
  // |policy_|. Logs UMA stats about the number of invalid policy files
  // identified. Returns true unless there is at least one policy file on disk
  // and loading fails for all the policy files present.
  bool LoadOrCreate() override;

  // Removes the files from oldest to newest until a maximum limit of files
  // allowed remains on disk. It's expected that at most one file is deleted
  // in this function.
  void CleanupPolicyFiles(
      const std::map<int, base::FilePath>& sorted_policy_file_paths);

  void ReportInvalidDevicePolicyFilesStatus(int number_of_good_files,
                                            int number_of_invalid_files);

  LoginMetrics* metrics_ = nullptr;  //  Not owned.
  std::unique_ptr<policy::DevicePolicyImpl> device_policy_;
};
}  // namespace login_manager

#endif  // LOGIN_MANAGER_RESILIENT_POLICY_STORE_H_
