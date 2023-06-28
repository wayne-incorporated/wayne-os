// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_RESILIENT_POLICY_STORE_H_
#define LOGIN_MANAGER_RESILIENT_POLICY_STORE_H_

#include "login_manager/policy_store.h"

#include <map>

#include <base/files/file_path.h>

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

  // Not implemented yet - this class is meant for Chrome device policy,
  // but deletion is only allowed for component policy.
  bool Delete() override;

  bool resilient_for_testing() const override { return true; }

 private:
  // Check the policy files from the most recent to the oldest until a valid
  // file is found. Loads the signed policy off of the valid file into
  // |policy_|. Logs UMA stats about the number of invalid policy files
  // identified. Returns true unless there is at least one policy file on disk
  // and loading fails for all the policy files present.
  bool LoadOrCreate() override;

  // Read and validate the policy files corresponding to names from
  // |sorted_policy_file_names|. Keeps at most |kMaxPolicyFileCount| valid
  // policy files, the rest gets deleted. Logs UMA stats about the number of
  // invalid policy files identified.
  void CleanupPolicyFiles(
      const std::map<int, base::FilePath>& sorted_policy_file_paths);

  void ReportInvalidDevicePolicyFilesStatus(int number_of_good_files,
                                            int number_of_invalid_files);

  LoginMetrics* metrics_ = nullptr;  //  Not owned.
};
}  // namespace login_manager

#endif  // LOGIN_MANAGER_RESILIENT_POLICY_STORE_H_
