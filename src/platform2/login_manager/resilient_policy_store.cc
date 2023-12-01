// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/resilient_policy_store.h"

#include <algorithm>
#include <string>

#include <base/check.h>
#include <base/containers/adapters.h>
#include <base/files/file_util.h>
#include <base/hash/sha1.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/files/file_util.h>
#include <policy/policy_util.h>
#include <policy/device_policy_impl.h>
#include <policy/resilient_policy_util.h>

#include "login_manager/login_metrics.h"
#include "login_manager/system_utils_impl.h"

namespace login_manager {

namespace {

// The path of temporary file to be saved when policy cleanup is done. The path
// is extended with policy path hash as suffix. The file is stored on tmpfs, so
// it is intentionally lost on each shutdown/restart of the device.
const char kCleanupDoneFilePrefix[] =
    "/run/session_manager/policy_cleanup_done-";

// Maximum number of valid policy files to be kept by policy cleanup.
const int kMaxPolicyFileCount = 3;

// Returns the path to cleanup_done temporary file associated with
// |policy_path|.
base::FilePath GetCleanupDoneFilePath(const base::FilePath& policy_path) {
  const std::string policy_path_hash =
      base::SHA1HashString(policy_path.value());
  const std::string policy_path_hex =
      base::HexEncode(policy_path_hash.c_str(), policy_path_hash.size());
  const std::string cleanup_done_path(kCleanupDoneFilePrefix + policy_path_hex);
  return base::FilePath(cleanup_done_path);
}

// Checks if the cleanup_done temporary file associated with |policy_path|
// exists. If not present, creates it and returns true. Otherwise returns false.
bool CreateCleanupDoneFile(const base::FilePath& policy_path) {
  const base::FilePath cleanup_done_path = GetCleanupDoneFilePath(policy_path);
  if (!base::PathExists(cleanup_done_path)) {
    base::File file(cleanup_done_path,
                    base::File::FLAG_CREATE | base::File::FLAG_WRITE);
    return true;
  }

  return false;
}

}  // namespace

ResilientPolicyStore::ResilientPolicyStore(const base::FilePath& policy_path,
                                           LoginMetrics* metrics)
    : PolicyStore(policy_path, /*is_resilient=*/true), metrics_(metrics) {}

bool ResilientPolicyStore::LoadOrCreate() {
  DCHECK(metrics_);
  if (!device_policy_)
    device_policy_ = std::make_unique<policy::DevicePolicyImpl>();
  bool policy_loaded =
      device_policy_->LoadPolicy(/*delete_invalid_files=*/true);
  if (device_policy_->get_number_of_policy_files() == 0) {
    LOG(INFO) << "No device policy file present.";
    return true;
  }

  if (policy_loaded)
    policy_ = device_policy_->get_policy_fetch_response();
  else
    policy_.Clear();

  int number_of_invalid_files = device_policy_->get_number_of_invalid_files();
  ReportInvalidDevicePolicyFilesStatus(
      device_policy_->get_number_of_policy_files() - number_of_invalid_files,
      number_of_invalid_files);

  if (number_of_invalid_files > 0) {
    // If at least one policy file has been deleted, we need to delete the
    // |kCleanupDoneFileName| to make sure the next persist doesn't overwrite
    // the data in a good file saved in a previous session.
    brillo::DeleteFile(GetCleanupDoneFilePath(policy_path_));
  }

  return policy_loaded;
}

bool ResilientPolicyStore::Persist() {
  std::map<int, base::FilePath> sorted_policy_file_paths =
      policy::GetSortedResilientPolicyFilePaths(policy_path_);
  int new_index = sorted_policy_file_paths.empty()
                      ? 0
                      : sorted_policy_file_paths.rbegin()->first;

  // The policy file where the data will be persisted has to be the latest
  // that exists on disk (i.e. the highest index). But if it is the first
  // persist after boot, the policy has to be saved in a new file. In that
  // case the highest index present is incremented to have the new file with
  // higher index. We determine if it's the first persist after boot by the
  // absense of cleanup temporary file. The index is never reset as it is not
  // realistic to expect int overflow in non-devmode here.
  if (CreateCleanupDoneFile(policy_path_)) {
    CleanupPolicyFiles(sorted_policy_file_paths);
    new_index++;
  }
  // To be on the safe side, persist only in file with index >= 1.
  new_index = std::max(new_index, 1);

  return PersistToPath(
      policy::GetResilientPolicyFilePathForIndex(policy_path_, new_index));
}

void ResilientPolicyStore::CleanupPolicyFiles(
    const std::map<int, base::FilePath>& sorted_policy_file_paths) {
  int remaining_files = sorted_policy_file_paths.size();
  for (const auto& map_pair : sorted_policy_file_paths) {
    // Allow one less file, since we need room for the new file to be persisted
    // after cleanup.
    if (remaining_files < kMaxPolicyFileCount)
      break;

    const base::FilePath& policy_path = map_pair.second;
    brillo::DeleteFile(policy_path);
    LOG(INFO) << "Deleted old device policy file: " << policy_path.value();
    remaining_files--;
  }
}

void ResilientPolicyStore::ReportInvalidDevicePolicyFilesStatus(
    int number_of_good_files, int number_of_invalid_files) {
  if (number_of_invalid_files == 0) {
    metrics_->SendInvalidPolicyFilesStatus(
        LoginMetrics::InvalidDevicePolicyFilesStatus::ALL_VALID);
  } else if (number_of_good_files > 0) {
    metrics_->SendInvalidPolicyFilesStatus(
        LoginMetrics::InvalidDevicePolicyFilesStatus::SOME_INVALID);
  } else {
    metrics_->SendInvalidPolicyFilesStatus(
        LoginMetrics::InvalidDevicePolicyFilesStatus::ALL_INVALID);
  }
}

}  // namespace login_manager
