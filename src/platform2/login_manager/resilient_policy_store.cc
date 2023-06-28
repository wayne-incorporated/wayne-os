// Copyright 2018 The Chromium OS Authors. All rights reserved.
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
#include <policy/policy_util.h>
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
    : PolicyStore(policy_path), metrics_(metrics) {}

bool ResilientPolicyStore::LoadOrCreate() {
  DCHECK(metrics_);
  std::map<int, base::FilePath> sorted_policy_file_paths =
      policy::GetSortedResilientPolicyFilePaths(policy_path_);
  if (sorted_policy_file_paths.empty())
    return true;

  // Try to load the existent policy files one by one in reverse order of their
  // index until we succeed. The files that fail to be parsed are deleted.
  int number_of_invalid_files = 0;
  bool policy_loaded = false;
  for (const auto& map_pair : base::Reversed(sorted_policy_file_paths)) {
    const base::FilePath& policy_path = map_pair.second;
    if (LoadOrCreateFromPath(policy_path)) {
      policy_loaded = true;
      break;
    }
    number_of_invalid_files++;
    base::DeleteFile(policy_path);
  }

  if (number_of_invalid_files > 0) {
    // If at least one policy file has been deleted, we need to delete the
    // |kCleanupDoneFileName| to make sure the next persist doesn't overwrite
    // the data in a good file saved in a previous session.
    base::DeleteFile(GetCleanupDoneFilePath(policy_path_));
  }

  ReportInvalidDevicePolicyFilesStatus(
      sorted_policy_file_paths.size() - number_of_invalid_files,
      number_of_invalid_files);

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

bool ResilientPolicyStore::Delete() {
  NOTREACHED();
  return false;
}

void ResilientPolicyStore::CleanupPolicyFiles(
    const std::map<int, base::FilePath>& sorted_policy_file_paths) {
  DCHECK(metrics_);
  int number_of_good_files = 0;
  int number_of_invalid_files = 0;
  // Allow one less file, since we need room for the new file to be persisted
  // after cleanup.
  const int max_allowed_files = kMaxPolicyFileCount - 1;
  for (const auto& map_pair : base::Reversed(sorted_policy_file_paths)) {
    const base::FilePath& policy_path = map_pair.second;
    if (number_of_good_files >= max_allowed_files) {
      base::DeleteFile(policy_path);
      continue;
    }

    std::string polstr;
    enterprise_management::PolicyFetchResponse policy;
    policy::LoadPolicyResult result =
        policy::LoadPolicyFromPath(policy_path, &polstr, &policy);
    switch (result) {
      case policy::LoadPolicyResult::kSuccess:
        number_of_good_files++;
        break;
      case policy::LoadPolicyResult::kFileNotFound:
        break;
      case policy::LoadPolicyResult::kFailedToReadFile:
      case policy::LoadPolicyResult::kEmptyFile:
      case policy::LoadPolicyResult::kInvalidPolicyData:
        number_of_invalid_files++;
        base::DeleteFile(policy_path);
        break;
    }
  }

  ReportInvalidDevicePolicyFilesStatus(number_of_good_files,
                                       number_of_invalid_files);
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
