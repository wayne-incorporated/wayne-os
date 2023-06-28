// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/user_policy_service_factory.h"

#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <utility>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>

#include "brillo/cryptohome.h"

#include "login_manager/nss_util.h"
#include "login_manager/policy_key.h"
#include "login_manager/policy_store.h"
#include "login_manager/system_utils.h"
#include "login_manager/user_policy_service.h"

namespace em = enterprise_management;

namespace login_manager {

namespace {

// Daemon name we use for storing per-user data on the file system.
const char kDaemonName[] = "session_manager";
// Name of the subdirectory to store policy in.
const char kPolicyDir[] = "policy";
// Holds the public key for policy signing.
const char kPolicyKeyFile[] = "key";

// Directory that contains the public keys for user policy verification.
// These keys are duplicates from the key contained in the vault, so that the
// chrome process can read them; the authoritative version of the key is still
// the vault's.
const char kPolicyKeyCopyDir[] = "/run/user_policy";
// Name of the policy key files.
const char kPolicyKeyCopyFile[] = "policy.pub";

}  // namespace

UserPolicyServiceFactory::UserPolicyServiceFactory(NssUtil* nss,
                                                   SystemUtils* system_utils)
    : nss_(nss), system_utils_(system_utils) {}

UserPolicyServiceFactory::~UserPolicyServiceFactory() {}

std::unique_ptr<PolicyService> UserPolicyServiceFactory::Create(
    const std::string& username) {
  using brillo::cryptohome::home::GetDaemonStorePath;
  base::FilePath policy_dir(
      GetDaemonStorePath(username, kDaemonName).Append(kPolicyDir));
  if (!base::CreateDirectory(policy_dir)) {
    PLOG(ERROR) << "Failed to create user policy directory.";
    return nullptr;
  }

  return CreateInternal(username, policy_dir);
}

std::unique_ptr<PolicyService>
UserPolicyServiceFactory::CreateForHiddenUserHome(const std::string& username) {
  using brillo::cryptohome::home::GetDaemonPathForHiddenUserHome;
  base::FilePath policy_dir(
      GetDaemonPathForHiddenUserHome(username, kDaemonName).Append(kPolicyDir));
  return CreateInternal(username, policy_dir);
}

std::unique_ptr<PolicyService> UserPolicyServiceFactory::CreateInternal(
    const std::string& username, const base::FilePath& policy_dir) {
  auto key =
      std::make_unique<PolicyKey>(policy_dir.Append(kPolicyKeyFile), nss_);
  bool key_load_success = key->PopulateFromDiskIfPossible();
  if (!key_load_success) {
    LOG(ERROR) << "Failed to load user policy key from disk.";
    return nullptr;
  }

  using brillo::cryptohome::home::SanitizeUserName;
  const std::string sanitized(SanitizeUserName(username));
  const base::FilePath key_copy_file(base::StringPrintf(
      "%s/%s/%s", kPolicyKeyCopyDir, sanitized.c_str(), kPolicyKeyCopyFile));

  std::unique_ptr<UserPolicyService> service =
      std::make_unique<UserPolicyService>(policy_dir, std::move(key),
                                          key_copy_file, system_utils_);
  service->PersistKeyCopy();
  return service;
}

}  // namespace login_manager
