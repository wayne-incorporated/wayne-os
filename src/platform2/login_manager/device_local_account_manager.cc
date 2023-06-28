// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/device_local_account_manager.h"

#include <utility>

#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/strings/string_util.h>
#include <brillo/cryptohome.h>

#include "bindings/chrome_device_policy.pb.h"
#include "login_manager/policy_service.h"
#include "login_manager/policy_store.h"

namespace em = enterprise_management;

namespace login_manager {

// Device-local account state directory.
constexpr char DeviceLocalAccountManager::kPolicyDir[] = "policy";

DeviceLocalAccountManager::DeviceLocalAccountManager(
    const base::FilePath& state_dir, PolicyKey* owner_key)
    : state_dir_(state_dir), owner_key_(owner_key) {}

DeviceLocalAccountManager::~DeviceLocalAccountManager() = default;

void DeviceLocalAccountManager::UpdateDeviceSettings(
    const em::ChromeDeviceSettingsProto& device_settings) {
  // Update the policy map.
  typedef google::protobuf::RepeatedPtrField<em::DeviceLocalAccountInfoProto>
      DeviceLocalAccountList;
  std::map<std::string, std::unique_ptr<PolicyService>> new_policy_map;
  const DeviceLocalAccountList& list(
      device_settings.device_local_accounts().account());
  for (DeviceLocalAccountList::const_iterator account(list.begin());
       account != list.end(); ++account) {
    std::string account_key;
    if (account->has_account_id()) {
      account_key = GetAccountKey(account->account_id());
    } else if (!account->has_type() &&
               account->has_deprecated_public_session_id()) {
      account_key = GetAccountKey(account->deprecated_public_session_id());
    }
    if (!account_key.empty()) {
      new_policy_map[account_key] = std::move(policy_map_[account_key]);
    }
  }
  policy_map_.swap(new_policy_map);

  MigrateUppercaseDirs();

  // Purge all existing on-disk accounts that are no longer defined.
  base::FileEnumerator enumerator(state_dir_, false,
                                  base::FileEnumerator::DIRECTORIES);
  base::FilePath subdir;
  while (!(subdir = enumerator.Next()).empty()) {
    if (IsValidAccountKey(subdir.BaseName().value()) &&
        policy_map_.find(subdir.BaseName().value()) == policy_map_.end()) {
      LOG(INFO) << "Purging " << subdir.value();
      if (!base::DeletePathRecursively(subdir))
        LOG(ERROR) << "Failed to delete " << subdir.value();
    }
  }
}

bool DeviceLocalAccountManager::MigrateUppercaseDirs() {
  base::FileEnumerator enumerator(state_dir_, false,
                                  base::FileEnumerator::DIRECTORIES);
  base::FilePath subdir;

  while (!(subdir = enumerator.Next()).empty()) {
    std::string upper = subdir.BaseName().value();
    std::string lower = base::ToLowerASCII(upper);
    if (IsValidAccountKey(lower) && lower != upper) {
      base::FilePath subdir_to(subdir.DirName().Append(lower));
      LOG(INFO) << "Migrating " << upper << " to " << lower;
      if (!base::ReplaceFile(subdir, subdir_to, nullptr))
        LOG(ERROR) << "Failed to migrate " << subdir.value();
    }
  }

  return true;
}

PolicyService* DeviceLocalAccountManager::GetPolicyService(
    const std::string& account_id) {
  const std::string key = GetAccountKey(account_id);
  auto entry = policy_map_.find(key);
  if (entry == policy_map_.end())
    return nullptr;

  // Lazily create and initialize the policy service instance.
  if (!entry->second) {
    const base::FilePath policy_dir =
        state_dir_.AppendASCII(key).Append(kPolicyDir);
    if (!base::CreateDirectory(policy_dir)) {
      LOG(ERROR) << "Failed to create device-local account policy directory "
                 << policy_dir.value();
      return nullptr;
    }

    entry->second =
        std::make_unique<PolicyService>(policy_dir, owner_key_, nullptr, false);
  }

  return entry->second.get();
}

void DeviceLocalAccountManager::PersistAllPolicy() {
  for (const auto& kv : policy_map_) {
    if (kv.second)
      kv.second->PersistAllPolicy();
  }
}

std::string DeviceLocalAccountManager::GetAccountKey(
    const std::string& account_id) {
  return brillo::cryptohome::home::SanitizeUserName(account_id);
}

bool DeviceLocalAccountManager::IsValidAccountKey(const std::string& str) {
  return brillo::cryptohome::home::IsSanitizedUserName(str);
}

}  // namespace login_manager
