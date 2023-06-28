// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_DEVICE_LOCAL_ACCOUNT_MANAGER_H_
#define LOGIN_MANAGER_DEVICE_LOCAL_ACCOUNT_MANAGER_H_

#include <stdint.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/macros.h>
#include <base/memory/ref_counted.h>
#include <gtest/gtest_prod.h>

namespace enterprise_management {
class ChromeDeviceSettingsProto;
}

namespace login_manager {

class PolicyKey;
class PolicyService;

// Manages policy services for device-local accounts. Restricts access to
// accounts defined in device settings.
class DeviceLocalAccountManager {
 public:
  // Name of the subdirectory to store policy in.
  static const char kPolicyDir[];

  DeviceLocalAccountManager(const base::FilePath& state_dir,
                            PolicyKey* owner_key);
  DeviceLocalAccountManager(const DeviceLocalAccountManager&) = delete;
  DeviceLocalAccountManager& operator=(const DeviceLocalAccountManager&) =
      delete;

  ~DeviceLocalAccountManager();

  // Updates device settings, i.e. what device-local accounts are available.
  // This will purge any on-disk state for accounts that are no longer defined
  // in device settings. Later requests to Load() and Store() will respect the
  // new list of device-local accounts and fail for accounts that are not
  // present.
  void UpdateDeviceSettings(
      const enterprise_management::ChromeDeviceSettingsProto& device_settings);

  // Obtains the PolicyService instance that manages disk storage for
  // |account_id| after checking that |account_id| is valid. The PolicyService
  // is lazily created on the fly if not present yet.
  PolicyService* GetPolicyService(const std::string& account_id);

  // Persists policy for accounts and namespaces.
  void PersistAllPolicy();

 private:
  // Migrate uppercase local-account directories to their lowercase variants.
  // This is to repair the damage caused by http://crbug.com/225472.
  bool MigrateUppercaseDirs();

  // Returns the identifier for a given |account_id|. The value returned is safe
  // to use as a file system name. This may fail, in which case the returned
  // string will be empty.
  std::string GetAccountKey(const std::string& account_id);

  // Checks whether the passed string is a properly formatted account key.
  bool IsValidAccountKey(const std::string& str);

  // The base path for storing device-local account information on disk.
  base::FilePath state_dir_;

  // The policy key to verify signatures against.
  PolicyKey* owner_key_;

  // Keeps lazily-created instances of the device-local account policy services.
  // The keys present in this map are kept in sync with device policy. Entries
  // that are not present are invalid, entries that contain a nullptr indicate
  // the respective policy blob hasn't been pulled from disk yet.
  std::map<std::string, std::unique_ptr<PolicyService>> policy_map_;

  FRIEND_TEST(DeviceLocalAccountManagerTest, MigrateUppercaseDirs);
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_DEVICE_LOCAL_ACCOUNT_MANAGER_H_
