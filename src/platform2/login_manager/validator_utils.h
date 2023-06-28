// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_VALIDATOR_UTILS_H_
#define LOGIN_MANAGER_VALIDATOR_UTILS_H_

#include <string>

namespace login_manager {

class PolicyDescriptor;

// Determines what a PolicyDescriptor is used for, i.e. for storing or
// retrieving policy.
enum class PolicyDescriptorUsage {
  kStore,
  kRetrieve,
  kList,
};

// Performs very, very basic validation of |email_address|.
bool ValidateEmail(const std::string& email_address);

// Checks if string looks like a valid account ID key (as returned by
// AccountId::GetAccountIdKey()).
bool ValidateAccountIdKey(const std::string& account_id);

// Verifies that |id| is a Chrome extension ID. Pretty much copied from
// components/crx_file/id_util.cc.
bool ValidateExtensionId(const std::string& id);

// Returns true if |account_id| is a guest or demo account.
bool IsIncognitoAccountId(const std::string& account_id);

// Verifies that |account_id| is either an incognito account, a valid account ID
// key or a legacy email address. On success, |normalized_account_id| is set to
// a normalized version of |account_id|. Can be nullptr if not needed.
// TODO(alemate): remove the legacy email address part after ChromeOS will stop
// using email as cryptohome identifier.
bool ValidateAccountId(const std::string& account_id,
                       std::string* normalized_account_id);

// Verifies that |descriptor| is a valid PolicyDescriptor:
//   - Enums have valid values.
//   - account_id() should be set except for ACCOUNT_TYPE_DEVICE.
//   - component_id() should be set and valid except for POLICY_DOMAIN_CHROME.
// |usage| is used for the following:
//   - ACCOUNT_TYPE_SESSIONLESS_USER is only allowed for
//     PolicyDescriptorUsage::kRetrieve.
//   - Domain must not be POLICY_DOMAIN_CHROME and component_id() must be empty
//     for PolicyDescriptorUsage::kList.
bool ValidatePolicyDescriptor(const PolicyDescriptor& descriptor,
                              PolicyDescriptorUsage usage);

}  // namespace login_manager

#endif  // LOGIN_MANAGER_VALIDATOR_UTILS_H_
