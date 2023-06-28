// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/validator_utils.h"

#include <base/compiler_specific.h>
#include <base/strings/string_util.h>
#include <brillo/cryptohome.h>

#include <login_manager/proto_bindings/policy_descriptor.pb.h>
#include <login_manager/session_manager_impl.h>

namespace {

// Magic user name strings.
constexpr char kDemoUser[] = "demouser@";

// Constants used in email validation.
constexpr char kEmailSeparator = '@';
constexpr char kEmailLegalCharacters[] =
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ".@1234567890!#$%&'*+-/=?^_`{|}~";

// Should match chromium AccountId::kKeyGaiaIdPrefix .
constexpr char kGaiaIdKeyPrefix[] = "g-";
// Should match chromium AccountId::kKeyAdIdPrefix .
constexpr char kActiveDirectoryPrefix[] = "a-";
constexpr char kAccountIdKeyLegalCharacters[] =
    "-0123456789"
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

}  // namespace

namespace login_manager {

bool ValidateAccountIdKey(const std::string& account_id) {
  if (account_id.find_first_not_of(kAccountIdKeyLegalCharacters) !=
      std::string::npos)
    return false;

  return base::StartsWith(account_id, kGaiaIdKeyPrefix,
                          base::CompareCase::SENSITIVE) ||
         base::StartsWith(account_id, kActiveDirectoryPrefix,
                          base::CompareCase::SENSITIVE);
}

bool ValidateEmail(const std::string& email_address) {
  if (email_address.find_first_not_of(kEmailLegalCharacters) !=
      std::string::npos) {
    return false;
  }

  size_t at = email_address.find(kEmailSeparator);
  // it has NO @.
  if (at == std::string::npos)
    return false;

  // it has more than one @.
  if (email_address.find(kEmailSeparator, at + 1) != std::string::npos)
    return false;

  return true;
}

bool ValidateExtensionId(const std::string& id) {
  if (id.size() != 32)
    return false;

  std::string temp = base::ToLowerASCII(id);
  for (size_t n = 0; n < id.size(); n++) {
    char ch = base::ToLowerASCII(id[n]);
    if (ch < 'a' || ch > 'p')
      return false;
  }

  return true;
}

bool IsIncognitoAccountId(const std::string& account_id) {
  using brillo::cryptohome::home::kGuestUserName;
  const std::string lower_case_id(base::ToLowerASCII(account_id));
  return lower_case_id == kGuestUserName || lower_case_id == kDemoUser;
}

bool ValidateAccountId(const std::string& account_id,
                       std::string* normalized_account_id) {
  if (IsIncognitoAccountId(account_id) || ValidateAccountIdKey(account_id)) {
    if (normalized_account_id)
      *normalized_account_id = account_id;
    return true;
  }

  // Support legacy email addresses.
  // TODO(alemate): remove this after ChromeOS will stop using email as
  // cryptohome identifier.
  if (ValidateEmail(account_id)) {
    if (normalized_account_id)
      *normalized_account_id = base::ToLowerASCII(account_id);
    return true;
  }

  if (normalized_account_id)
    normalized_account_id->clear();
  return false;
}

bool ValidatePolicyDescriptor(const PolicyDescriptor& descriptor,
                              PolicyDescriptorUsage usage) {
  if (!PolicyAccountType_IsValid(descriptor.account_type()))
    return false;

  switch (descriptor.account_type()) {
    case ACCOUNT_TYPE_DEVICE:
      if (!descriptor.account_id().empty())
        return false;
      break;

    case ACCOUNT_TYPE_SESSIONLESS_USER:
      // Can only retrieve policy for sessionless users, i.e. from login screen.
      if (usage != PolicyDescriptorUsage::kRetrieve)
        return false;
      FALLTHROUGH;
    case ACCOUNT_TYPE_USER:
      if (!ValidateAccountId(descriptor.account_id(), nullptr))
        return false;
      break;

    case ACCOUNT_TYPE_DEVICE_LOCAL_ACCOUNT:
      // Device local accounts are specified via policy, but don't have further
      // restrictions, so nothing to validate.
      if (descriptor.account_id().empty())
        return false;
      break;
  }

  if (!PolicyDomain_IsValid(descriptor.domain()))
    return false;

  switch (descriptor.domain()) {
    case POLICY_DOMAIN_CHROME:
      if (usage == PolicyDescriptorUsage::kList)
        return false;
      if (!descriptor.component_id().empty())
        return false;
      break;

    case POLICY_DOMAIN_EXTENSIONS:
    case POLICY_DOMAIN_SIGNIN_EXTENSIONS:
      if (usage == PolicyDescriptorUsage::kList) {
        if (!descriptor.component_id().empty())
          return false;
      } else {
        if (!ValidateExtensionId(descriptor.component_id()))
          return false;
      }
      break;
  }

  return true;
}

}  // namespace login_manager
