// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <vector>

#include "policy/device_local_account_policy_util.h"

#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>

namespace em = enterprise_management;

namespace policy {

std::string CanonicalizeEmail(const std::string& email_address) {
  std::string lower_case_email = base::ToLowerASCII(email_address);
  std::vector<std::string> parts = base::SplitString(
      lower_case_email, "@", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  if (parts.size() != 2U)
    return lower_case_email;

  if (parts[1] == "gmail.com")  // only strip '.' for gmail accounts.
    base::RemoveChars(parts[0], ".", &parts[0]);

  std::string new_email = base::JoinString(parts, "@");
  return new_email;
}

std::string GenerateDeviceLocalAccountUserId(
    const std::string& account_id,
    em::DeviceLocalAccountInfoProto_AccountType type) {
  std::string domain_prefix;
  switch (type) {
    case em::DeviceLocalAccountInfoProto::ACCOUNT_TYPE_PUBLIC_SESSION:
      domain_prefix = "public-accounts";
      break;
    case em::DeviceLocalAccountInfoProto::ACCOUNT_TYPE_KIOSK_APP:
      domain_prefix = "kiosk-apps";
      break;
    case em::DeviceLocalAccountInfoProto::ACCOUNT_TYPE_KIOSK_ANDROID_APP:
      domain_prefix = "arc-kiosk-apps";
      break;
    case em::DeviceLocalAccountInfoProto::ACCOUNT_TYPE_SAML_PUBLIC_SESSION:
      domain_prefix = "saml-public-accounts";
      break;
    case em::DeviceLocalAccountInfoProto::ACCOUNT_TYPE_WEB_KIOSK_APP:
      domain_prefix = "web-kiosk-apps";
      break;
  }

  return CanonicalizeEmail(
      base::HexEncode(account_id.c_str(), account_id.size()) + "@" +
      domain_prefix + ".device-local.localhost");
}

}  // namespace policy
