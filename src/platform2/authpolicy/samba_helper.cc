// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "authpolicy/samba_helper.h"

#include <cstring>
#include <iterator>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/utf_string_conversion_utils.h>
#include <base/system/sys_info.h>
#include <base/uuid.h>
#include <crypto/random.h>

#include "authpolicy/anonymizer.h"
#include "authpolicy/log_colors.h"

namespace {

// Map GUID position to octet position for each byte xx.
// The bytes of the first 3 groups have to be reversed.
// GUID:
//   |0    |6 |9|1114|1619|21|24       |34
//   xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
// Octet:
//    |1       |10|13|16|19|22|25|28|31            |46
//   \XX\XX\XX\XX\XX\XX\XX\XX\XX\XX\XX\XX\XX\XX\XX\XX
// clang-format off
const int octet_pos_map[16][2] = {  // Maps GUID position to octet position.
  {0, 10}, {2, 7}, {4, 4}, {6, 1},  // First group, reversed byte order.
  {9, 16}, {11, 13},                // Second group, reversed byte order.
  {14, 22}, {16, 19},               // Third group, reversed byte order.
  {19, 25}, {21, 28},               // Fourth group, same byte order.
  {24, 31}, {26, 34}, {28, 37}, {30, 40}, {32, 43}, {34, 46}};  // Last group.
// clang-format on

const size_t kGuidSize = 36;   // 16 bytes, xx each byte, plus 4 '-'.
const size_t kOctetSize = 48;  // 16 bytes, \XX each byte.

// How many random code points are generated at a time during random password
// generation. Password lentgh + some more for skipped code points.
const size_t kRandCodePointsCount = 48;

constexpr char kAttributeValueEscapedCharacters[] = ",+\"\\<>;\r\n=/";

constexpr char kLsbReleaseName[] = "CHROMEOS_RELEASE_NAME";
constexpr char kLsbReleaseMilestone[] = "CHROMEOS_RELEASE_CHROME_MILESTONE";
constexpr char kLsbReleaseBuild[] = "CHROMEOS_RELEASE_BUILD_NUMBER";
constexpr char kLsbReleaseBranch[] = "CHROMEOS_RELEASE_BRANCH_NUMBER";
constexpr char kLsbReleasePatch[] = "CHROMEOS_RELEASE_PATCH_NUMBER";

// Escapes a relative distinguished name attribute value according to
// https://msdn.microsoft.com/en-us/library/aa366101(v=vs.85).aspx.
std::string EscapeAttributeValue(const std::string& value) {
  std::string escaped_value;
  for (size_t n = 0; n < value.size(); ++n) {
    // Escape
    //   - ' ' and # at the beginning,
    //   - ' ' at the end and
    //   - all characters in kAttributeValueEscapedCharacters.
    const bool should_escape =
        (n == 0 && (value[n] == ' ' || value[n] == '#')) ||
        (n + 1 == value.size() && value[n] == ' ') ||
        strchr(kAttributeValueEscapedCharacters, value[n]) != nullptr;
    if (should_escape)
      escaped_value += '\\';
    escaped_value += value[n];
  }
  return escaped_value;
}

}  // namespace

namespace authpolicy {

// Prefix for Active Directory account ids. A prefixed |account_id| is usually
// called |account_id_key|. Must match Chromium AccountId::kKeyAdIdPrefix.
const char kActiveDirectoryPrefix[] = "a-";

// Flags for parsing GPO.
const char* const kGpFlagsStr[] = {
    "0 GPFLAGS_ALL_ENABLED",
    "1 GPFLAGS_USER_SETTINGS_DISABLED",
    "2 GPFLAGS_MACHINE_SETTINGS_DISABLED",
    "3 GPFLAGS_ALL_DISABLED",
};

constexpr char kKerberosParam[] = "--use-kerberos=required";
constexpr char kConfigParam[] = "--configfile";
constexpr char kDebugParam[] = "--debuglevel";
constexpr char kCommandParam[] = "--command";
constexpr char kUserParam[] = "-U";
constexpr char kMachinepassStdinParam[] = "machinepassStdin";
constexpr char kCreatecomputerParam[] = "createcomputer=";
constexpr char kOsNameParam[] = "osName=";
constexpr char kOsVersionParam[] = "osVer=";
constexpr char kOsServicePackParam[] = "osServicePack=None";

constexpr char kUseKeytabParam[] = "-k";
constexpr char kValidityLifetimeParam[] = "-l";
constexpr char kRenewalLifetimeParam[] = "-r";
constexpr char kRenewParam[] = "-R";

constexpr char kSetExitStatusParam[] = "-s";
constexpr char kCredentialCacheParam[] = "-c";

constexpr char kEncTypesAll[] = "all";
constexpr char kEncTypesStrong[] = "strong";
constexpr char kEncTypesLegacy[] = "legacy";

constexpr char kAffiliationMarker[] = "ad_affiliation_marker";

// Random number generator, used for testing purposes.
RandomBytesGenerator* g_rand_bytes = nullptr;

bool ParseUserPrincipalName(const std::string& user_principal_name,
                            std::string* user_name,
                            std::string* realm,
                            std::string* normalized_user_principal_name) {
  std::vector<std::string> parts = base::SplitString(
      user_principal_name, "@", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  if (parts.size() != 2 || parts.at(0).empty() || parts.at(1).empty()) {
    // Don't log user_principal_name, it might contain sensitive data.
    LOG(ERROR) << "Failed to parse user principal name. Expected form "
                  "'user@some.realm'.";
    return false;
  }
  *user_name = parts.at(0);
  *realm = base::ToUpperASCII(parts.at(1));
  *normalized_user_principal_name = *user_name + "@" + *realm;
  return true;
}

bool FindToken(const std::string& in_str,
               char token_separator,
               const std::string& token,
               std::string* result) {
  std::vector<std::string> lines = base::SplitString(
      in_str, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  for (const std::string& line : lines) {
    if (FindTokenInLine(line, token_separator, token, result))
      return true;
  }

  // Don't log in_str, it might contain sensitive data.
  LOG(ERROR) << "Failed to find '" << token << "' in string";
  return false;
}

bool FindTokenInLine(const std::string& in_line,
                     char token_separator,
                     const std::string& token,
                     std::string* result) {
  size_t sep_pos = in_line.find(token_separator);
  if (sep_pos == std::string::npos)
    return false;

  std::string line_token;
  base::TrimWhitespaceASCII(in_line.substr(0, sep_pos), base::TRIM_ALL,
                            &line_token);
  if (line_token != token)
    return false;

  base::TrimWhitespaceASCII(in_line.substr(sep_pos + 1), base::TRIM_ALL,
                            result);
  return !result->empty();
}

bool ParseGpoVersion(const std::string& str, uint32_t* version) {
  DCHECK(version);
  *version = 0;
  uint32_t version_hex = 0;
  if (sscanf(str.c_str(), "%u (0x%08x)", version, &version_hex) != 2 ||
      *version != version_hex)
    return false;

  return true;
}

bool ParseGpFlags(const std::string& str, int* gp_flags) {
  for (int flag = 0; flag < static_cast<int>(std::size(kGpFlagsStr)); ++flag) {
    if (str == kGpFlagsStr[flag]) {
      *gp_flags = flag;
      return true;
    }
  }
  return false;
}

bool Contains(const std::string& str, const std::string& substr) {
  return str.find(substr) != std::string::npos;
}

std::string GuidToOctetString(const std::string& guid) {
  std::string octet_str;
  if (!base::Uuid::ParseCaseInsensitive(guid).is_valid())
    return octet_str;
  DCHECK_EQ(kGuidSize, guid.size());

  octet_str.assign(kOctetSize, '\\');
  for (const auto& pos : octet_pos_map) {
    for (int hex_digit = 0; hex_digit < 2; ++hex_digit) {
      octet_str.at(pos[1] + hex_digit) = toupper(guid.at(pos[0] + hex_digit));
    }
  }

  return octet_str;
}

std::string OctetStringToGuidForTesting(const std::string& octet_str) {
  std::string guid;
  if (octet_str.size() != kOctetSize)
    return guid;

  guid.assign(kGuidSize, '-');
  for (const auto& pos : octet_pos_map) {
    for (int hex_digit = 0; hex_digit < 2; ++hex_digit) {
      guid.at(pos[0] + hex_digit) = tolower(octet_str.at(pos[1] + hex_digit));
    }
  }
  return guid;
}

std::string GetAccountIdKey(const std::string& account_id) {
  return kActiveDirectoryPrefix + account_id;
}

void LogLongString(const char* color,
                   const std::string& header,
                   const std::string& str,
                   Anonymizer* anonymizer) {
  if (!LOG_IS_ON(INFO))
    return;

  std::string anonymized_str = anonymizer->Process(str);
  std::vector<std::string> lines = base::SplitString(
      anonymized_str, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  if (lines.size() <= 1) {
    LOG(INFO) << color << header << anonymized_str << kColorReset;
  } else {
    LOG(INFO) << color << header << kColorReset;
    for (const std::string& line : lines)
      LOG(INFO) << color << "  " << line << kColorReset;
  }
}

std::string BuildDistinguishedName(
    const std::vector<std::string>& organizational_units,
    const std::string& domain) {
  std::string distinguished_name;

  for (const std::string& ou : organizational_units) {
    if (distinguished_name.size() > 0)
      distinguished_name += ",";
    distinguished_name += "ou=" + EscapeAttributeValue(ou);
  }

  std::vector<std::string> dc_parts = base::SplitString(
      domain, ".", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
  for (const std::string& dc : dc_parts) {
    if (distinguished_name.size() > 0)
      distinguished_name += ",";
    distinguished_name += "dc=" + EscapeAttributeValue(dc);
  }

  return distinguished_name;
}

std::string GenerateRandomMachinePassword() {
  // Each code point uses at most 3 bytes (and 3 is actually most likely), so
  // this is a good upper bound.
  std::string random_password;
  random_password.reserve(kMachinePasswordCodePoints * 3);

  // Since invalid code points and zero should be ignored, we cannot simply fill
  // a wchar_t string with random bytes and convert to UTF-8. Instead, throw
  // away bad code points (don't just map to valid code points (e.g. 0->1) as
  // this would create a bias).
  size_t code_point_count = 0;
  uint16_t rand_code_points[kRandCodePointsCount];
  for (;;) {
    // g_rand_bytes is only set for testing.
    if (g_rand_bytes)
      g_rand_bytes(rand_code_points, sizeof(rand_code_points));
    else
      crypto::RandBytes(rand_code_points, sizeof(rand_code_points));

    for (uint16_t code_point : rand_code_points) {
      // Discard bad code points.
      if (code_point == 0 || code_point == '\n' ||
          !base::IsValidCodepoint(code_point))
        continue;

      base::WriteUnicodeCharacter(code_point, &random_password);
      if (++code_point_count >= kMachinePasswordCodePoints)
        return random_password;
    }
  }
}

void SetRandomNumberGeneratorForTesting(RandomBytesGenerator* rand_bytes) {
  g_rand_bytes = rand_bytes;
}

std::string GetOsName() {
  std::string os_name;
  if (!base::SysInfo::GetLsbReleaseValue(kLsbReleaseName, &os_name)) {
    LOG(ERROR) << "Cannot determine OS name: Field '" << kLsbReleaseName
               << "' missing from /etc/lsb-release";
    return std::string();
  }
  return os_name;
}

std::string GetOsVersion() {
  std::string milestone, build, branch, patch;
  if (!base::SysInfo::GetLsbReleaseValue(kLsbReleaseMilestone, &milestone) ||
      !base::SysInfo::GetLsbReleaseValue(kLsbReleaseBuild, &build) ||
      !base::SysInfo::GetLsbReleaseValue(kLsbReleaseBranch, &branch) ||
      !base::SysInfo::GetLsbReleaseValue(kLsbReleasePatch, &patch)) {
    LOG(ERROR)
        << "Cannot determine OS version: Field missing from /etc/lsb-release";
    return std::string();
  }

  const std::vector<std::string> parts = {milestone, build, branch, patch};
  return base::JoinString(parts, ".");
}

}  // namespace authpolicy
