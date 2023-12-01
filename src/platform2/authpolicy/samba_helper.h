// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AUTHPOLICY_SAMBA_HELPER_H_
#define AUTHPOLICY_SAMBA_HELPER_H_

#include <string>
#include <vector>

#include <base/time/time.h>

namespace authpolicy {

class Anonymizer;

// Number of code points in randomly generated machine passwords.
constexpr size_t kMachinePasswordCodePoints = 32;

// By default, change the machine password every 30 days.
constexpr base::TimeDelta kDefaultMachinePasswordChangeRate = base::Days(30);

// Group policy flags.
const int kGpFlagAllEnabled = 0x00;
const int kGpFlagUserDisabled = 0x01;
const int kGpFlagMachineDisabled = 0x02;
const int kGpFlagAllDisabled = 0x03;
const int kGpFlagCount = 0x04;
const int kGpFlagInvalid = 0x04;

extern const char* const kGpFlagsStr[];

// Params for net and smbclient.
extern const char kKerberosParam[];
extern const char kConfigParam[];
extern const char kDebugParam[];
extern const char kCommandParam[];
extern const char kUserParam[];
extern const char kMachinepassStdinParam[];
extern const char kCreatecomputerParam[];
extern const char kOsNameParam[];
extern const char kOsVersionParam[];
extern const char kOsServicePackParam[];

// Params for kinit.
extern const char kUseKeytabParam[];
extern const char kValidityLifetimeParam[];
extern const char kRenewalLifetimeParam[];
extern const char kRenewParam[];

// Params for klist.
extern const char kSetExitStatusParam[];
extern const char kCredentialCacheParam[];

// Kerberos encryption types strings for the Kerberos configuration.
extern const char kEncTypesAll[];
extern const char kEncTypesStrong[];
extern const char kEncTypesLegacy[];

// Marker for user affiliation (whether the device domain trusts the user
// domain). This marker is added to PolicyData.device_affiliation_ids for device
// policy. For user policy, it is added if and only if
// SambaInterface::IsUserAffiliated indicates that the user is affiliated.
extern const char kAffiliationMarker[];

// Parses user_name@some.realm into its components and normalizes (uppercases)
// the part behind the @. |user_name| is 'user_name', |realm| is |SOME.REALM|
// and |normalized_user_principal_name| is user_name@SOME.REALM.
bool ParseUserPrincipalName(const std::string& user_principal_name,
                            std::string* user_name,
                            std::string* realm,
                            std::string* normalized_user_principal_name);

// Parses the given |in_str| consisting of individual lines for
//   ... \n
//   |token| <token_separator> |result| \n
//   ... \n
// and returns the first non-empty |result|. Whitespace is trimmed.
bool FindToken(const std::string& in_str,
               char token_separator,
               const std::string& token,
               std::string* result);

// Returns true if the given one-line string |in_line| has the form
//   |token| <token_separator> |result|
// and returns |result|. Whitespace is trimmed.
bool FindTokenInLine(const std::string& in_line,
                     char token_separator,
                     const std::string& token,
                     std::string* result);

// Parses a GPO version string, which consists of a number and the same number
// as base-16 hex number, e.g. '31 (0x0000001f)'.
bool ParseGpoVersion(const std::string& str, uint32_t* version);

// Parses a group policy flags string, which consists of a number 0-3 and a
// descriptive name. See |kGpFlag*| for possible values.
bool ParseGpFlags(const std::string& str, int* gp_flags);

// Returns true if the string contains the given substring.
bool Contains(const std::string& str, const std::string& substr);

// Converts a valid GUID (see base::Uuid) to an octet string, see e.g.
// http://stackoverflow.com/questions/1545630/searching-for-a-objectguid-in-ad.
// Returns an empty string on error.
std::string GuidToOctetString(const std::string& guid);

// Converts an octet string to a GUID. Inverse of GuidToOctetString(). Only for
// testing! Just performs basic size checks, no strict format checks. Returns an
// empty string on error.
std::string OctetStringToGuidForTesting(const std::string& octet_str);

// Converts an |account_id| (aka objectGUID) to an account_id_key by adding a
// prefix |kActiveDirectoryPrefix|.
std::string GetAccountIdKey(const std::string& account_id);

// Logs |str| to INFO, prepending |header|. Splits |str| into lines and logs the
// lines. This works around a restriction of syslog of 8kb per log and fixes
// unreadable logs where \n is replaced by #012. Anonymizes logs with
// |anonymizer| to remove sensitive data. |color| is a color from log_colors.h.
void LogLongString(const char* color,
                   const std::string& header,
                   const std::string& str,
                   Anonymizer* anonymizer);

// Builds a distinguished name from a vector of |organizational_units|, ordered
// leaf-to-root, and a DNS |domain| name. Returns a combined string
// 'ou=ouLeaf,...,ou=ouRoot,dc="example",dc="com"'. Makes sure the result is
// properly escaped..
std::string BuildDistinguishedName(
    const std::vector<std::string>& organizational_units,
    const std::string& domain);

// Generates a random password that can be used for Active Directory machine
// accounts. It is UTF-8 encoded with |kMachinePasswordCodePoints| code points.
// Since Kerberos code cannot handle higher code points, all code points are
// below or equal to 0xFFFF. Excludes
//  - invalid code points,
//  - '\0', so that the string can be safely converted to and from char*, and
//  - '\n', so that the password can be read from stdin.
// The runtime is not deterministic, but the average runtime is
// O(kMachinePasswordCodePoints).
std::string GenerateRandomMachinePassword();

using RandomBytesGenerator = void(void* bytes, size_t length);
void SetRandomNumberGeneratorForTesting(RandomBytesGenerator* rand_bytes);

// Returns the OS name from the lsb-release file or an empty string on error.
std::string GetOsName();

// Returns the OS version from the lsb-release file or an empty string on error.
std::string GetOsVersion();

}  // namespace authpolicy

#endif  // AUTHPOLICY_SAMBA_HELPER_H_
