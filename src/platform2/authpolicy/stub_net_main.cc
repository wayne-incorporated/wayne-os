// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Stub implementation of Samba net. Does not talk to server, but simply returns
// fixed responses to predefined input.

#include <inttypes.h>
#include <string>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/strcat.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

#include "authpolicy/constants.h"
#include "authpolicy/platform_helper.h"
#include "authpolicy/samba_helper.h"
#include "authpolicy/stub_common.h"

namespace authpolicy {
namespace {

const char kSmbConfDevice[] = "smb_device.conf";
const char kSmbConfUser[] = "smb_user.conf";
const char kMachinePass[] = "machine_pass";
const char kStateDir[] = "state";
const char kSambaDir[] = "samba";
const char kKrb5CCUser[] = "krb5cc_user";

// Prefix for the fake domain sid marker file "fake_domain_sid_<workgroup>".
const char kFakeDomainSidMarkerPrefix[] = "fake_domain_sid_";

// Various stub error messages.
const char kSmbConfArgMissingError[] =
    "Can't load /etc/samba/smb.conf - run testparm to debug it";
const char kNetworkError[] = "No logon servers";
const char kWrongPasswordError[] =
    "Failed to join domain: failed to lookup DC info for domain "
    "'REALM.EXAMPLE.COM' over rpc: Logon failure";
const char kExpiredPasswordError[] =
    "Enter user@REALM.EXAMPLE.COM's password:\n"
    "Failed to join domain: failed to lookup DC info for domain "
    "'REALM.EXAMPLE.COM' over rpc: Must change password";
const char kJoinAccessDeniedError[] =
    "Failed to join domain: Failed to set account flags for machine account "
    "(NT_STATUS_ACCESS_DENIED)";
const char kMachineNameTooLongError[] =
    "Our netbios name can be at most %zd chars long, \"%s\" is %zd chars long\n"
    "Failed to join domain: The format of the specified computer name is "
    "invalid.";
const char kInvalidMachineNameError[] =
    "Failed to join domain: failed to join domain 'REALM.EXAMPLE.COM' over "
    "rpc: Improperly formed account name";
const char kInsufficientQuotaError[] =
    "Insufficient quota exists to complete the operation";
const char kEncTypeNotSupportedError[] =
    "Failed to join domain: failed to connect to AD: KDC has no support for "
    "encryption type";

// Size limit for machine name.
const size_t kMaxMachineNameSize = 15;

// Stub net ads info response.
const char kStubInfo[] = R"!!!(LDAP server: 111.222.33.1
LDAP server name: LDAPNAME.example.com
Realm: REALM.EXAMPLE.COM
Bind Path: dc=REALM,dc=EXAMPLE,dc=COM
LDAP port: 389
Server time: %s
KDC server: 111.222.33.2
Server time offset: -91
Last machine account password change:
Wed, 31 Dec 1969 16:00:00 PST)!!!";

constexpr char kDefaultServerTime[] = "Fri, 03 Feb 2017 05:24:05 PST";

// Stub net ads info response.
const char kStubLookup[] = R"!!!(Information for Domain Controller: 111.222.33.3
Response Type: LOGON_SAM_LOGON_RESPONSE_EX
GUID: fca78f31-bf15-4ca3-b730-fbe619e937b2
Flags:
    Is a PDC:                                   yes
    Is a GC of the forest:                      yes
    Is an LDAP server:                          yes
    Supports DS:                                yes
    Is running a KDC:                           yes
    Is running time services:                   yes
    Is the closest DC:                          no
    Is writable:                                yes
    Has a hardware clock:                       yes
    Is a non-domain NC serviced by LDAP server: no
    Is NT6 DC that has some secrets:            no
    Is NT6 DC that has all secrets:             yes
    Runs Active Directory Web Services:         yes
    Runs on Windows 2012 or later:              yes
Forest:             FOREST.EXAMPLE.COM
Domain:             REALM.EXAMPLE.COM
Domain Controller:  DCNAME.EXAMPLE.COM
Pre-Win2k Domain:   REALM
Pre-Win2k Hostname: DCNAME
Server Site Name :  SITE
Client Site Name :  SITE
NT Version: 5
LMNT Token: ffff
LM20 Token: ffff)!!!";

// Stub net ads gpo list response.
const char kStubLocalGpo[] = R"!!!(---------------------
name:   Local Policy
displayname:  Local Policy
version:  0 (0x00000000)
version_user:  0 (0x0000)
version_machine: 0 (0x0000)
filesyspath:  (null)
dspath:  (null)
options:  0 GPFLAGS_ALL_ENABLED
link:   (null)
link_type:  5 machine_extensions: (null)
user_extensions: (null)
)!!!";

const char kStubRemoteGpo[] = R"!!!(---------------------
name:   %s
displayname:  test-user-policy
version:  %u (0x%04x%04x)
version_user:  %u (0x%04x)
version_machine: %u (0x%04x)
filesyspath:  \\realm.example.com\SysVol\realm.example.com\Policies\%s
dspath:  cn=%s,cn=policies,cn=system,DC=realm,DC=example,DC=com
options:  %s
link:   OU=test-ou,DC=realm,DC=example,DC=com
link_type:  4 GP_LINK_OU
machine_extensions: (null)
user_extensions: [{D02B1F73-3407-48AE-BA88-E8213C6761F1}]
)!!!";

// Stub net ads search response.
const char kStubSearchFormat[] = R"!!!(Got 1 replies
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: %s
sn: Doe
givenName: %s
initials: JD
distinguishedName: CN=%s,OU=test-ou,DC=realm,DC=example,DC=com
instanceType: 4
whenCreated: 20161018155136.0Z
whenChanged: 20170217134227.0Z
displayName: %s
uSNCreated: 287406
uSNChanged: 307152
name: John Doe
objectGUID: %s
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 131309487458845506
lastLogoff: 0
lastLogon: 131320568639495686
primaryGroupID: 513
objectSid: S-1-5-21-250062649-3667841115-373469193-1134
accountExpires: 9223372036854775807
logonCount: 1453
sAMAccountName: %s
sAMAccountType: 805306368
userPrincipalName: jdoe@realm.example.com
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=realm,DC=example,DC=com
dSCorePropagationData: 20161024075536.0Z
dSCorePropagationData: 20161024075311.0Z
dSCorePropagationData: 20161019075502.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 131318125471489990
msDS-SupportedEncryptionTypes: 0)!!!";

// Password related fields in search response.
const char kStubSearchPwdFormat[] = R"!!!(
pwdLastSet: %)!!!" PRIu64 R"!!!(
userAccountControl: %)!!!" PRIu32;

// Search that doesn't find anything.
const char kStubBadSearch[] = "Got 0 replies";

// Builder for custom search results (without having a 7-line base::StringPrintf
// every time). Usage:
//   search_result = SearchBuilder().SetDisplayName("John Doe").GetResult();
class SearchBuilder {
 public:
  // Prints out a stub net ads search result with the set parameters.
  std::string GetResult() {
    std::string result = base::StringPrintf(
        kStubSearchFormat, common_name_.c_str(), given_name_.c_str(),
        common_name_.c_str(), display_name_.c_str(), object_guid_.c_str(),
        sam_account_name_.c_str());

    if (output_pwd_fields) {
      result += base::StringPrintf(kStubSearchPwdFormat, pwd_last_set_,
                                   user_account_control_);
    }

    return result;
  }

  // Sets the value of the givenName key.
  SearchBuilder& SetGivenName(const std::string& value) {
    given_name_ = value;
    return *this;
  }

  // Sets the value of the displayName key.
  SearchBuilder& SetDisplayName(const std::string& value) {
    display_name_ = value;
    return *this;
  }

  // Sets the value of the objectUID key.
  SearchBuilder& SetObjectGuid(const std::string& value) {
    object_guid_ = value;
    return *this;
  }

  // Sets the value of the sAMAccountName key.
  SearchBuilder& SetSAMAccountName(const std::string& value) {
    sam_account_name_ = value;
    return *this;
  }

  // Sets the value of the common name key.
  SearchBuilder& SetCommonName(const std::string& value) {
    common_name_ = value;
    return *this;
  }

  // Sets the value of the userAccountControl key.
  SearchBuilder& SetUserAccountControl(const uint32_t value) {
    user_account_control_ = value;
    return *this;
  }

  // Sets the value of the pwdLastSet key.
  SearchBuilder& SetPwdLastSet(const uint64_t value) {
    pwd_last_set_ = value;
    return *this;
  }

  // Prevents output of pwdLastSet and userAccountControl fields.
  SearchBuilder& NoPwdFields() {
    output_pwd_fields = false;
    return *this;
  }

 private:
  std::string given_name_ = kGivenName;
  std::string display_name_ = kDisplayName;
  std::string object_guid_ = kAccountId;
  std::string sam_account_name_ = kUserName;
  std::string common_name_ = kCommonName;
  uint32_t user_account_control_ = kUserAccountControl;
  uint64_t pwd_last_set_ = kPwdLastSet;
  bool output_pwd_fields = true;
};

// Searches |str| for (|searchKey|=value) and returns value. Returns an empty
// string if the key could not be found or if the value is empty.
std::string FindSearchValue(const std::string& str, const char* search_key) {
  const std::string full_key = base::StringPrintf("(%s=", search_key);
  size_t idx1 = str.find(full_key);
  if (idx1 == std::string::npos)
    return "";
  const size_t idx2 = str.find(")", idx1 + full_key.size());
  if (idx2 == std::string::npos)
    return "";
  idx1 += full_key.size();
  return str.substr(idx1, idx2 - idx1);
}

// Prints custom stub net ads gpo list output corresponding to one remote GPO
// with the given properties. For |gpflags| see kGpFlag*.
std::string PrintGpo(const char* guid,
                     uint32_t version_user,
                     uint32_t version_machine,
                     int gpflags) {
  DCHECK(gpflags >= 0 && gpflags < kGpFlagCount);
  return base::StringPrintf(
      kStubRemoteGpo, guid, (version_user << 16) | version_machine,
      version_user, version_machine, version_user, version_user,
      version_machine, version_machine, guid, guid, kGpFlagsStr[gpflags]);
}

// Reads the machine and user passwords from stdin.
// Expected format is:machine_pass + "\n" + user_pass.
bool GetNetAdsJoinPasswords(std::string* user_password,
                            std::string* machine_password) {
  std::string passwords_str;
  if (!ReadPipeToString(STDIN_FILENO, &passwords_str))
    return false;
  std::vector<std::string> passwords = base::SplitString(
      passwords_str, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
  if (passwords.size() != 2)
    return false;
  *machine_password = std::move(passwords[0]);
  *user_password = std::move(passwords[1]);
  return true;
}

// Reads the contents of the (stub) user Kerberos credentials cache. Returns an
// empty string if the file does not exist.
std::string GetUserKrb5CCData(const std::string& smb_conf_path) {
  // Note: Can't use GetKrb5CCFilePath() here since the env var is not defined,
  // so figure it out from |smb_conf_path|.
  // smb.conf is at <basepath>/temp/smb_*.conf.
  // krb5cc   is at <basepath>/temp/samba/krb5cc_user.
  const base::FilePath krb5cc_path = base::FilePath(smb_conf_path)
                                         .DirName()
                                         .Append(kSambaDir)
                                         .Append(kKrb5CCUser);
  std::string krb5cc_data;
  if (!base::PathExists(krb5cc_path))
    return std::string();
  CHECK(base::ReadFileToString(krb5cc_path, &krb5cc_data));
  return krb5cc_data;
}

// Reads the smb.conf file at |smb_conf_path| and extracts the string value
// associated with given |setting|.
std::string GetStringValueFromSmbConf(const std::string& smb_conf_path,
                                      const std::string& setting) {
  std::string smb_conf;
  CHECK(base::ReadFileToString(base::FilePath(smb_conf_path), &smb_conf));
  std::string value;
  CHECK(FindToken(smb_conf, '=', setting, &value));
  return value;
}

// Reads the smb.conf file at |smb_conf_path| and extracts the netbios name.
std::string GetMachineNameFromSmbConf(const std::string& smb_conf_path) {
  // We need the device smb.conf here, the user smb.conf doesn't contain the
  // netbios name.
  std::string device_smb_conf_path = smb_conf_path;
  base::ReplaceFirstSubstringAfterOffset(&device_smb_conf_path, 0, kSmbConfUser,
                                         kSmbConfDevice);
  return GetStringValueFromSmbConf(device_smb_conf_path, "netbios name");
}

// Returns different stub net ads search results depending on |object_guid|.
std::string GetSearchResultFromObjectGUID(const std::string& object_guid) {
  SearchBuilder search_builder;
  search_builder.SetObjectGuid(object_guid);

  // Valid account id, return valid search result for the default user.
  if (object_guid == kAccountId)
    return search_builder.GetResult();

  // Invalid account id, return bad "nothing found" search result.
  if (object_guid == kBadAccountId)
    return kStubBadSearch;

  // Pretend that the password expired.
  if (object_guid == kExpiredPasswordAccountId)
    return search_builder.SetPwdLastSet(0).GetResult();

  // Pretend that the password never expires.
  if (object_guid == kNeverExpirePasswordAccountId) {
    return search_builder.SetPwdLastSet(0)
        .SetUserAccountControl(UF_DONT_EXPIRE_PASSWD)
        .GetResult();
  }

  // Pretend that the password changed on the server.
  if (object_guid == kPasswordChangedAccountId)
    return search_builder.SetPwdLastSet(kPwdLastSet + 1).GetResult();

  // Pretend missing pwdLastSet and userAccountControl fields.
  if (object_guid == kNoPwdFieldsAccountId)
    return search_builder.NoPwdFields().GetResult();

  NOTREACHED() << "UNHANDLED OBJECT GUID " << object_guid;
  return std::string();
}

// Returns different stub net ads search results depending on
// |sam_account_name|.
std::string GetSearchResultFromSAMAccountName(
    const std::string& sam_account_name) {
  SearchBuilder search_builder;
  search_builder.SetSAMAccountName(sam_account_name);

  // Set special account ids, required during auth for tests that use the ids in
  // GetUserStatus().
  if (sam_account_name == kPasswordChangedUserName)
    return search_builder.SetObjectGuid(kPasswordChangedAccountId).GetResult();
  if (sam_account_name == kNoPwdFieldsUserName) {
    return search_builder.SetObjectGuid(kNoPwdFieldsAccountId)
        .NoPwdFields()
        .GetResult();
  }

  // In all cases, just return a search result with the proper sAMAccountName.
  return search_builder.GetResult();
}

// Formats time according to "Fri, 03 Feb 2017 05:24:05 UTC".
std::string FormatServerTime(const base::Time& time) {
  time_t utime = time.ToTimeT();
  struct tm tm;
  gmtime_r(&utime, &tm);
  char str[64];
  CHECK(strftime(str, sizeof(str), "%a, %d %b %Y %H:%M:%S UTC", &tm));
  return std::string(str);
}

// Returns the path of a marker file to check whether "net setdomainsid" has
// been called for a given workgroup stored in a config file at |smb_conf_path|.
base::FilePath GetDomainSidMarkerPath(const std::string& smb_conf_path) {
  return base::FilePath(smb_conf_path)
      .DirName()
      .Append(kFakeDomainSidMarkerPrefix +
              GetStringValueFromSmbConf(smb_conf_path, "workgroup"));
}

// Fakes setting a "net setdomainsid" call by writing a marker file.
void SetFakeDomainSid(const std::string& smb_conf_path) {
  char c = 0;
  CHECK_EQ(base::WriteFile(GetDomainSidMarkerPath(smb_conf_path), &c, 1), 1);
}

// Checks whether "net setdomainsid" has been called before by checking the
// marker file.
bool IsFakeDomainSidSet(const std::string& smb_conf_path) {
  return base::PathExists(GetDomainSidMarkerPath(smb_conf_path));
}

// Handles a stub 'net ads workgroup' call. Different behavior is triggered by
// passing different machine names (in smb.conf) and user credential caches.
int HandleWorkgroup(const std::string& smb_conf_path) {
  // Read machine name from smb.conf.
  const std::string machine_name = GetMachineNameFromSmbConf(smb_conf_path);

  // Stub server ping error when the TGT is expired (to get certain behavior in
  // GetUserStatus()). Note that SambaInterface::PingServer currently calls net
  // ads workgroup to check if the server is available.
  if (machine_name == base::ToUpperASCII(kPingServerFailMachineName) &&
      GetUserKrb5CCData(smb_conf_path) == kExpiredKrb5CCData) {
    WriteOutput("", kNetworkError);
    return kExitCodeError;
  }

  // Select workgroup based on realm.
  std::string workgroup = (GetStringValueFromSmbConf(smb_conf_path, "realm") ==
                           kSecondaryWorkgroupRealm)
                              ? kSecondaryWorkgroup
                              : kDefaultWorkgroup;

  WriteOutput(base::StrCat({"Workgroup: ", workgroup}), "");
  return kExitCodeOk;
}

// Handles a stub 'net ads join' call. Different behavior is triggered by
// passing different user principals, passwords and machine names (in smb.conf).
int HandleJoin(const std::string& command_line,
               const std::string& smb_conf_path) {
  // Read the passwords from stdin (should be machine_pass + "\n" + user_pass).
  std::string user_password, machine_password;
  if (!GetNetAdsJoinPasswords(&user_password, &machine_password)) {
    LOG(ERROR) << "Failed to read passwords";
    return kExitCodeError;
  }
  CheckMachinePassword(machine_password);

  const std::string kUserFlag(std::string(kUserParam) + " ");

  // Read machine name from smb.conf.
  const std::string machine_name = GetMachineNameFromSmbConf(smb_conf_path);

  // Stub too long machine name error.
  if (machine_name.size() > kMaxMachineNameSize) {
    WriteOutput(
        base::StringPrintf(kMachineNameTooLongError, kMaxMachineNameSize,
                           machine_name.c_str(), machine_name.size()),
        "");
    return kExitCodeError;
  }

  // Stub bad machine name error.
  if (machine_name == base::ToUpperASCII(kInvalidMachineName)) {
    WriteOutput(kInvalidMachineNameError, "");
    return kExitCodeError;
  }

  // Stub seccomp failure.
  if (machine_name == base::ToUpperASCII(kSeccompMachineName)) {
    TriggerSeccompFailure();
    return kExitCodeOk;
  }

  // Stub insufficient quota error.
  if (Contains(command_line, kUserFlag + kInsufficientQuotaUserPrincipal)) {
    WriteOutput(kInsufficientQuotaError, "");
    return kExitCodeError;
  }

  // Stub non-existing account error (same error as 'wrong password' error).
  if (Contains(command_line, kUserFlag + kNonExistingUserPrincipal)) {
    WriteOutput(kWrongPasswordError, "");
    return kExitCodeError;
  }

  // Stub network error.
  if (Contains(command_line, kUserFlag + kNetworkErrorUserPrincipal)) {
    WriteOutput("", kNetworkError);
    return kExitCodeError;
  }

  // Stub access denied error.
  if (Contains(command_line, kUserFlag + kAccessDeniedUserPrincipal)) {
    WriteOutput(kJoinAccessDeniedError, "");
    return kExitCodeError;
  }

  // Stub encryption type not supported error.
  if (Contains(command_line, kUserFlag + kEncTypeNotSupportedUserPrincipal)) {
    WriteOutput(kEncTypeNotSupportedError, "");
    return kExitCodeError;
  }

  // Check whether createcomputer argument matches the expected one.
  if (Contains(command_line, kUserFlag + kExpectOuUserPrincipal)) {
    CHECK(Contains(command_line, std::string(kCreatecomputerParam) +
                                     kExpectedOuCreatecomputer))
        << "Bad createcomputer arg in command line " << command_line
        << ". Expected: " << kExpectedOuCreatecomputer;
    return kExitCodeOk;
  }

  // Stub valid user principal. Switch behavior based on password.
  if (Contains(command_line, kUserFlag + kUserPrincipal)) {
    // Stub wrong password.
    if (user_password == kWrongPassword) {
      WriteOutput(kWrongPasswordError, "");
      return kExitCodeError;
    }
    // Stub expired password.
    if (user_password == kExpiredPassword) {
      WriteOutput(kExpiredPasswordError, "");
      return kExitCodeError;
    }
    // Stub valid password.
    if (user_password == kPassword)
      return kExitCodeOk;

    NOTREACHED() << "UNHANDLED PASSWORD " << user_password;
    return kExitCodeError;
  }

  NOTREACHED() << "UNHANDLED COMMAND LINE " << command_line;
  return kExitCodeError;
}

// Handles a stub 'net ads info' call. Just returns stub information.
int HandleInfo(const std::string& smb_conf_path) {
  // Read machine name from smb.conf.
  const std::string machine_name = GetMachineNameFromSmbConf(smb_conf_path);

  if (machine_name == base::ToUpperASCII(kChangePasswordMachineName)) {
    // Figure out the machine pass last modified time.
    // smb.conf is at <basepath>/temp/smb_*.conf, the
    // password is at <basepath>/state/machine_pass.
    const base::FilePath password_path = base::FilePath(smb_conf_path)
                                             .DirName()
                                             .DirName()
                                             .Append(kStateDir)
                                             .Append(kMachinePass);
    base::File::Info file_info;
    if (GetFileInfo(password_path, &file_info)) {
      const base::Time password_time = file_info.last_modified;
      const base::Time server_time =
          password_time + kDefaultMachinePasswordChangeRate + base::Days(1);
      const std::string server_time_str = FormatServerTime(server_time);
      WriteOutput(base::StringPrintf(kStubInfo, server_time_str.c_str()), "");
      return kExitCodeOk;
    }
  }

  WriteOutput(base::StringPrintf(kStubInfo, kDefaultServerTime), "");
  return kExitCodeOk;
}

// Handles a stub 'net ads lookup' call. Just returns stub information.
int HandleLookup() {
  WriteOutput(kStubLookup, "");
  return kExitCodeOk;
}

// Handles a stub 'net ads gpo list' call. Different behavior is triggered by
// passing different machine names (in smb.conf).
int HandleGpoList(const std::string& smb_conf_path) {
  // Read machine name from smb.conf.
  const std::string machine_name = GetMachineNameFromSmbConf(smb_conf_path);

  // Stub empty GPO list.
  if (machine_name == base::ToUpperASCII(kEmptyGpoMachineName))
    return kExitCodeOk;

  // Samba 4.10.7 requires a domain sid for this command.
  if (!IsFakeDomainSidSet(smb_conf_path))
    return kExitCodeError;

  // All other GPO lists use the local GPO.
  std::string gpos = kStubLocalGpo;

  // Increase the version by default, so that GPOs will always reload properly
  // (prevents nasty surprises in tests). The version is only frozen for GPO
  // cache tests.
  const auto test_dir = base::FilePath(smb_conf_path).DirName();
  const int version = 1 + PostIncTestCounter(test_dir);

  if (machine_name == base::ToUpperASCII(kGpoDownloadErrorMachineName)) {
    // Stub GPO list that triggers a download error in smbclient.
    gpos += PrintGpo(kErrorGpoGuid, version, version, kGpFlagAllEnabled);
  } else if (machine_name == base::ToUpperASCII(kSeccompMachineName)) {
    // Stub GPO list that triggers a seccomp failure in smbclient.
    gpos += PrintGpo(kSeccompGpoGuid, version, version, kGpFlagAllEnabled);
  } else if (machine_name == base::ToUpperASCII(kOneGpoMachineName)) {
    // Stub GPO list that downloads one GPO if present.
    gpos += PrintGpo(kGpo1Guid, version, version, kGpFlagAllEnabled);
  } else if (machine_name == base::ToUpperASCII(kTwoGposMachineName)) {
    // Stub GPO list that downloads two GPOs if present.
    gpos += PrintGpo(kGpo1Guid, version, version, kGpFlagAllEnabled);
    gpos += PrintGpo(kGpo2Guid, version, version, kGpFlagAllEnabled);
  } else if (machine_name ==
             base::ToUpperASCII(kOneGpoKeepVersionMachineName)) {
    // Stub GPO list with two GPOs and frozen version.
    gpos += PrintGpo(kGpo1Guid, 1, 1, kGpFlagAllEnabled);
  } else if (machine_name ==
             base::ToUpperASCII(kTwoGposKeepVersionMachineName)) {
    // Stub GPO list with two GPOs and freezing the version of the second.
    gpos += PrintGpo(kGpo1Guid, version, version, kGpFlagAllEnabled);
    gpos += PrintGpo(kGpo2Guid, 1, 1, kGpFlagAllEnabled);
  } else if (machine_name == base::ToUpperASCII(kZeroUserVersionMachineName)) {
    // Stub GPO list that contains a GPO with version_user == 0 (should be
    // ignored during user policy fetch).
    gpos += PrintGpo(kGpo1Guid, 0, version, kGpFlagAllEnabled);
  } else if (machine_name == base::ToUpperASCII(kDisableUserFlagMachineName)) {
    // Stub GPO list that contains a GPO with kGpFlagUserDisabled set (should be
    // ignored during user policy fetch).
    gpos += PrintGpo(kGpo1Guid, version, version, kGpFlagUserDisabled);
  } else if (machine_name == base::ToUpperASCII(kLoopbackGpoMachineName)) {
    // Stub GPO list that contains
    //   - GPO1 when querying GPOs for the user account and
    //   - GPO2 when querying GPOs for the device account.
    bool requesting_user_gpos = Contains(smb_conf_path, kSmbConfUser);
    const char* gpo_guid = requesting_user_gpos ? kGpo1Guid : kGpo2Guid;
    gpos += PrintGpo(gpo_guid, version, version, kGpFlagAllEnabled);
  }

  WriteOutput(smb_conf_path, gpos);
  return kExitCodeOk;
}

// Handles a stub 'net ads search' call. Different behavior is triggered by
// passing different sAMAccountNames or objectGUIDs as search term.
int HandleSearch(const std::string& command_line) {
  std::string sam_account_name =
      FindSearchValue(command_line, kSearchSAMAccountName);
  std::string object_guid_octet =
      FindSearchValue(command_line, kSearchObjectGUID);

  // Handle the net ads search command to detect unaffiliated users.
  if (sam_account_name == base::ToUpperASCII(kUnaffiliatedMachineName) + "$")
    return kExitCodeUnspecifiedError;

  std::string search_result;
  if (!object_guid_octet.empty()) {
    // Search by objectGUID aka account id.
    std::string object_guid = OctetStringToGuidForTesting(object_guid_octet);
    search_result = GetSearchResultFromObjectGUID(object_guid);
  } else if (!sam_account_name.empty()) {
    // Search by sAMAccountName.
    search_result = GetSearchResultFromSAMAccountName(sam_account_name);
  } else {
    LOG(ERROR) << "SEARCH TERM NOT RECOGNIZED IN COMMAND LINE " << command_line;
  }

  WriteOutput(search_result, "");
  return kExitCodeOk;
}

// Handles a stub 'net setdomainsid' call. Writes out a marker file to indicate
// that the domain sid has been set. This is checked in 'net ads gpo list'. This
// fakes the behavior of Samba 4.10.7, which requires the domain sid to be set
// for that command.
int HandleSetDomainSid(const std::string& smb_conf_path) {
  // net setdomainsid should be called at most once for the same workgroup.
  if (IsFakeDomainSidSet(smb_conf_path))
    return kExitCodeError;
  SetFakeDomainSid(smb_conf_path);
  return kExitCodeOk;
}

int HandleCommandLine(const std::string& command_line,
                      const std::string& smb_conf_path) {
  // Make sure the caller adds the debug level.
  CHECK(Contains(command_line, kDebugParam));

  // Stub net ads workgroup.
  if (StartsWithCaseSensitive(command_line, "ads workgroup"))
    return HandleWorkgroup(smb_conf_path);

  // Stub net ads join.
  if (StartsWithCaseSensitive(command_line, "ads join"))
    return HandleJoin(command_line, smb_conf_path);

  // Stub net ads info.
  if (StartsWithCaseSensitive(command_line, "ads info"))
    return HandleInfo(smb_conf_path);

  // Stub net ads lookup.
  if (StartsWithCaseSensitive(command_line, "ads lookup"))
    return HandleLookup();

  // Stub net ads gpo list.
  if (StartsWithCaseSensitive(command_line, "ads gpo list"))
    return HandleGpoList(smb_conf_path);

  // Stub net ads search.
  if (StartsWithCaseSensitive(command_line, "ads search"))
    return HandleSearch(command_line);

  // Stub net setdomainsid.
  if (StartsWithCaseSensitive(command_line, "setdomainsid"))
    return HandleSetDomainSid(smb_conf_path);

  NOTREACHED() << "UNHANDLED COMMAND LINE " << command_line;
  return kExitCodeError;
}

}  // namespace
}  // namespace authpolicy

int main(int argc, char* argv[]) {
  // Find Samba configuration path ("-s" argument).
  const std::string smb_conf_path =
      authpolicy::GetArgValue(argc, argv, authpolicy::kConfigParam);
  if (smb_conf_path.empty()) {
    authpolicy::WriteOutput("", authpolicy::kSmbConfArgMissingError);
    return authpolicy::kExitCodeError;
  }

  const std::string command_line = authpolicy::GetCommandLine(argc, argv);
  return authpolicy::HandleCommandLine(command_line, smb_conf_path);
}
