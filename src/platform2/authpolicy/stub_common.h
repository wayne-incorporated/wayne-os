// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AUTHPOLICY_STUB_COMMON_H_
#define AUTHPOLICY_STUB_COMMON_H_

#include <string>

// Common helper methods for stub executables.

namespace base {
class FilePath;
}

namespace authpolicy {

extern const int kExitCodeOk;
extern const int kExitCodeError;
extern const int kExitCodeUnspecifiedError;

// Workgroups.
extern const char kDefaultWorkgroup[];
extern const char kSecondaryWorkgroup[];

// Realms.
extern const char kUserRealm[];
extern const char kMachineRealm[];

// Realm for secondary workgroup.
extern const char kSecondaryWorkgroupRealm[];

// Default, valid user name.
extern const char kUserName[];
// Default, valid user principal.
extern const char kUserPrincipal[];
// Triggers a parse error in SambaInterface code (UPN malformed).
extern const char kInvalidUserPrincipal[];
// Triggers bad user error in kinit and net ads join (user does not exist).
extern const char kNonExistingUserPrincipal[];
// Triggers network error in kinit and net ads join.
extern const char kNetworkErrorUserPrincipal[];
// Triggers an access denied error in net ads join (user cannot add machines).
extern const char kAccessDeniedUserPrincipal[];
// Triggers an error in kinit if krb5.conf contains the KDC IP, which causes
// SambaInterface to retry kinit without KDC IP in krb5.conf.
extern const char kKdcRetryUserPrincipal[];
// Same as above, but the second try fails as well.
extern const char kKdcRetryFailsUserPrincipal[];
// Triggers quota error in net ads join (user cannot add additional machines).
extern const char kInsufficientQuotaUserPrincipal[];
// Triggers 'KDC has no support for encryption type' error in net ads join.
extern const char kEncTypeNotSupportedUserPrincipal[];
// Triggers kinit to produce a TGT that klist interprets as expired.
extern const char kExpiredTgtUserPrincipal[];
// Triggers net ads search to return |kPasswordChangedAccountId| as objectGUID.
extern const char kPasswordChangedUserPrincipal[];
// Corresponding user name.
extern const char kPasswordChangedUserName[];
// Triggers net ads search to return |kNoPwdFieldsAccountId| as objectGUID.
extern const char kNoPwdFieldsUserPrincipal[];
// Corresponding user name.
extern const char kNoPwdFieldsUserName[];
// Triggers kinit to call a syscall that is not allowlisted.
extern const char kSeccompUserPrincipal[];
// Triggers an error in net ads join for missing or bad createcomputer argument.
extern const char kExpectOuUserPrincipal[];

// 'createcomputer' argument tested by the kExpectOuUserPrincipal check. Equals
// a distinguished name made from kExpectedOuParts and kUserRealm.
extern const char kExpectedOuCreatecomputer[];
// Array of organizational unit names used for the kExpectOuUserPrincipal check.
extern const char* kExpectedOuParts[];
// Array size of kExpectedOuParts.
extern const size_t kExpectedOuPartsSize;

// Misc account information, used to test whether they're properly parsed and
// encoded.
extern const char kDisplayName[];
extern const char kGivenName[];
extern const char kCommonName[];
extern const uint64_t kPwdLastSet;
extern const uint32_t kUserAccountControl;

// Default, valid account id (aka objectGUID).
extern const char kAccountId[];
// Alternative, valid account id.
extern const char kAltAccountId[];
// Triggers a net ads search error when searching for this objectGUID.
extern const char kBadAccountId[];
// Triggers "pwdLastSet=0" in net ads search.
extern const char kExpiredPasswordAccountId[];
// Triggers "pwdLastSet=0" and a userAccountControl flag to never expire the
// password in net ads search.
extern const char kNeverExpirePasswordAccountId[];
// Triggers a different pwdLastSet timestamp in net ads search.
extern const char kPasswordChangedAccountId[];
// Triggers missing pwdLastSet and userAccountControl fields in net ads search.
extern const char kNoPwdFieldsAccountId[];

// Default, valid Kerberos crendentials cache contents (in particular, TGT).
extern const char kValidKrb5CCData[];
// Triggers a "TGT expired" message in klist.
extern const char kExpiredKrb5CCData[];

// Default, valid password.
extern const char kPassword[];
// Triggers a wrong/bad password error in kinit.
extern const char kWrongPassword[];
// Triggers "expired password" error in kinit.
extern const char kExpiredPassword[];
// Triggers "rejected password" error in kinit.
extern const char kRejectedPassword[];
// Triggers "password will expire" warning in kinit.
extern const char kWillExpirePassword[];

// Default, valid machine name.
extern const char kMachineName[];
// Triggers a "machine name is too long" error in net ads join.
extern const char kTooLongMachineName[];
// Triggers an "invalid machine name" error in net ads join (machine name
// contains invalid chars).
extern const char kInvalidMachineName[];
// Triggers a "bad machine error" in kinit (machine doesn't exist).
extern const char kNonExistingMachineName[];
// Triggers a completely empty GPO list in net ads gpo list.
extern const char kEmptyGpoMachineName[];
// Triggers a GPO download error in net ads gpo list.
extern const char kGpoDownloadErrorMachineName[];
// Triggers downloading one GPO with user/machine versions > 0 and no flags.
extern const char kOneGpoMachineName[];
// Triggers downloading two GPOs with user/machine versions > 0 and no flags.
extern const char kTwoGposMachineName[];
// Triggers downloading one GPO, where its version is frozen at 1 between net
// ads gpo list calls.
extern const char kOneGpoKeepVersionMachineName[];
// Triggers downloading two GPOs, where the version of the second GPO is frozen.
extern const char kTwoGposKeepVersionMachineName[];
// Triggers downloading a GPO with user version 0.
extern const char kZeroUserVersionMachineName[];
// Triggers downloading a GPO with the kGpFlagUserDisabled flag set.
extern const char kDisableUserFlagMachineName[];
// Triggers downloading GPO1 for the user and GPO2 for the device. Used to test
// loopback processing for user policy.
extern const char kLoopbackGpoMachineName[];
// Triggers kinit to expect a keytab instead of a password.
extern const char kExpectKeytabMachineName[];
// Triggers net ads info to print a server time later than password write time +
// kDefaultMachinePasswordChangeRate, which should cause a password change.
extern const char kChangePasswordMachineName[];
// Triggers ADS server ping to fail, which causes GetUserStatus to return error.
extern const char kPingServerFailMachineName[];
// Triggers net ads search to return an unspecified error during the user
// affiliation check.
extern const char kUnaffiliatedMachineName[];
// Triggers kinit to be retried a few times for the machine TGT (simulates that
// the account hasn't propagated yet).
extern const char kPropagationRetryMachineName[];
// Triggers net ads join to call a syscall that is not allowlisted.
extern const char kSeccompMachineName[];

// How many times an account propagation error is simulated if
// |kPropagationRetryMachineName| is used.
const int kNumPropagationRetries = 15;

// Stub GPO GUID, triggers a "download" of testing GPO 1 in smbclient.
extern const char kGpo1Guid[];
// Stub GPO GUID, triggers a "download" of testing GPO 2 in smbclient.
extern const char kGpo2Guid[];
// Stub GPO GUID, triggers a GPO download error in smbclient.
extern const char kErrorGpoGuid[];
// Stub GPO GUID, triggers a seccomp failure in smbclient.
extern const char kSeccompGpoGuid[];

// Filename of stub GPO 1 file. This PREG file is written by tests and smbclient
// can be triggered to "download" it, e.g. by using kOneGpoMachineName.
extern const char kGpo1Filename[];
// Filename of stub GPO 2 file. "Download" can be triggered by using
// kTwoGposMachineName.
extern const char kGpo2Filename[];

// Filename of the expected machine password. stub_kinit fails if the file
// exists and the contained machine password does not match.
extern const char kExpectedMachinePassFilename[];

// Returns |argv[1] + " " + argv[2] + " " + ... + argv[argc-1]|.
std::string GetCommandLine(int argc, const char* const* argv);

// Gets the arg value following |name|, e.g. in a command line
// "kinit -c krb5cc_file", calling GetArgValue("-c") would return 'krb5cc_file'.
std::string GetArgValue(int argc, const char* const* argv, const char* name);

// Shortcut for base::StartsWith with case-sensitive comparison.
bool StartsWithCaseSensitive(const std::string& str, const char* search_for);

// Writes to stdout and stderr.
void WriteOutput(const std::string& stdout_str, const std::string& stderr_str);

// Reads the keytab file path from the environment. CHECKs that the environment
// actually contains a non-empty path.
std::string GetKeytabFilePath();

// Reads the Kerberos configuration file path from the environment. CHECKs that
// the environment actually contains a non-empty path.
std::string GetKrb5ConfFilePath();

// Reads the Kerberos credentials cache file path from the environment. CHECKs
// that the environment actually contains a non-empty path.
std::string GetKrb5CCFilePath();

// Checks that |password| is UTF-8 encoded and 256 characters long.
void CheckMachinePassword(const std::string& password);

// Makes an invalid system call (not in any of the *seccomp.policy files).
void TriggerSeccompFailure();

// Post increments a file based counter. The code is equivalent to
// int64_t PostIncTestCounter() { static int64_t count = 0; return count++; }
// except that it works across processes, so it can be used between stub_*
// calls. |test_dir| is the test temp directory. Internally, this function inc's
// the size of a file in |test_dir|.
int64_t PostIncTestCounter(const base::FilePath& test_dir);

}  // namespace authpolicy

#endif  // AUTHPOLICY_STUB_COMMON_H_
