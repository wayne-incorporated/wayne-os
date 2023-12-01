// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Stub implementation of kinit. Does not talk to server, but simply returns
// fixed responses to predefined input.

#include <string>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

#include "authpolicy/platform_helper.h"
#include "authpolicy/samba_helper.h"
#include "authpolicy/stub_common.h"

namespace authpolicy {
namespace {

// kinit error messages. stub_kinit reproduces kinit errors because authpolicy
// reads and interprets error messages from stdout/stderr.
const char kNonExistingPrincipalErrorFormat[] =
    "kinit: Client '%s' not found in Kerberos database while getting initial "
    "credentials";
const char kWrongPasswordError[] =
    "kinit: Preauthentication failed while getting initial credentials";
const char kPasswordExpiredStdout[] =
    "Password expired.  You must change it now.";
const char kPasswordRejectedStdout[] =
    "Password for user@realm:"
    "Password expired.  You must change it now.\n"
    "Enter new password:\n"
    "Enter it again:\n"
    "Password change rejected: The password must include numbers or symbols.  "
    "Don't include any part of your name in the password.  The password must "
    "contain at least 7 characters.  The password must be different from the "
    "previous 24 passwords.  The password can only be changed once a day..  "
    "Please try again.";
const char kCannotReadPasswordStderr[] =
    "Cannot read password while getting initial credentials";
const char kNetworkError[] = "Cannot resolve network address for KDC in realm";
const char kCannotContactKdc[] = "Cannot contact any KDC";
const char kKdcIpKey[] = "kdc = [";
const char kPasswordWillExpireWarning[] =
    "Warning: Your password will expire in 7 days on Fri May 19 14:28:41 2017";
const char kRefresh[] = "-R";
const char kTicketExpired[] =
    "kinit: Ticket expired while renewing credentials";
const char kEncTypeNotSupported[] =
    "KDC has no support for encryption type while getting initial credentials";

// Returns upper-cased |machine_name|$@|kUserRealm|.
std::string MakeMachinePrincipal(const std::string& machine_name) {
  return base::ToUpperASCII(machine_name) + "$@" + kUserRealm;
}

// For a given |machine_name|, tests if the |command_line| starts with
// corresponding machine principal part (upper-cased |machine_name| + "$@").
bool TestMachinePrincipal(const std::string& command_line,
                          const std::string& machine_name) {
  std::string machine_principal_part = base::ToUpperASCII(machine_name) + "$@";
  return StartsWithCaseSensitive(command_line, machine_principal_part.c_str());
}

// Returns true if |command_line| contains a machine principal and not a user
// principal.
bool HasMachinePrincipal(const std::string& command_line) {
  return Contains(command_line, "$@");
}

// Returns false for the first |kNumPropagationRetries| times the method is
// called and true afterwards. Used to simulate account propagation errors. Only
// works once per test. Uses a test file internally, where each time a byte is
// appended to count retries. Note that each invokation usually happens in a
// separate process, so a static memory location can't be used for counting.
bool HasStubAccountPropagated() {
  const auto test_dir = base::FilePath(GetKrb5ConfFilePath()).DirName();
  return PostIncTestCounter(test_dir) == kNumPropagationRetries;
}

// Reads the contents of the file at |kExpectedMachinePassFilename| and returns
// it in |expected_machine_pass|. Returns false if it doesn't exist.
bool GetExpectedMachinePassword(std::string* expected_machine_pass) {
  const base::FilePath krb5_conf_path(GetKrb5ConfFilePath());
  const base::FilePath expected_password_path =
      krb5_conf_path.DirName().Append(kExpectedMachinePassFilename);
  if (!base::PathExists(expected_password_path))
    return false;

  CHECK(base::ReadFileToString(base::FilePath(expected_password_path),
                               expected_machine_pass));
  return true;
}

// Writes a stub Kerberos credentials cache to the file path given by the
// kKrb5CCEnvKey environment variable.
void WriteKrb5CC(const std::string& data) {
  const std::string krb5cc_path = GetKrb5CCFilePath();
  // Note: base::WriteFile triggers a seccomp failure, so do it old-school.
  base::ScopedFILE krb5cc_file(fopen(krb5cc_path.c_str(), "w"));
  CHECK(krb5cc_file);
  CHECK_EQ(1U, fwrite(data.c_str(), data.size(), 1, krb5cc_file.get()));
}

// Checks whether the Kerberos configuration file contains the KDC IP.
bool Krb5ConfContainsKdcIp() {
  const base::FilePath krb5_conf_path(GetKrb5ConfFilePath());
  std::string krb5_conf;
  CHECK(base::ReadFileToString(krb5_conf_path, &krb5_conf));
  return Contains(krb5_conf, kKdcIpKey);
}

// Handles ticket refresh with kinit -R. Switches behavior based on the contents
// of the Kerberos ticket.
int HandleRefresh() {
  const std::string krb5cc_path = GetKrb5CCFilePath();
  std::string krb5cc_data;
  CHECK(base::ReadFileToString(base::FilePath(krb5cc_path), &krb5cc_data));
  if (krb5cc_data == kExpiredKrb5CCData) {
    WriteOutput("", kTicketExpired);
    return kExitCodeError;
  }
  WriteKrb5CC(kValidKrb5CCData);
  return kExitCodeOk;
}

int HandleCommandLine(const std::string& command_line) {
  // Read the password from stdin.
  std::string password;
  if (!ReadPipeToString(STDIN_FILENO, &password)) {
    LOG(ERROR) << "Failed to read password";
    return kExitCodeError;
  }

  // Request for TGT refresh. The only test that uses it expects a failure.
  if (StartsWithCaseSensitive(command_line, kRefresh))
    return HandleRefresh();

  // Stub non-existing account error.
  if (StartsWithCaseSensitive(command_line, kNonExistingUserPrincipal)) {
    WriteOutput("", base::StringPrintf(kNonExistingPrincipalErrorFormat,
                                       kNonExistingUserPrincipal));
    return kExitCodeError;
  }

  // Stub network error.
  if (StartsWithCaseSensitive(command_line, kNetworkErrorUserPrincipal)) {
    WriteOutput("", kNetworkError);
    return kExitCodeError;
  }

  // Stub kinit retry if the krb5.conf contains the KDC IP.
  if (StartsWithCaseSensitive(command_line, kKdcRetryUserPrincipal)) {
    if (Krb5ConfContainsKdcIp()) {
      WriteOutput("", kCannotContactKdc);
      return kExitCodeError;
    }
    WriteKrb5CC(kValidKrb5CCData);
    return kExitCodeOk;
  }

  // Stub kinit retry, but fail the second time as well.
  if (StartsWithCaseSensitive(command_line, kKdcRetryFailsUserPrincipal)) {
    WriteOutput("", kCannotContactKdc);
    return kExitCodeError;
  }

  // Stub encryption type not supported error.
  if (StartsWithCaseSensitive(command_line,
                              kEncTypeNotSupportedUserPrincipal)) {
    WriteOutput("", kEncTypeNotSupported);
    return kExitCodeError;
  }

  // Stub expired credential cache.
  if (StartsWithCaseSensitive(command_line, kExpiredTgtUserPrincipal)) {
    WriteKrb5CC(kExpiredKrb5CCData);
    return kExitCodeOk;
  }

  // Stub seccomp failure.
  if (StartsWithCaseSensitive(command_line, kSeccompUserPrincipal)) {
    TriggerSeccompFailure();
    WriteKrb5CC(kValidKrb5CCData);
    return kExitCodeOk;
  }

  // Stub valid user principal. Switch behavior based on password.
  if (StartsWithCaseSensitive(command_line, kUserPrincipal) ||
      StartsWithCaseSensitive(command_line, kPasswordChangedUserPrincipal) ||
      StartsWithCaseSensitive(command_line, kNoPwdFieldsUserPrincipal)) {
    // Stub wrong password error.
    if (password == kWrongPassword) {
      WriteOutput("", kWrongPasswordError);
      return kExitCodeError;
    }

    // Stub expired password error.
    if (password == kExpiredPassword) {
      WriteOutput(kPasswordExpiredStdout, kCannotReadPasswordStderr);
      return kExitCodeError;
    }

    // Stub rejected password error.
    if (password == kRejectedPassword) {
      WriteOutput(kPasswordRejectedStdout, kCannotReadPasswordStderr);
      return kExitCodeError;
    }

    // Stub warning that the password will expire soon.
    if (password == kWillExpirePassword) {
      WriteKrb5CC(kValidKrb5CCData);
      WriteOutput(kPasswordWillExpireWarning, "");
      return kExitCodeOk;
    }

    // Stub valid password.
    if (password == kPassword) {
      WriteKrb5CC(kValidKrb5CCData);
      return kExitCodeOk;
    }

    NOTREACHED() << "UNHANDLED PASSWORD " << password;
    return kExitCodeError;
  }

  // Handle machine principals.
  if (HasMachinePrincipal(command_line)) {
    // Stub account propagation error.
    if (TestMachinePrincipal(command_line, kExpectKeytabMachineName)) {
      // Make sure the caller adds the debug level.
      CHECK(Contains(command_line, kUseKeytabParam));
      CHECK(password.empty());
      std::string keytab_path = GetKeytabFilePath();
      CHECK(!keytab_path.empty());
      WriteKrb5CC(kValidKrb5CCData);
      return kExitCodeOk;
    }

    // The ones below should be using a password.
    CheckMachinePassword(password);

    // Compare to the expected password, if it exists.
    std::string expected_password;
    if (GetExpectedMachinePassword(&expected_password) &&
        password != expected_password) {
      WriteOutput("", kWrongPasswordError);
      return kExitCodeError;
    }

    // Stub account propagation error.
    if (TestMachinePrincipal(command_line, kPropagationRetryMachineName) &&
        !HasStubAccountPropagated()) {
      WriteOutput(
          "", base::StringPrintf(
                  kNonExistingPrincipalErrorFormat,
                  MakeMachinePrincipal(kPropagationRetryMachineName).c_str()));
      return kExitCodeError;
    }

    // Stub non-existent machine error (e.g. machine got deleted from ACtive
    // Directory).
    if (TestMachinePrincipal(command_line, kNonExistingMachineName)) {
      // Note: Same error as if the account hasn't propagated yet.
      WriteOutput("",
                  base::StringPrintf(
                      kNonExistingPrincipalErrorFormat,
                      MakeMachinePrincipal(kNonExistingMachineName).c_str()));
      return kExitCodeError;
    }

    // All other machine principals just pass.
    WriteKrb5CC(kValidKrb5CCData);
    return kExitCodeOk;
  }

  NOTREACHED() << "UNHANDLED COMMAND LINE " << command_line;
  return kExitCodeError;
}

}  // namespace
}  // namespace authpolicy

int main(int argc, char* argv[]) {
  std::string command_line = authpolicy::GetCommandLine(argc, argv);
  return authpolicy::HandleCommandLine(command_line);
}
