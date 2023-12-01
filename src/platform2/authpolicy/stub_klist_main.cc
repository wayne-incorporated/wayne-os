// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Stub implementation of klist. Simply returns fixed responses to predefined
// input.

#include <string>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/notreached.h>
#include <base/strings/stringprintf.h>

#include "authpolicy/samba_helper.h"
#include "authpolicy/stub_common.h"

namespace authpolicy {
namespace {

const int kExitCodeTgtValid = 0;
const int kExitCodeTgtInvalid = 1;

const time_t kTenHours = 3600 * 10;
const time_t kSevenDays = 3600 * 24 * 7;

const char kDefaultKrb5CCPath[] = "/tmp/krb5cc_0";

const char kNoCredentialsCacheErrorFormat[] =
    "klist: No credentials cache found (filename: %s)";

// Stub klist result format. Times to be filled in.
const char kStubListFormat[] = R"!!!(Ticket cache: FILE:/krb5cc
Default principal: TESTCOMP$@EXAMPLE.COM

Valid starting     Expires            Service principal
%s  %s  krbtgt/EXAMPLE.COM@EXAMPLE.COM
         renew until %s
%s  %s  ldap/server.example.com@EXAMPLE.COM
         renew until %s
)!!!";

// Formats |time_epoch| (e.g. from time()) as "mm/dd/yy HH:MM:SS".
std::string FormatDateTime(time_t time_epoch) {
  char buffer[64] = {};
  struct tm tm;
  localtime_r(&time_epoch, &tm);
  CHECK(strftime(buffer, sizeof(buffer), "%m/%d/%y %H:%M:%S", &tm));
  return buffer;
}

// Fills in the times for kStubListFormat.
std::string FormatStubList(time_t valid_from,
                           time_t expires,
                           time_t renew_until) {
  const std::string valid_from_str = FormatDateTime(valid_from);
  const std::string expires_str = FormatDateTime(expires);
  const std::string renew_until_str = FormatDateTime(renew_until);
  return base::StringPrintf(kStubListFormat, valid_from_str.c_str(),
                            expires_str.c_str(), renew_until_str.c_str(),
                            valid_from_str.c_str(), expires_str.c_str(),
                            renew_until_str.c_str());
}

// Returns a stub klist result with valid tickets.
std::string GetValidStubList() {
  // Note: The base/time.h methods cause a seccomp failure here.
  time_t now = time(NULL);
  return FormatStubList(now, now + kTenHours, now + kSevenDays);
}

// Reads the Kerberos credentials cache from the file path given by the
// kKrb5CCEnvKey environment variable. Returns an empty string on error.
std::string ReadKrb5CC(const std::string& krb5cc_path) {
  std::string data;
  if (!base::ReadFileToString(base::FilePath(krb5cc_path), &data))
    data.clear();
  return data;
}

int HandleCommandLine(const std::string& command_line,
                      const std::string& krb5cc_path) {
  const std::string krb5cc_data = ReadKrb5CC(krb5cc_path);
  if (krb5cc_data.empty()) {
    const std::string no_credentials_cache_error =
        base::StringPrintf(kNoCredentialsCacheErrorFormat, krb5cc_path.c_str());
    WriteOutput("", no_credentials_cache_error);
    return kExitCodeError;
  }

  // klist -s just returns 0 if the TGT is valid and 1 otherwise.
  if (Contains(command_line, "-s")) {
    if (krb5cc_data == kValidKrb5CCData)
      return kExitCodeTgtValid;
    else if (krb5cc_data == kExpiredKrb5CCData)
      return kExitCodeTgtInvalid;
    else
      NOTREACHED() << "UNHANDLED KRB5CC DATA " << krb5cc_data;
  }

  if (krb5cc_data == kValidKrb5CCData) {
    WriteOutput(GetValidStubList(), "");
    return kExitCodeOk;
  } else if (krb5cc_data == kExpiredKrb5CCData) {
    NOTREACHED() << "klist -s should have prevented this code path";
  }
  NOTREACHED() << "UNHANDLED KRB5CC DATA " << krb5cc_data;
  return kExitCodeError;
}

}  // namespace
}  // namespace authpolicy

int main(int argc, const char* const* argv) {
  // Find Kerberos credentials cache path ("-c" argument).
  std::string krb5cc_path = authpolicy::GetArgValue(argc, argv, "-c");
  if (krb5cc_path.empty())
    krb5cc_path = authpolicy::kDefaultKrb5CCPath;

  std::string command_line = authpolicy::GetCommandLine(argc, argv);
  return authpolicy::HandleCommandLine(command_line, krb5cc_path);
}
