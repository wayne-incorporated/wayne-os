// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AUTHPOLICY_CONSTANTS_H_
#define AUTHPOLICY_CONSTANTS_H_

namespace authpolicy {

// Commands for the parser.
extern const char kCmdParseServerInfo[];
extern const char kCmdParseDcName[];
extern const char kCmdParseWorkgroup[];
extern const char kCmdParseAccountInfo[];
extern const char kCmdParseUserGpoList[];
extern const char kCmdParseDeviceGpoList[];
extern const char kCmdParseUserPreg[];
extern const char kCmdParseDevicePreg[];
extern const char kCmdParseTgtLifetime[];

// Env variable for the Kerberos machine keytab.
extern const char kKrb5KTEnvKey[];
// Env variable for the Kerberos credentials cache.
extern const char kKrb5CCEnvKey[];
// Env variable for krb5.conf file.
extern const char kKrb5ConfEnvKey[];
// Prefix for some environment variable values that specify a file path.
extern const char kFilePrefix[];

// Net ads search keys.
extern const char kSearchObjectGUID[];
extern const char kSearchSAMAccountName[];
extern const char kSearchCommonName[];
extern const char kSearchDisplayName[];
extern const char kSearchGivenName[];
extern const char kSearchPwdLastSet[];
extern const char kSearchUserAccountControl[];

// User account control flag specifying that the password never expires.
const unsigned int UF_DONT_EXPIRE_PASSWD = 0x00010000;

enum ExitCodes {
  EXIT_CODE_OK = 0,
  EXIT_CODE_BAD_COMMAND = 1,
  EXIT_CODE_FIND_TOKEN_FAILED = 2,
  EXIT_CODE_READ_INPUT_FAILED = 3,
  EXIT_CODE_PARSE_INPUT_FAILED = 4,
  EXIT_CODE_WRITE_OUTPUT_FAILED = 5,
};

// Specifies the source of GPOs (user vs machine/device GPOs).
enum class GpoSource {
  USER,
  MACHINE,
};

// Specifies the type of policy (user vs machine/device policy). Note that
// sometimes user policy from device GPOs is needed (see 'loopback processing').
enum class PolicyScope {
  USER,
  MACHINE,
};

}  // namespace authpolicy

#endif  // AUTHPOLICY_CONSTANTS_H_
