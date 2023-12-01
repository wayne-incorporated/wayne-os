// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "authpolicy/constants.h"

namespace authpolicy {

const char kCmdParseServerInfo[] = "parse_server_info";
const char kCmdParseDcName[] = "parse_dc_name";
const char kCmdParseWorkgroup[] = "parse_workgroup";
const char kCmdParseAccountInfo[] = "parse_account_info";
const char kCmdParseUserGpoList[] = "parse_user_gpo_list";
const char kCmdParseDeviceGpoList[] = "parse_device_gpo_list";
const char kCmdParseUserPreg[] = "parse_user_preg";
const char kCmdParseDevicePreg[] = "parse_device_preg";
const char kCmdParseTgtLifetime[] = "parse_tgt_lifetime";

const char kKrb5KTEnvKey[] = "KRB5_KTNAME";
const char kKrb5CCEnvKey[] = "KRB5CCNAME";
const char kKrb5ConfEnvKey[] = "KRB5_CONFIG";
const char kFilePrefix[] = "FILE:";

const char kSearchObjectGUID[] = "objectGUID";
const char kSearchSAMAccountName[] = "sAMAccountName";
const char kSearchCommonName[] = "cn";
const char kSearchDisplayName[] = "displayName";
const char kSearchGivenName[] = "givenName";
const char kSearchPwdLastSet[] = "pwdLastSet";
const char kSearchUserAccountControl[] = "userAccountControl";

}  // namespace authpolicy
