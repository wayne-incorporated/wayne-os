// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbprovider/constants.h"

namespace smbprovider {

const char kEntryParent[] = "..";
const char kEntrySelf[] = ".";
const char kHomeEnvironmentVariable[] = "HOME";
const char kSmbProviderHome[] = "/tmp/smbproviderd";
const char kSmbConfLocation[] = "/.smb";
const char kSmbConfFile[] = "/smb.conf";
const char kSmbConfData[] =
    "[global]\n"
    "\tclient min protocol = SMB2\n"
    "\tclient max protocol = SMB3\n"
    "\tsecurity = user\n";
const char kKrb5ConfigEnvironmentVariable[] = "KRB5_CONFIG";
const char kKrb5CCNameEnvironmentVariable[] = "KRB5CCNAME";
const char kKrb5TraceEnvironmentVariable[] = "KRB5_TRACE";
const char kKrb5ConfLocation[] = "/.krb";
const char kKrb5ConfFile[] = "/krb5.conf";
const char kCCacheLocation[] = "/.krb";
const char kCCacheFile[] = "/ccache";
const char kKrbTraceLocation[] = "/.krb";
const char kKrbTraceFile[] = "/krb_trace.txt";

}  // namespace smbprovider
