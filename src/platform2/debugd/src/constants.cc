// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/constants.h"

namespace debugd {

// For security purposes the path needs to be on rootfs. This prevents the
// possibility of enabling Chrome remote debugging without being in dev mode and
// having removed rootfs verification.
const char kDevFeaturesChromeRemoteDebuggingFlagPath[] =
    "/etc/chrome_remote_debugging_on";

const char kDeviceCoredumpUploadFlagPath[] =
    "/var/lib/crash_reporter/device_coredump_upload_allowed";

const char kDebugfsGroup[] = "debugfs-access";

const char kPstoreAccessGroup[] = "pstore-access";

}  // namespace debugd
