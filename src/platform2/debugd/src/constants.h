// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_CONSTANTS_H_
#define DEBUGD_SRC_CONSTANTS_H_

namespace debugd {

// The file path used to indicate the Chrome remote debugging dev feature
// should be on.
extern const char kDevFeaturesChromeRemoteDebuggingFlagPath[];

// The file path used to indicate the device coredump uploads are allowed.
extern const char kDeviceCoredumpUploadFlagPath[];

extern const char kDebugfsGroup[];
extern const char kPstoreAccessGroup[];

}  // namespace debugd

#endif  // DEBUGD_SRC_CONSTANTS_H_
