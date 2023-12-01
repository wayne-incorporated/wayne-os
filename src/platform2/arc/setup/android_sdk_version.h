// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_SETUP_ANDROID_SDK_VERSION_H_
#define ARC_SETUP_ANDROID_SDK_VERSION_H_

#include <climits>

namespace arc {

enum class AndroidSdkVersion {
  UNKNOWN = 0,
  ANDROID_M = 23,
  ANDROID_N_MR1 = 25,
  ANDROID_P = 28,
  ANDROID_R = 30,
  ANDROID_S = 31,
  ANDROID_S_V2 = 32,
  ANDROID_TIRAMISU = 33,

  // Development SDK number is equal to
  // android.os.Build.VersionCode#CUR_DEVELOPMENT in Android framework.
  ANDROID_DEVELOPMENT = 10000,
};

}  // namespace arc

#endif  // ARC_SETUP_ANDROID_SDK_VERSION_H_
