// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file is used for reserving project IDs (the ones used for disk quota
// management) on Chrome OS file system.

#ifndef CRYPTOHOME_PROJECTID_CONFIG_H_
#define CRYPTOHOME_PROJECTID_CONFIG_H_

namespace cryptohome {

// The constants below describes the ranges of project IDs reserved by Android.
// These numbers are from
// system/core/libcutils/include/private/android_projectid_config.h
// in Android code base. (go/arc-project-quota)

// Project IDs reserved for Android files on external storage.
// Total 100 IDs are reserved from PROJECT_ID_EXT_DEFAULT (1000)
// in android_projectid_config.h
constexpr int kProjectIdForAndroidFilesStart = 1000;
constexpr int kProjectIdForAndroidFilesEnd = 1099;

// Project IDs reserved for Android apps.
// The range corresponds with PROJECT_ID_EXT_DATA_START and
// PROJECT_ID_EXT_OBB_END in android_projectid_config.h.
constexpr int kProjectIdForAndroidAppsStart = 20000;
constexpr int kProjectIdForAndroidAppsEnd = 49999;

}  // namespace cryptohome

#endif  // CRYPTOHOME_PROJECTID_CONFIG_H_
