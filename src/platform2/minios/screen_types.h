// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_SCREEN_TYPES_H_
#define MINIOS_SCREEN_TYPES_H_

namespace minios {

// All the different screens in the MiniOs Flow. `kDownloadError` is shown when
// there is an Update Engine failure, `kNetworkError` is shown when there is an
// issue getting the networks. `kPasswordError` and `kConnectionError` are shown
// upon failures connecting to a chosen network.
enum class ScreenType {
  kWelcomeScreen = 0,
  kNetworkDropDownScreen = 1,
  kLanguageDropDownScreen = 2,
  kUserPermissionScreen = 3,
  kStartDownload = 4,
  kDownloadError = 5,
  kNetworkError = 6,
  kPasswordError = 7,
  kConnectionError = 8,
  kGeneralError = 9,
  kDebugOptionsScreen = 10,
  kLogScreen = 11,
};

}  // namespace minios

#endif  // MINIOS_SCREEN_TYPES_H_
