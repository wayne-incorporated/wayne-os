// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef GOLDFISHD_GOLDFISH_LIBRARY_H_
#define GOLDFISHD_GOLDFISH_LIBRARY_H_

#include <string>

namespace goldfishd {

// Supported messages from host.
namespace message {
// Host asks guest to auto login.
constexpr char kAutoLogin[] = "autologin=1";
}  // namespace message

// Get one message from goldfish pipe, the message format is defined
// https://android.googlesource.com/platform/external/qemu/+/HEAD/docs/ANDROID-QEMUD.TXT#158
bool ReadOneMessage(int fd, std::string* message_out);

}  //  namespace goldfishd

#endif  // GOLDFISHD_GOLDFISH_LIBRARY_H_
