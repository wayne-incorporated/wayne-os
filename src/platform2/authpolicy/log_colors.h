// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AUTHPOLICY_LOG_COLORS_H_
#define AUTHPOLICY_LOG_COLORS_H_

namespace authpolicy {

// Terminal colors for LOG outputs. See .cc for actual colors.
// Usage: LOG(INFO) << kColorCommand << "Red text" << kColorReset

extern const char kColorReset[];
extern const char kColorCommand[];
extern const char kColorCommandStdout[];
extern const char kColorCommandStderr[];
extern const char kColorKrb5Trace[];
extern const char kColorPolicy[];
extern const char kColorGpo[];
extern const char kColorFlags[];
extern const char kColorStatus[];
extern const char kColorCaches[];
extern const char kColorRequest[];
extern const char kColorRequestSuccess[];
extern const char kColorRequestFail[];

}  // namespace authpolicy

#endif  // AUTHPOLICY_LOG_COLORS_H_
