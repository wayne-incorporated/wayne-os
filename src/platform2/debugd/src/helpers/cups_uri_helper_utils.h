// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This utility library defines supporting functions for the CUPS URI helper.

#ifndef DEBUGD_SRC_HELPERS_CUPS_URI_HELPER_UTILS_H_
#define DEBUGD_SRC_HELPERS_CUPS_URI_HELPER_UTILS_H_

#include <string>

namespace debugd {
namespace cups_helper {

// Evaluates true if the |uri| (fed to lpadmin) seems valid.
// Don't confuse this for ::debugd::CupsTool::UriSeemsReasonable(),
// which farms out all the work to this helper.
bool UriSeemsReasonable(const std::string& uri);

}  // namespace cups_helper
}  // namespace debugd

#endif  // DEBUGD_SRC_HELPERS_CUPS_URI_HELPER_UTILS_H_
