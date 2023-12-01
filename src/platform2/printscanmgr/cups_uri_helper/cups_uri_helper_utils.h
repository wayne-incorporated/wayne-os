// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This utility library defines supporting functions for the CUPS URI helper.

#ifndef PRINTSCANMGR_CUPS_URI_HELPER_CUPS_URI_HELPER_UTILS_H_
#define PRINTSCANMGR_CUPS_URI_HELPER_CUPS_URI_HELPER_UTILS_H_

#include <string>

namespace printscanmgr {
namespace cups_helper {

// Evaluates true if the |uri| (fed to lpadmin) seems valid.
// Don't confuse this for ::printscanmgr::CupsTool::UriSeemsReasonable(),
// which farms out all the work to this helper.
bool UriSeemsReasonable(const std::string& uri);

}  // namespace cups_helper
}  // namespace printscanmgr

#endif  // PRINTSCANMGR_CUPS_URI_HELPER_CUPS_URI_HELPER_UTILS_H_
