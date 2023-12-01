// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PRINT_TOOLS_HELPERS_H_
#define PRINT_TOOLS_HELPERS_H_

#include <string>

// Validates the protocol of `url` and modifies it if necessary. The protocols
// ipp and ipps are converted to http and https, respectively. If the
// conversion occurs, adds a port number if one is not specified.
// Prints an error message to stderr and returns false in the following cases:
// * `url` does not contain "://" substring
// * the protocol is not one of http, https, ipp or ipps.
// Does not verify the correctness of the given URL.
bool ConvertIppToHttp(std::string& url);

#endif  //  PRINT_TOOLS_HELPERS_H_
