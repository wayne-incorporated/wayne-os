// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// This tool is used for getting dmesg information through debugd.

#ifndef DEBUGD_SRC_DMESG_TOOL_H_
#define DEBUGD_SRC_DMESG_TOOL_H_

#include <stdint.h>

#include <string>

#include <brillo/errors/error.h>
#include <brillo/variant_dictionary.h>

namespace debugd {

class DmesgTool {
 public:
  DmesgTool() = default;
  DmesgTool(const DmesgTool&) = delete;
  DmesgTool& operator=(const DmesgTool&) = delete;

  ~DmesgTool() = default;

  bool CallDmesg(const brillo::VariantDictionary& options,
                 brillo::ErrorPtr* error,
                 std::string* output);

  // If |output| has more than |lines| lines, trim output to only contain the
  // last |lines| lines. Basically /usr/bin/tail.
  static void Tail(uint32_t lines, std::string& output);
};

}  // namespace debugd

#endif  // DEBUGD_SRC_DMESG_TOOL_H_
