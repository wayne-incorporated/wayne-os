// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_ROUTE_TOOL_H_
#define DEBUGD_SRC_ROUTE_TOOL_H_

#include <string>
#include <vector>

#include <brillo/variant_dictionary.h>

namespace debugd {

class RouteTool {
 public:
  RouteTool() = default;
  RouteTool(const RouteTool&) = delete;
  RouteTool& operator=(const RouteTool&) = delete;

  ~RouteTool() = default;

  std::vector<std::string> GetRoutes(const brillo::VariantDictionary& options);
};

}  // namespace debugd

#endif  // DEBUGD_SRC_ROUTE_TOOL_H_
