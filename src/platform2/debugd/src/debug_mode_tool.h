// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_DEBUG_MODE_TOOL_H_
#define DEBUGD_SRC_DEBUG_MODE_TOOL_H_

#include <string>
#include <vector>

#include <base/memory/ref_counted.h>
#include <dbus/bus.h>

namespace debugd {

class DebugModeTool {
 public:
  explicit DebugModeTool(scoped_refptr<dbus::Bus> bus);
  DebugModeTool(const DebugModeTool&) = delete;
  DebugModeTool& operator=(const DebugModeTool&) = delete;

  virtual ~DebugModeTool() = default;

  virtual void SetDebugMode(const std::string& subsystem);

 private:
  void SetModemManagerLogging(const std::string& level);

  scoped_refptr<dbus::Bus> bus_;
};

}  // namespace debugd

#endif  // DEBUGD_SRC_DEBUG_MODE_TOOL_H_
