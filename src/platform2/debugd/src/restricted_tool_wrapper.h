// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// This file provides the RestrictedToolWrapper template class, which helps
// control access to tools that should not always be available for use. Typical
// usage will look something like this:
//
//   // Instantiate the tool wrapper.
//   RestrictedToolWrapper<FooTool>* foo_tool_wrapper =
//       new RestrictedToolWrapper<FooTool>(...);
//
//   // Unwrap and use the tool.
//   brillo::ErrorPtr error;
//   int result = 0;
//   FooTool* tool = foo_tool_wrapper->GetTool(&error);
//   if (tool)
//     tool->ToolFunction(&error);
//
// Some advantages of using a wrapper rather than putting the condition check
// inside the tool functions themselves are:
//   1. Conditions are declared in a single location during tool instantiation,
//      rather than being spread around into each tool implementation.
//   2. The compiler prevents forgotten condition checks, since trying to use a
//      wrapper directly will cause compilation errors. This becomes important
//      with multiple access-restricted functions to avoid having to manually
//      put the right condition in each one.
//   3. Reusability - currently only the DevFeaturesTool class is wrapped,
//      but the template wrapper could be applied to future classes without
//      any condition logic in the classes themselves.

#ifndef DEBUGD_SRC_RESTRICTED_TOOL_WRAPPER_H_
#define DEBUGD_SRC_RESTRICTED_TOOL_WRAPPER_H_

#include <brillo/errors/error.h>

#include "debugd/src/dev_mode_no_owner_restriction.h"

namespace debugd {

// Templated wrapper to enforce tool access restrictions. See comments at the
// top of the file for usage notes.
template <class T>
class RestrictedToolWrapper {
 public:
  // Tools without a default constructor may need specialized
  // RestrictedToolWrapper classes for additional constructor parameters. If
  // possible, use a tool Initialize() function instead of passing additional
  // parameters to the constructor.
  explicit RestrictedToolWrapper(scoped_refptr<dbus::Bus> bus)
      : restriction_(bus) {}
  RestrictedToolWrapper(const RestrictedToolWrapper&) = delete;
  RestrictedToolWrapper& operator=(const RestrictedToolWrapper&) = delete;

  ~RestrictedToolWrapper() = default;

  // Returns a raw pointer to the underlying tool instance if both conditions
  // from the DevModeNoOwnerRestriction class are met:
  //   1. Device is in dev mode.
  //   2. Device has no owner.
  // Otherwise, returns nullptr and |error| is set (if it's non-null).
  //
  // Do not store the direct tool pointer longer than needed for immediate use,
  // to avoid bypassing the wrapper's condition checks.
  T* GetTool(brillo::ErrorPtr* error) {
    if (restriction_.AllowToolUse(error)) {
      return &tool_;
    }
    return nullptr;
  }

  const DevModeNoOwnerRestriction& restriction() const { return restriction_; }

 private:
  T tool_;
  DevModeNoOwnerRestriction restriction_;
};

}  // namespace debugd

#endif  // DEBUGD_SRC_RESTRICTED_TOOL_WRAPPER_H_
