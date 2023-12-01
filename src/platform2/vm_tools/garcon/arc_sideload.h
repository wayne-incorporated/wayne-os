// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_GARCON_ARC_SIDELOAD_H_
#define VM_TOOLS_GARCON_ARC_SIDELOAD_H_

#include <string>

namespace vm_tools {
namespace garcon {
class PackageKitProxy;

class ArcSideload {
 public:
  // Enable sideloading android apps into Arc. If something goes wrong, a
  // human-readable error will be written to |out_error|. Returns true if it
  // succeeds.
  static bool Enable(std::string* out_error);

 private:
  // Tracks whether we have successfully added the rules once this session. This
  // will be false until Enable() succeeds. This variable is static so that
  // different instances of ArcSideload will not re-run the same configuration.
  static bool enable_completed_successfully_this_session_;
};

}  // namespace garcon
}  // namespace vm_tools

#endif  // VM_TOOLS_GARCON_ARC_SIDELOAD_H_
