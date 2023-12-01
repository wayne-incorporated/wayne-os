// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_COMMON_VM_ID_H_
#define VM_TOOLS_COMMON_VM_ID_H_

#include <ostream>
#include <string>
#include <utility>

#include <vm_applications/apps.pb.h>

namespace vm_tools {

namespace apps {
enum VmType : int;
}

class VmId {
 public:
  // This is the de-facto VM type used by most APIs.
  using Type = apps::VmType;

  VmId(const std::string owner_id, const std::string name)
      : id_(std::move(owner_id), std::move(name)) {}

  const std::string& owner_id() const { return id_.first; }
  const std::string& name() const { return id_.second; }

  bool operator==(const VmId& rhs) const { return id_ == rhs.id_; }
  bool operator<(const VmId& rhs) const { return id_ < rhs.id_; }

  friend std::ostream& operator<<(std::ostream& os, const VmId& id) {
    return os << id.owner_id() << '/' << id.name();
  }

 private:
  std::pair<std::string, std::string> id_;
};

}  // namespace vm_tools

#endif  // VM_TOOLS_COMMON_VM_ID_H_
