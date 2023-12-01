// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_PLUGIN_VM_HELPER_H_
#define VM_TOOLS_CONCIERGE_PLUGIN_VM_HELPER_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <dbus/bus.h>

#include "vm_tools/common/vm_id.h"

namespace dbus {
class ObjectProxy;
};  // namespace dbus

namespace vm_tools {
namespace concierge {
namespace pvm {
namespace helper {

bool CreateVm(const VmId& vm_id, std::vector<std::string> params);
bool DeleteVm(const VmId& vm_id);
bool AttachIso(const VmId& vm_id,
               const std::string& cdrom_name,
               const std::string& iso_name);
bool CreateCdromDevice(const VmId& vm_id, const std::string& iso_name);

void CleanUpAfterInstall(const VmId& vm_id, const base::FilePath& iso_path);

bool SetMemorySize(scoped_refptr<dbus::Bus> bus,
                   dbus::ObjectProxy* dispatcher_proxy,
                   const VmId& vm_id,
                   std::vector<std::string> params,
                   std::string* failure_message);

bool ToggleSharedProfile(scoped_refptr<dbus::Bus> bus,
                         dbus::ObjectProxy* dispatcher_proxy,
                         const VmId& vm_id,
                         std::vector<std::string> params,
                         std::string* failure_message);

}  // namespace helper
}  // namespace pvm
}  // namespace concierge
}  // namespace vm_tools

#endif  // VM_TOOLS_CONCIERGE_PLUGIN_VM_HELPER_H_
