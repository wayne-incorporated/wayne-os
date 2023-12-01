// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_VM_PERMISSION_INTERFACE_H_
#define VM_TOOLS_CONCIERGE_VM_PERMISSION_INTERFACE_H_

#include <string>

#include <dbus/exported_object.h>
#include <dbus/object_proxy.h>

#include <vm_tools/common/vm_id.h>

namespace vm_tools {
namespace concierge {
namespace vm_permission {

dbus::ObjectProxy* GetServiceProxy(scoped_refptr<dbus::Bus> bus);

enum class VmType {
  CROSTINI_VM = 0,
  PLUGIN_VM = 1,
  BOREALIS = 2,
};

bool RegisterVm(scoped_refptr<dbus::Bus> bus,
                dbus::ObjectProxy* proxy,
                const VmId& vm_id,
                VmType type,
                std::string* token);
bool UnregisterVm(scoped_refptr<dbus::Bus> bus,
                  dbus::ObjectProxy* proxy,
                  const VmId& vm_id);

bool IsCameraEnabled(scoped_refptr<dbus::Bus> bus,
                     dbus::ObjectProxy* proxy,
                     const std::string& vm_token);
bool IsMicrophoneEnabled(scoped_refptr<dbus::Bus> bus,
                         dbus::ObjectProxy* proxy,
                         const std::string& vm_token);

}  // namespace vm_permission
}  // namespace concierge
}  // namespace vm_tools

#endif  //  VM_TOOLS_CONCIERGE_VM_PERMISSION_INTERFACE_H_
