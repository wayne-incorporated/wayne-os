// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_VMPLUGIN_DISPATCHER_INTERFACE_H_
#define VM_TOOLS_CONCIERGE_VMPLUGIN_DISPATCHER_INTERFACE_H_

#include <string>

#include <base/files/file_path.h>
#include <dbus/exported_object.h>
#include <dbus/object_proxy.h>

#include <vm_tools/common/vm_id.h>

namespace vm_tools {
namespace concierge {
namespace pvm {
namespace dispatcher {

enum class VmOpResult {
  SUCCESS,
  INTERNAL_ERROR,            // Failed to call to dispatcher or parse response.
  DISPATCHER_NOT_AVAILABLE,  // DBus call to dispatcher failed because the
                             // service is not there.
  DISPATCHER_TIMEOUT,        // DBus call to dispatcher timed out.
  DISPATCHER_SHUTTING_DOWN,
  DISPATCHER_LICENSE_ERROR,
  DISPATCHER_GENERIC_ERROR,
};

dbus::ObjectProxy* GetServiceProxy(scoped_refptr<dbus::Bus> bus);

bool RegisterVm(scoped_refptr<dbus::Bus> bus,
                dbus::ObjectProxy* proxy,
                const VmId& vm_id,
                const base::FilePath& disk_image_path);
bool UnregisterVm(scoped_refptr<dbus::Bus> bus,
                  dbus::ObjectProxy* proxy,
                  const VmId& vm_id);

bool IsVmRegistered(scoped_refptr<dbus::Bus> bus,
                    dbus::ObjectProxy* proxy,
                    const VmId& vm_id,
                    bool* result);
bool IsVmShutDown(scoped_refptr<dbus::Bus> bus,
                  dbus::ObjectProxy* proxy,
                  const VmId& vm_id,
                  bool* result);

VmOpResult ShutdownVm(scoped_refptr<dbus::Bus> bus,
                      dbus::ObjectProxy* proxy,
                      const VmId& vm_id);
VmOpResult SuspendVm(scoped_refptr<dbus::Bus> bus,
                     dbus::ObjectProxy* proxy,
                     const VmId& vm_id);

void RegisterVmToolsChangedCallbacks(
    dbus::ObjectProxy* proxy,
    dbus::ObjectProxy::SignalCallback cb,
    dbus::ObjectProxy::OnConnectedCallback on_connected_cb);
bool ParseVmToolsChangedSignal(dbus::Signal* signal,
                               std::string* owner_id,
                               std::string* vm_name,
                               bool* running);

}  // namespace dispatcher
}  // namespace pvm
}  // namespace concierge
}  // namespace vm_tools

#endif  //  VM_TOOLS_CONCIERGE_VMPLUGIN_DISPATCHER_INTERFACE_H_
