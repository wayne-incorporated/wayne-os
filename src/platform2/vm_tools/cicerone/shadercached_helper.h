// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CICERONE_SHADERCACHED_HELPER_H_
#define VM_TOOLS_CICERONE_SHADERCACHED_HELPER_H_

#include <map>
#include <string>
#include <tuple>
#include <vector>

#include <base/synchronization/waitable_event.h>
#include <dbus/object_proxy.h>
#include <shadercached/proto_bindings/shadercached.pb.h>
#include <vm_protos/proto_bindings/container_host.pb.h>

namespace vm_tools::cicerone {

class ShadercachedHelper {
 public:
  explicit ShadercachedHelper(dbus::ObjectProxy* shader_cache_proxy);

  // Install shader cache per request for the specified VM.
  void InstallShaderCache(
      const std::string& owner_id,
      const std::string& vm_name,
      const vm_tools::container::InstallShaderCacheRequest* request,
      std::string* error_out,
      base::WaitableEvent* event,
      dbus::ObjectProxy* shadercached_proxy_);

  // Uninstall shader cache per request for the specified VM.
  void UninstallShaderCache(
      const std::string& owner_id,
      const std::string& vm_name,
      const vm_tools::container::UninstallShaderCacheRequest* request,
      std::string* error_out,
      base::WaitableEvent* event,
      dbus::ObjectProxy* shadercached_proxy_);

  // Uninstall shader cache per request for the specified VM.
  void UnmountShaderCache(
      const std::string& owner_id,
      const std::string& vm_name,
      const vm_tools::container::UnmountShaderCacheRequest* request,
      std::string* error_out,
      base::WaitableEvent* event,
      dbus::ObjectProxy* shadercached_proxy_);

 private:
  struct CallbackCondition {
    std::string vm_name;
    std::string owner_id;
    uint64_t steam_app_id;

    bool const operator==(const CallbackCondition& o) {
      return o.vm_name == vm_name && o.owner_id == owner_id &&
             o.steam_app_id == steam_app_id;
    }

    bool operator<(const CallbackCondition& o) const {
      return vm_name < o.vm_name && owner_id < o.owner_id &&
             steam_app_id < o.steam_app_id;
    }
  };

  // Add a callback with the condition. Returns false if callback already
  // exists for the condition and sets error_out.
  bool AddCallback(const CallbackCondition& condition,
                   bool expected_mount,
                   std::string* error_out,
                   base::WaitableEvent* event_to_notify);

  using MountResultCallback = base::OnceCallback<void(
      const shadercached::ShaderCacheMountStatus& mount_state,
      bool was_replaced)>;

  // This method listens to the D-Bus signal then reads the proto message. It
  // calls the callback that matches the signal in |mount_callbacks_|.
  void MountStatusChanged(dbus::Signal* signal);

  void ConnectedToShadercached(const std::string& interface,
                               const std::string& signal,
                               bool success);

  std::map<CallbackCondition, MountResultCallback> mount_callbacks_;

  base::WeakPtrFactory<ShadercachedHelper> weak_ptr_factory_{this};

  // Set to true upon establishing signal connection to shadercached
  bool connected_;
};

}  // namespace vm_tools::cicerone

#endif  // VM_TOOLS_CICERONE_SHADERCACHED_HELPER_H_
