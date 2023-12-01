// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_SENESCHAL_SERVER_PROXY_H_
#define VM_TOOLS_CONCIERGE_SENESCHAL_SERVER_PROXY_H_

#include <stdint.h>

#include <memory>
#include <utility>
#include <vector>

#include <base/files/scoped_file.h>
#include <dbus/object_proxy.h>
#include <seneschal/proto_bindings/seneschal_service.pb.h>

namespace vm_tools {
namespace concierge {

// Represents a running shared directory server.
class SeneschalServerProxy final {
 public:
  // Ask the seneschal service to start a new 9P server.  Callers must ensure
  // that the |seneschal_proxy| object outlives this object.
  static std::unique_ptr<SeneschalServerProxy> CreateVsockProxy(
      scoped_refptr<dbus::Bus> bus,
      dbus::ObjectProxy* seneschal_proxy,
      uint32_t port,
      uint32_t accept_cid,
      std::vector<std::pair<uint32_t, uint32_t>> uid_map,
      std::vector<std::pair<uint32_t, uint32_t>> gid_map);
  static std::unique_ptr<SeneschalServerProxy> CreateFdProxy(
      scoped_refptr<dbus::Bus> bus,
      dbus::ObjectProxy* seneschal_proxy,
      const base::ScopedFD& socket_fd);

  ~SeneschalServerProxy();

  uint32_t handle() const { return handle_; }

 private:
  SeneschalServerProxy(scoped_refptr<dbus::Bus> bus,
                       dbus::ObjectProxy* seneschal_proxy,
                       uint32_t handle);
  SeneschalServerProxy(const SeneschalServerProxy&) = delete;
  SeneschalServerProxy& operator=(const SeneschalServerProxy&) = delete;

  static std::unique_ptr<SeneschalServerProxy> SeneschalCreateProxy(
      scoped_refptr<dbus::Bus> bus,
      dbus::ObjectProxy* seneschal_proxy,
      dbus::MethodCall* method_call);

  scoped_refptr<dbus::Bus> bus_;

  // Proxy to the seneschal service.  Not owned.
  dbus::ObjectProxy* seneschal_proxy_;

  // The handle for this server.
  uint32_t handle_;
};

}  // namespace concierge
}  // namespace vm_tools

#endif  // VM_TOOLS_CONCIERGE_SENESCHAL_SERVER_PROXY_H_
