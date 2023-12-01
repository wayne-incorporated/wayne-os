// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_GARCON_SCREENSAVER_DBUS_SERVICE_H_
#define VM_TOOLS_GARCON_SCREENSAVER_DBUS_SERVICE_H_

#include <memory>
#include <string>

#include <dbus/bus.h>
#include <dbus/exported_object.h>
#include <dbus/message.h>

#include "vm_tools/garcon/host_notifier.h"

namespace vm_tools {
namespace garcon {

class ScreenSaverDBusService {
 public:
  ~ScreenSaverDBusService() = default;

  static std::unique_ptr<ScreenSaverDBusService> Create(
      vm_tools::garcon::HostNotifier* host_notifier);

 private:
  explicit ScreenSaverDBusService(
      vm_tools::garcon::HostNotifier* host_notifier);
  ScreenSaverDBusService(const ScreenSaverDBusService&) = delete;
  ScreenSaverDBusService& operator=(const ScreenSaverDBusService&) = delete;

  bool RegisterMethods();

  std::unique_ptr<dbus::Response> Inhibit(dbus::MethodCall* method_call);
  std::unique_ptr<dbus::Response> Uninhibit(dbus::MethodCall* method_call);

  bool Init();

  scoped_refptr<dbus::Bus> bus_;
  dbus::ExportedObject* exported_object_ = nullptr;  // Owned by |bus_|.

  // The cookie used to reply to inhibit. Incremented by 1 each time.
  uint32_t cookie_counter_ = 1;

  vm_tools::garcon::HostNotifier* host_notifier_ = nullptr;
};

}  // namespace garcon
}  // namespace vm_tools

#endif  // VM_TOOLS_GARCON_SCREENSAVER_DBUS_SERVICE_H_
