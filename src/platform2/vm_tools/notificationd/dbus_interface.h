// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_NOTIFICATIOND_DBUS_INTERFACE_H_
#define VM_TOOLS_NOTIFICATIOND_DBUS_INTERFACE_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest_prod.h>

namespace vm_tools {
namespace notificationd {

// Interface for org.freedesktop.Notifications according to the Desktop
// Notifications Specification here:
// https://developer.gnome.org/notification-spec/
class DBusInterface {
 public:
  // Argument for notify method in org.freedesktop.notifications according
  // to the Desktop Notifications Specification here:
  // https://developer.gnome.org/notification-spec/
  struct NotifyArgument {
    std::string app_name;
    uint32_t replaces_id = 0;
    std::string app_icon;
    std::string summary;
    std::string body;
    std::vector<std::string> actions;
    std::map<std::string, std::string> hints;
    int32_t expire_timeout = 0;
  };

  // Output for GetServerInformation method in org.freedesktop.notifications
  // according to the Desktop Notifications Specification here:
  // https://developer.gnome.org/notification-spec/
  struct ServerInformation {
    std::string name;
    std::string vendor;
    std::string version;
    std::string spec_version;
  };

  DBusInterface() = default;
  DBusInterface(const DBusInterface&) = delete;
  DBusInterface& operator=(const DBusInterface&) = delete;

  virtual ~DBusInterface() = default;

  // Callback for GetCapabilities in org.freedesktop.notifications. Returns true
  // on success.
  virtual bool GetCapabilities(std::vector<std::string>* out_capabilities) = 0;

  // Callback for Notify in org.freedesktop.notifications. Returns true on
  // success.
  virtual bool Notify(const NotifyArgument& input, uint32_t* out_id) = 0;

  // Callback for GetServerInformation in org.freedesktop.notifications. Returns
  // true on success.
  virtual bool GetServerInformation(ServerInformation* output) = 0;

  // Callback for CloseNotification in org.freedesktop.notifications. Returns
  // true on success.
  virtual bool CloseNotification(uint32_t id) = 0;
};

}  // namespace notificationd
}  // namespace vm_tools

#endif  // VM_TOOLS_NOTIFICATIOND_DBUS_INTERFACE_H_
