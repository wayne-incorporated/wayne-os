// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_NOTIFICATIOND_NOTIFICATION_DAEMON_H_
#define VM_TOOLS_NOTIFICATIOND_NOTIFICATION_DAEMON_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <brillo/message_loops/base_message_loop.h>

#include "vm_tools/notificationd/dbus_interface.h"
#include "vm_tools/notificationd/dbus_service.h"
#include "vm_tools/notificationd/notification_shell_client.h"
#include "vm_tools/notificationd/notification_shell_interface.h"

namespace vm_tools {
namespace notificationd {

// Handles D-BUS server for notification and Wayland client for notification.
// Once the D-BUS server recieves notification event, the daemon forwards it via
// the Wayland client.
class NotificationDaemon : public DBusInterface,
                           public NotificationShellInterface {
 public:
  // Creates and returns a NotificationDaemon. Returns nullptr if the the daemon
  // failed to be initialized for any reason.
  static std::unique_ptr<NotificationDaemon> Create(
      const std::string& display_name,
      const std::string& virtwl_device,
      base::OnceClosure quit_closure);

  ~NotificationDaemon() override = default;

  // DBusInterface overrides.
  bool GetCapabilities(std::vector<std::string>* out_capabilities) override;
  bool Notify(const NotifyArgument& input, uint32_t* out_id) override;
  bool GetServerInformation(ServerInformation* output) override;
  bool CloseNotification(uint32_t id) override;

  // NotificationShellInterface overrides.
  void OnClosed(const std::string& notification_key, bool by_user) override;
  void OnClicked(const std::string& notification_key,
                 int32_t button_index) override;

 private:
  // Used for conversion from the events of notification-shell (clicking buttons
  // and body) to those of org.freedesktop.Notifications (ActionInvoled).
  struct ClickAction {
    std::vector<std::string> action_keys_for_buttons;
    bool default_action_enabled = false;
  };

  NotificationDaemon() = default;
  NotificationDaemon(const NotificationDaemon&) = delete;
  NotificationDaemon& operator=(const NotificationDaemon&) = delete;

  // Initializes the notification daemon. Returns true on success.
  bool Init(const std::string& display_name,
            const std::string& virtwl_device,
            base::OnceClosure quit_closure);

  std::unique_ptr<NotificationShellClient> notification_shell_client_;
  std::unique_ptr<DBusService> dbus_service_;

  // Incremental notification id handled by this daemon. Notification id starts
  // from 1 according to the spec of org.freedesktop.Notifications.
  uint32_t id_count_ = 1;

  // Clicking action conversion mapping for each notification id.
  std::map<uint32_t, ClickAction> click_actions;

  FRIEND_TEST(DBusServiceTest, GetCapabilities);
  FRIEND_TEST(DBusServiceTest, Notify);
  FRIEND_TEST(DBusServiceTest, GetServerInformation);
};

}  // namespace notificationd
}  // namespace vm_tools

#endif  // VM_TOOLS_NOTIFICATIOND_NOTIFICATION_DAEMON_H_
