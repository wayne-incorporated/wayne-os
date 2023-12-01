// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_NOTIFICATIOND_NOTIFICATION_SHELL_INTERFACE_H_
#define VM_TOOLS_NOTIFICATIOND_NOTIFICATION_SHELL_INTERFACE_H_

#include <string>

namespace vm_tools {
namespace notificationd {

// Interface for handling notification shell events.
class NotificationShellInterface {
 public:
  NotificationShellInterface() = default;
  NotificationShellInterface(const NotificationShellInterface&) = delete;
  NotificationShellInterface& operator=(const NotificationShellInterface&) =
      delete;

  virtual ~NotificationShellInterface() = default;

  // Callback for closed event in notification shell.
  virtual void OnClosed(const std::string& notification_key, bool by_user) = 0;

  // Callback for clicked event in notification shell.
  virtual void OnClicked(const std::string& notification_key,
                         int32_t button_index) = 0;
};

}  // namespace notificationd
}  // namespace vm_tools

#endif  // VM_TOOLS_NOTIFICATIOND_NOTIFICATION_SHELL_INTERFACE_H_
