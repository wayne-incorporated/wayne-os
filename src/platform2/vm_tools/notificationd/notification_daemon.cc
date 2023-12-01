// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/notificationd/notification_daemon.h"

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/strings/string_number_conversions.h>

#include "vm_tools/notificationd/notification_shell_client.h"

namespace {

constexpr char kNotificationsServerName[] = "notificationd";
constexpr char kNotificationsVendor[] = "Chromium OS";
constexpr char kNotificationsVersion[] = "1.0";
constexpr char kNotificationsSpecVersion[] = "1.2";
constexpr char kDefaultActionKey[] = "default";

}  // namespace

namespace vm_tools {
namespace notificationd {

// static
std::unique_ptr<NotificationDaemon> NotificationDaemon::Create(
    const std::string& display_name,
    const std::string& virtwl_device,
    base::OnceClosure quit_closure) {
  auto daemon = base::WrapUnique(new NotificationDaemon());

  if (!daemon->Init(display_name, virtwl_device, std::move(quit_closure))) {
    LOG(ERROR) << "Failed to initialize notification daemon";
    return nullptr;
  }

  return daemon;
}

bool NotificationDaemon::Init(const std::string& display_name,
                              const std::string& virtwl_device,
                              base::OnceClosure quit_closure) {
  notification_shell_client_ = NotificationShellClient::Create(
      display_name, virtwl_device, this, std::move(quit_closure));
  if (!notification_shell_client_) {
    LOG(ERROR) << "Failed to create notification shell client";
    return false;
  }

  dbus_service_ = DBusService::Create(this);
  if (!dbus_service_) {
    LOG(ERROR) << "Failed to create D-BUS service";
    return false;
  }

  return true;
}

bool NotificationDaemon::GetCapabilities(
    std::vector<std::string>* out_capabilities) {
  out_capabilities->emplace_back("actions");
  out_capabilities->emplace_back("body");
  return true;
}

bool NotificationDaemon::Notify(const NotifyArgument& input, uint32_t* out_id) {
  // Convert org.freedesktop.Notifications-style actions to notification
  // shell-style buttons and body clicking. According to
  // org.freedesktop.Notifications spec, each even element (including 0) of
  // |actions| represents action_key and the next element of it represents its
  // action title that will be displayed to the user. If action_key is
  // "default", it means clicking the body of notification instead of buttons.
  ClickAction click_action;
  std::vector<std::string> button_titles;
  if (input.actions.size() % 2 != 0) {
    LOG(ERROR) << "The size of actions must be even";
    return false;
  }
  for (int i = 0; i < input.actions.size(); i += 2) {
    auto action_key = input.actions[i];
    auto button_title = input.actions[i + 1];
    if (action_key == kDefaultActionKey) {
      click_action.default_action_enabled = true;
    } else {
      click_action.action_keys_for_buttons.emplace_back(std::move(action_key));
      button_titles.emplace_back(std::move(button_title));
    }
  }

  // If replaces_id is given, check if the notification id exists and use it as
  // a notification id. Else, use an incremental id as a notification id.
  if (input.replaces_id != 0) {
    *out_id = input.replaces_id;
    if (click_actions.find(*out_id) == click_actions.end()) {
      LOG(ERROR) << "No such notification id exists";
      return false;
    }
  } else {
    *out_id = id_count_;
    id_count_++;
  }

  // The |click_action| is needed to convert notification shell-style button and
  // body click event to org.freedesktop.Notifications-style action event. So,
  // store it with its notification id.
  click_actions.emplace(*out_id, click_action);

  // Forward notification request to host via Wayland.
  if (!notification_shell_client_->CreateNotification(
          input.summary, input.body, input.app_name, std::to_string(*out_id),
          button_titles)) {
    LOG(ERROR) << "Failed to request create_notification to host";
    return false;
  }
  return true;
}

bool NotificationDaemon::GetServerInformation(ServerInformation* output) {
  output->name = kNotificationsServerName;
  output->vendor = kNotificationsVendor;
  output->version = kNotificationsVersion;
  output->spec_version = kNotificationsSpecVersion;

  return true;
}

bool NotificationDaemon::CloseNotification(uint32_t id) {
  // Forward closing request to host via Wayland.
  if (!notification_shell_client_->CloseNotification(std::to_string(id))) {
    LOG(ERROR) << "Failed to request to close notification";
    return false;
  }
  return true;
}

void NotificationDaemon::OnClosed(const std::string& notification_key,
                                  bool by_user) {
  uint32_t id = 0;
  auto ret = base::StringToUint(notification_key, &id);
  DCHECK(ret);
  // Forward notification closed event to client via D-Bus.
  dbus_service_->SendNotificationClosedSignal(
      id, by_user ? DBusService::ClosedReason::BY_USER
                  : DBusService::ClosedReason::BY_REQUEST);

  DCHECK(click_actions.find(id) != click_actions.end());
  click_actions.erase(id);
}

void NotificationDaemon::OnClicked(const std::string& notification_key,
                                   int32_t button_index) {
  uint32_t id = 0;
  bool ret = base::StringToUint(notification_key, &id);
  DCHECK(ret);
  DCHECK(click_actions.find(id) != click_actions.end());

  // Convert |button_index| into action key using |click_action|.
  const auto click_action = click_actions[id];
  std::string action_key;
  if (button_index == -1) {
    if (click_action.default_action_enabled) {
      action_key = kDefaultActionKey;
    }
  } else {
    CHECK_LT(button_index, click_action.action_keys_for_buttons.size());
    action_key = click_action.action_keys_for_buttons[button_index];
  }

  // Forward notification clicked event to client via D-Bus if associated action
  // key exists.
  if (!action_key.empty()) {
    dbus_service_->SendActionInvokedSignal(id, action_key);
  }
}

}  // namespace notificationd
}  // namespace vm_tools
