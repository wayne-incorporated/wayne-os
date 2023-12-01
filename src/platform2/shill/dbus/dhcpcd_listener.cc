// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/dhcpcd_listener.h"

#include <memory>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <brillo/dbus/dbus_method_invoker.h>
#include <dbus/util.h>

#include "shill/event_dispatcher.h"
#include "shill/logging.h"
#include "shill/network/dhcp_controller.h"
#include "shill/network/dhcp_provider.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kDHCP;
}  // namespace Logging

DHCPCDListener::DHCPCDListener(const scoped_refptr<dbus::Bus>& bus,
                               EventDispatcher* dispatcher,
                               DHCPProvider* provider)
    : bus_(bus),
      dispatcher_(dispatcher),
      provider_(provider),
      match_rule_(base::StringPrintf("type='signal', interface='%s'",
                                     kDBusInterfaceName)) {
  bus_->AssertOnDBusThread();
  CHECK(bus_->SetUpAsyncOperations());
  if (!bus_->IsConnected()) {
    LOG(FATAL) << "DBus isn't connected.";
  }

  // Register filter function to the bus.  It will be called when incoming
  // messages are received.
  bus_->AddFilterFunction(&DHCPCDListener::HandleMessageThunk, this);

  // Add match rule to the bus.
  dbus::ScopedDBusError error;
  bus_->AddMatch(match_rule_, error.get());
  if (error.is_set()) {
    LOG(FATAL) << "Failed to add match rule: " << error.name() << " "
               << error.message();
  }
}

DHCPCDListener::~DHCPCDListener() {
  bus_->RemoveFilterFunction(&DHCPCDListener::HandleMessageThunk, this);
  dbus::ScopedDBusError error;
  bus_->RemoveMatch(match_rule_, error.get());
  if (error.is_set()) {
    LOG(FATAL) << "Failed to remove match rule: " << error.name() << " "
               << error.message();
  }
}

// static.
DBusHandlerResult DHCPCDListener::HandleMessageThunk(DBusConnection* connection,
                                                     DBusMessage* raw_message,
                                                     void* user_data) {
  DHCPCDListener* self = static_cast<DHCPCDListener*>(user_data);
  return self->HandleMessage(connection, raw_message);
}

DBusHandlerResult DHCPCDListener::HandleMessage(DBusConnection* connection,
                                                DBusMessage* raw_message) {
  bus_->AssertOnDBusThread();

  // Only interested in signal message.
  if (dbus_message_get_type(raw_message) != DBUS_MESSAGE_TYPE_SIGNAL) {
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
  }

  // raw_message will be unrefed in Signal's parent class's (dbus::Message)
  // destructor. Increment the reference so we can use it in Signal.
  dbus_message_ref(raw_message);
  std::unique_ptr<dbus::Signal> signal(
      dbus::Signal::FromRawMessage(raw_message));

  // Verify the signal comes from the interface that we interested in.
  if (signal->GetInterface() != kDBusInterfaceName) {
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
  }

  const auto sender = signal->GetSender();
  const auto member_name = signal->GetMember();
  dbus::MessageReader reader(signal.get());
  if (member_name == kSignalEvent) {
    uint32_t pid;
    std::string reason;
    brillo::VariantDictionary configurations;
    // ExtractMessageParameters will log the error if it failed.
    if (brillo::dbus_utils::ExtractMessageParameters(
            &reader, nullptr, &pid, &reason, &configurations)) {
      dispatcher_->PostTask(
          FROM_HERE, base::BindOnce(&DHCPCDListener::EventSignal,
                                    weak_factory_.GetWeakPtr(), sender, pid,
                                    reason, configurations));
    }
  } else if (member_name == kSignalStatusChanged) {
    uint32_t pid;
    std::string status;
    // ExtractMessageParameters will log the error if it failed.
    if (brillo::dbus_utils::ExtractMessageParameters(&reader, nullptr, &pid,
                                                     &status)) {
      dispatcher_->PostTask(
          FROM_HERE,
          base::BindOnce(&DHCPCDListener::StatusChangedSignal,
                         weak_factory_.GetWeakPtr(), sender, pid, status));
    }
  } else {
    LOG(INFO) << "Ignore signal: " << member_name;
  }

  return DBUS_HANDLER_RESULT_HANDLED;
}

void DHCPCDListener::EventSignal(
    const std::string& sender,
    uint32_t pid,
    const std::string& reason,
    const brillo::VariantDictionary& configuration) {
  auto* controller = provider_->GetController(pid);
  if (!controller) {
    if (provider_->IsRecentlyUnbound(pid)) {
      SLOG(3) << __func__ << ": ignoring message from recently unbound PID "
              << pid;
    } else {
      LOG(ERROR) << "Unknown DHCP client PID " << pid;
    }
    return;
  }
  LOG(INFO) << "Event reason: " << reason << " on "
            << controller->device_name();

  DHCPController::ClientEventReason parsed_reason =
      DHCPController::ClientEventReason::kUnknown;
  if (reason == kReasonBound) {
    parsed_reason = DHCPController::ClientEventReason::kBound;
  } else if (reason == kReasonFail) {
    parsed_reason = DHCPController::ClientEventReason::kFail;
  } else if (reason == kReasonGatewayArp) {
    parsed_reason = DHCPController::ClientEventReason::kGatewayArp;
  } else if (reason == kReasonNak) {
    parsed_reason = DHCPController::ClientEventReason::kNak;
  } else if (reason == kReasonRebind) {
    parsed_reason = DHCPController::ClientEventReason::kRebind;
  } else if (reason == kReasonReboot) {
    parsed_reason = DHCPController::ClientEventReason::kReboot;
  } else if (reason == kReasonRenew) {
    parsed_reason = DHCPController::ClientEventReason::kRenew;
  }

  controller->InitProxy(sender);
  KeyValueStore configuration_store =
      KeyValueStore::ConvertFromVariantDictionary(configuration);
  controller->ProcessEventSignal(parsed_reason, configuration_store);
}

void DHCPCDListener::StatusChangedSignal(const std::string& sender,
                                         uint32_t pid,
                                         const std::string& status) {
  auto* controller = provider_->GetController(pid);
  if (!controller) {
    if (provider_->IsRecentlyUnbound(pid)) {
      SLOG(3) << __func__ << ": ignoring message from recently unbound PID "
              << pid;
    } else {
      LOG(ERROR) << "Unknown DHCP client PID " << pid;
    }
    return;
  }
  LOG(INFO) << "Status changed: " << status << " on "
            << controller->device_name();

  DHCPController::ClientStatus parsed_status =
      DHCPController::ClientStatus::kUnknown;
  if (status == kStatusIPv6OnlyPreferred) {
    parsed_status = DHCPController::ClientStatus::kIPv6Preferred;
  }

  controller->InitProxy(sender);
  controller->ProcessStatusChangedSignal(parsed_status);
}

}  // namespace shill
