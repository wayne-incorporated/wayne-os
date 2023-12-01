// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/third_party_vpn_dbus_adaptor.h"

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <chromeos/dbus/service_constants.h>

#include "shill/error.h"
#include "shill/logging.h"
#include "shill/service.h"
#include "shill/vpn/third_party_vpn_driver.h"

namespace shill {

namespace Logging {

static auto kModuleLogScope = ScopeLogger::kVPN;

}  // namespace Logging

namespace {

// The API converts external connection state to internal one
bool ConvertConnectState(
    ThirdPartyVpnDBusAdaptor::ExternalConnectState external_state,
    Service::ConnectState* internal_state) {
  switch (external_state) {
    case ThirdPartyVpnDBusAdaptor::kStateConnected:
      *internal_state = Service::kStateOnline;
      break;
    case ThirdPartyVpnDBusAdaptor::kStateFailure:
      *internal_state = Service::kStateFailure;
      break;
    default:
      return false;
  }
  return true;
}

}  // namespace

ThirdPartyVpnDBusAdaptor::ThirdPartyVpnDBusAdaptor(
    const scoped_refptr<dbus::Bus>& bus, ThirdPartyVpnDriver* client)
    : org::chromium::flimflam::ThirdPartyVpnAdaptor(this),
      DBusAdaptor(bus, kObjectPathBase + client->object_path_suffix()),
      client_(client) {
  // Register DBus object.
  RegisterWithDBusObject(dbus_object());
  dbus_object()->RegisterAndBlock();
}

ThirdPartyVpnDBusAdaptor::~ThirdPartyVpnDBusAdaptor() {
  dbus_object()->UnregisterAndBlock();
}

void ThirdPartyVpnDBusAdaptor::EmitPacketReceived(
    const std::vector<uint8_t>& packet) {
  SLOG(2) << __func__;
  SendOnPacketReceivedSignal(packet);
}

void ThirdPartyVpnDBusAdaptor::EmitPlatformMessage(uint32_t message) {
  SLOG(2) << __func__ << "(" << message << ")";
  SendOnPlatformMessageSignal(message);
}

bool ThirdPartyVpnDBusAdaptor::SetParameters(
    brillo::ErrorPtr* error,
    const std::map<std::string, std::string>& parameters,
    std::string* warning_message) {
  SLOG(2) << __func__;
  std::string error_message;
  Error e;
  client_->SetParameters(parameters, &error_message, warning_message);
  if (!error_message.empty()) {
    e.Populate(Error::kInvalidArguments, error_message);
  }
  return !e.ToChromeosError(error);
}

bool ThirdPartyVpnDBusAdaptor::UpdateConnectionState(
    brillo::ErrorPtr* error, uint32_t connection_state) {
  SLOG(2) << __func__ << "(" << connection_state << ")";
  // Externally supported states are from Service::kStateConnected to
  // Service::kStateOnline.
  Service::ConnectState internal_state;
  std::string error_message;
  Error e;
  if (ConvertConnectState(static_cast<ExternalConnectState>(connection_state),
                          &internal_state)) {
    client_->UpdateConnectionState(internal_state, &error_message);
    if (!error_message.empty()) {
      e.Populate(Error::kInvalidArguments, error_message);
    }
  } else {
    e.Populate(Error::kInternalError,
               "Failed to convert connection_state: " +
                   base::NumberToString(connection_state));
  }
  return !e.ToChromeosError(error);
}

bool ThirdPartyVpnDBusAdaptor::SendPacket(
    brillo::ErrorPtr* error, const std::vector<uint8_t>& ip_packet) {
  SLOG(2) << __func__;
  std::string error_message;
  client_->SendPacket(ip_packet, &error_message);
  Error e;
  if (!error_message.empty()) {
    e.Populate(Error::kWrongState, error_message);
  }
  return !e.ToChromeosError(error);
}

}  // namespace shill
