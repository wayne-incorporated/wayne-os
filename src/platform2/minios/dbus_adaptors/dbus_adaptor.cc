// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "minios/dbus_adaptors/dbus_adaptor.h"

#include <utility>

#include <brillo/message_loops/message_loop.h>

namespace minios {

DBusService::DBusService(
    std::shared_ptr<MiniOsInterface> mini_os,
    std::shared_ptr<NetworkManagerInterface> network_manager)
    : mini_os_(std::move(mini_os)),
      network_manager_(std::move(network_manager)) {
  network_manager_->AddObserver(this);
}

bool DBusService::GetState(brillo::ErrorPtr* error, State* state_out) {
  return mini_os_->GetState(state_out, error);
}

void DBusService::Connect(ConnectResponse response,
                          const std::string& ssid,
                          const std::string& passphrase) {
  if (connect_response_) {
    response->ReplyWithError(FROM_HERE, brillo::errors::dbus::kDomain,
                             DBUS_ERROR_FAILED,
                             "Another Connect already in progress.");
    return;
  }
  connect_response_ = std::move(response);
  network_manager_->Connect(ssid, passphrase);
}

void DBusService::GetNetworks(GetNetworksResponse response) {
  if (get_networks_response_) {
    response->ReplyWithError(FROM_HERE, brillo::errors::dbus::kDomain,
                             DBUS_ERROR_FAILED,
                             "Another GetNetworks already in progress.");
    return;
  }
  get_networks_response_ = std::move(response);
  network_manager_->GetNetworks();
}

bool DBusService::NextScreen(brillo::ErrorPtr* error) {
  return mini_os_->NextScreen(error);
}

bool DBusService::PressKey(brillo::ErrorPtr* error, uint32_t in_keycode) {
  mini_os_->PressKey(in_keycode);
  return true;
}

bool DBusService::PrevScreen(brillo::ErrorPtr* error) {
  return mini_os_->PrevScreen(error);
}

bool DBusService::ResetState(brillo::ErrorPtr* error) {
  return mini_os_->Reset(error);
}

bool DBusService::SetNetworkCredentials(brillo::ErrorPtr* error,
                                        const std::string& in_ssid,
                                        const std::string& in_passphrase) {
  mini_os_->SetNetworkCredentials(in_ssid, in_passphrase);
  return true;
}

bool DBusService::StartRecovery(brillo::ErrorPtr* error,
                                const std::string& in_ssid,
                                const std::string& in_passphrase) {
  mini_os_->StartRecovery(in_ssid, in_passphrase);
  return true;
}

void DBusService::OnConnect(const std::string& ssid, brillo::Error* error) {
  if (!connect_response_)
    return;
  if (error)
    connect_response_->ReplyWithError(error);
  else
    connect_response_->Return();
  connect_response_.reset();
}

void DBusService::OnGetNetworks(
    const std::vector<NetworkManagerInterface::NetworkProperties>& networks,
    brillo::Error* error) {
  if (!get_networks_response_)
    return;
  if (error) {
    get_networks_response_->ReplyWithError(error);
  } else {
    std::vector<std::string> network_list;
    for (const auto& network : networks) {
      network_list.push_back(network.ssid);
    }
    get_networks_response_->Return(network_list);
  }

  get_networks_response_.reset();
}

DBusAdaptor::DBusAdaptor(std::unique_ptr<DBusService> dbus_service)
    : org::chromium::MiniOsInterfaceAdaptor(dbus_service.get()),
      dbus_service_(std::move(dbus_service)) {}

void DBusAdaptor::StateChanged(const State& state) {
  brillo::MessageLoop::current()->PostTask(
      FROM_HERE, base::BindOnce(&DBusAdaptor::SendMiniOsStateChangedSignal,
                                base::Unretained(this), state));
}

}  // namespace minios
