// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_DBUS_ADAPTORS_DBUS_ADAPTOR_H_
#define MINIOS_DBUS_ADAPTORS_DBUS_ADAPTOR_H_

#include <memory>
#include <string>
#include <vector>

#include <brillo/dbus/dbus_method_response.h>
#include <minios/proto_bindings/minios.pb.h>

#include "minios/dbus_adaptors/org.chromium.MiniOsInterface.h"
#include "minios/minios_interface.h"
#include "minios/network_manager_interface.h"
#include "minios/state_reporter_interface.h"

namespace minios {

class DBusService : public org::chromium::MiniOsInterfaceInterface,
                    public NetworkManagerInterface::Observer {
 public:
  explicit DBusService(
      std::shared_ptr<MiniOsInterface> mini_os,
      std::shared_ptr<NetworkManagerInterface> network_manager);
  ~DBusService() = default;

  DBusService(const DBusService&) = delete;
  DBusService& operator=(const DBusService&) = delete;

  bool GetState(brillo::ErrorPtr* error, State* state_out) override;

  using ConnectResponse =
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<>>;
  void Connect(ConnectResponse response,
               const std::string& ssid,
               const std::string& passphrase) override;

  using GetNetworksResponse = std::unique_ptr<
      brillo::dbus_utils::DBusMethodResponse<std::vector<std::string>>>;
  void GetNetworks(GetNetworksResponse response) override;

  bool NextScreen(brillo::ErrorPtr* error) override;
  bool PressKey(brillo::ErrorPtr* error, uint32_t in_keycode) override;
  bool PrevScreen(brillo::ErrorPtr* error) override;
  bool ResetState(brillo::ErrorPtr* error) override;
  bool SetNetworkCredentials(brillo::ErrorPtr* error,
                             const std::string& in_ssid,
                             const std::string& in_passphrase) override;
  bool StartRecovery(brillo::ErrorPtr* error,
                     const std::string& in_ssid,
                     const std::string& in_passphrase) override;

 private:
  // `NetworkManagerInterface::Observer` overrides.
  void OnConnect(const std::string& ssid, brillo::Error* error) override;
  void OnGetNetworks(
      const std::vector<NetworkManagerInterface::NetworkProperties>& networks,
      brillo::Error* error) override;

  std::shared_ptr<MiniOsInterface> mini_os_;

  ConnectResponse connect_response_;
  GetNetworksResponse get_networks_response_;
  std::shared_ptr<NetworkManagerInterface> network_manager_;
};

class DBusAdaptor : public org::chromium::MiniOsInterfaceAdaptor,
                    public StateReporterInterface {
 public:
  explicit DBusAdaptor(std::unique_ptr<DBusService> dbus_service);
  ~DBusAdaptor() = default;

  DBusAdaptor(const DBusAdaptor&) = delete;
  DBusAdaptor& operator=(const DBusAdaptor&) = delete;

  // StateReporterInterface overrides.
  void StateChanged(const State& state) override;

 private:
  std::unique_ptr<DBusService> dbus_service_;
};

}  // namespace minios

#endif  // MINIOS_DBUS_ADAPTORS_DBUS_ADAPTOR_H_
