// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_THIRD_PARTY_VPN_DBUS_ADAPTOR_H_
#define SHILL_DBUS_THIRD_PARTY_VPN_DBUS_ADAPTOR_H_

#include <map>
#include <string>
#include <vector>

#include <base/functional/callback.h>
#include <base/memory/ref_counted.h>

#include "dbus_bindings/org.chromium.flimflam.ThirdPartyVpn.h"
#include "shill/adaptor_interfaces.h"
#include "shill/dbus/dbus_adaptor.h"

namespace shill {

class ThirdPartyVpnDriver;

class ThirdPartyVpnDBusAdaptor
    : public org::chromium::flimflam::ThirdPartyVpnAdaptor,
      public org::chromium::flimflam::ThirdPartyVpnInterface,
      public DBusAdaptor,
      public ThirdPartyVpnAdaptorInterface {
 public:
  enum ExternalConnectState {
    kStateConnected = 1,
    kStateFailure,
  };

  ThirdPartyVpnDBusAdaptor(const scoped_refptr<dbus::Bus>& bus,
                           ThirdPartyVpnDriver* client);
  ThirdPartyVpnDBusAdaptor(const ThirdPartyVpnDBusAdaptor&) = delete;
  ThirdPartyVpnDBusAdaptor& operator=(const ThirdPartyVpnDBusAdaptor&) = delete;

  ~ThirdPartyVpnDBusAdaptor() override;

  // Implementation of ThirdPartyVpnAdaptorInterface
  void EmitPacketReceived(const std::vector<uint8_t>& packet) override;
  void EmitPlatformMessage(uint32_t message) override;

  // Implementation of org::chromium::flimflam::ThirdPartyVpnAdaptor
  bool SetParameters(brillo::ErrorPtr* error,
                     const std::map<std::string, std::string>& parameters,
                     std::string* warning_message) override;
  bool UpdateConnectionState(brillo::ErrorPtr* error,
                             uint32_t connection_state) override;
  bool SendPacket(brillo::ErrorPtr* error,
                  const std::vector<uint8_t>& ip_packet) override;

 private:
  ThirdPartyVpnDriver* client_;
};

}  // namespace shill

#endif  // SHILL_DBUS_THIRD_PARTY_VPN_DBUS_ADAPTOR_H_
