// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_DHCPCD_LISTENER_H_
#define SHILL_DBUS_DHCPCD_LISTENER_H_

#include <string>

#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>
#include <brillo/variant_dictionary.h>
#include <dbus/bus.h>
#include <dbus/message.h>

#include "shill/network/dhcpcd_listener_interface.h"

namespace shill {

class DHCPProvider;
class EventDispatcher;

// The DHCPCD listener is a singleton proxy that listens to signals from all
// DHCP clients and dispatches them through the DHCP provider to the appropriate
// client based on the PID.
class DHCPCDListener final : public DHCPCDListenerInterface {
 public:
  DHCPCDListener(const scoped_refptr<dbus::Bus>& bus,
                 EventDispatcher* dispatcher,
                 DHCPProvider* provider);
  DHCPCDListener(const DHCPCDListener&) = delete;
  DHCPCDListener& operator=(const DHCPCDListener&) = delete;

  ~DHCPCDListener() override;

 private:
  // dbus constants.
  static constexpr char kDBusInterfaceName[] = "org.chromium.dhcpcd";
  static constexpr char kSignalEvent[] = "Event";
  static constexpr char kSignalStatusChanged[] = "StatusChanged";

  // Constants used as event type got from dhcpcd.
  static constexpr char kReasonBound[] = "BOUND";
  static constexpr char kReasonFail[] = "FAIL";
  static constexpr char kReasonGatewayArp[] = "GATEWAY-ARP";
  static constexpr char kReasonNak[] = "NAK";
  static constexpr char kReasonRebind[] = "REBIND";
  static constexpr char kReasonReboot[] = "REBOOT";
  static constexpr char kReasonRenew[] = "RENEW";

  // Possible status string in StatusChanged event from dhcpcd.
  static constexpr char kStatusInit[] = "Init";
  static constexpr char kStatusBound[] = "Bound";
  static constexpr char kStatusRelease[] = "Release";
  static constexpr char kStatusDiscover[] = "Discover";
  static constexpr char kStatusRequest[] = "Request";
  static constexpr char kStatusRenew[] = "Renew";
  static constexpr char kStatusRebind[] = "Rebind";
  static constexpr char kStatusArpSelf[] = "ArpSelf";
  static constexpr char kStatusInform[] = "Inform";
  static constexpr char kStatusReboot[] = "Reboot";
  static constexpr char kStatusNakDefer[] = "NakDefer";
  static constexpr char kStatusIPv6OnlyPreferred[] = "IPv6OnlyPreferred";
  static constexpr char kStatusIgnoreInvalidOffer[] = "IgnoreInvalidOffer";
  static constexpr char kStatusIgnoreFailedOffer[] = "IgnoreFailedOffer";
  static constexpr char kStatusIgnoreAdditionalOffer[] =
      "IgnoreAdditionalOffer";
  static constexpr char kStatusIgnoreNonOffer[] = "IgnoreNonOffer";
  static constexpr char kStatusArpGateway[] = "ArpGateway";

  // Redirects the function call to HandleMessage
  static DBusHandlerResult HandleMessageThunk(DBusConnection* connection,
                                              DBusMessage* raw_message,
                                              void* user_data);

  // Handles incoming messages.
  DBusHandlerResult HandleMessage(DBusConnection* connection,
                                  DBusMessage* raw_message);

  // Signal handlers.
  void EventSignal(const std::string& sender,
                   uint32_t pid,
                   const std::string& reason,
                   const brillo::VariantDictionary& configurations);
  void StatusChangedSignal(const std::string& sender,
                           uint32_t pid,
                           const std::string& status);

  scoped_refptr<dbus::Bus> bus_;
  EventDispatcher* dispatcher_;
  DHCPProvider* provider_;
  const std::string match_rule_;

  base::WeakPtrFactory<DHCPCDListener> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_DBUS_DHCPCD_LISTENER_H_
