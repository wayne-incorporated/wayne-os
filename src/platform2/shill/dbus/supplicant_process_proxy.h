// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_SUPPLICANT_PROCESS_PROXY_H_
#define SHILL_DBUS_SUPPLICANT_PROCESS_PROXY_H_

#include <memory>
#include <string>
#include <vector>

#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>

#include "shill/event_dispatcher.h"
#include "shill/supplicant/supplicant_process_proxy_interface.h"
#include "supplicant/dbus-proxies.h"

namespace shill {

class EventDispatcher;

class SupplicantProcessProxy : public SupplicantProcessProxyInterface {
 public:
  SupplicantProcessProxy(
      EventDispatcher* dispatcher,
      const scoped_refptr<dbus::Bus>& bus,
      const base::RepeatingClosure& service_appeared_callback,
      const base::RepeatingClosure& service_vanished_callback);
  SupplicantProcessProxy(const SupplicantProcessProxy&) = delete;
  SupplicantProcessProxy& operator=(const SupplicantProcessProxy&) = delete;

  ~SupplicantProcessProxy() override;

  // Implementation of SupplicantProcessProxyInterface.
  bool CreateInterface(const KeyValueStore& args,
                       RpcIdentifier* rpc_identifier) override;
  bool RemoveInterface(const RpcIdentifier& rpc_identifier) override;
  bool GetInterface(const std::string& ifname,
                    RpcIdentifier* rpc_identifier) override;
  // This function will always return true since PropertySet::Set is an async
  // method. Any failures will be logged in the callback.
  bool SetDebugLevel(const std::string& level) override;
  bool GetDebugLevel(std::string* level) override;
  bool ExpectDisconnect() override;

 private:
  class PropertySet : public dbus::PropertySet {
   public:
    PropertySet(dbus::ObjectProxy* object_proxy,
                const std::string& interface_name,
                const PropertyChangedCallback& callback);
    PropertySet(const PropertySet&) = delete;
    PropertySet& operator=(const PropertySet&) = delete;

    brillo::dbus_utils::Property<std::string> debug_level;
    brillo::dbus_utils::Property<bool> debug_timestamp;
    brillo::dbus_utils::Property<bool> debug_show_keys;
    brillo::dbus_utils::Property<std::vector<dbus::ObjectPath>> interfaces;
    brillo::dbus_utils::Property<std::vector<std::string>> eap_methods;

   private:
  };

  static const char kInterfaceName[];
  static const char kPropertyDebugLevel[];
  static const char kPropertyDebugTimestamp[];
  static const char kPropertyDebugShowKeys[];
  static const char kPropertyInterfaces[];
  static const char kPropertyEapMethods[];

  // Signal handlers.
  void InterfaceAdded(const dbus::ObjectPath& path,
                      const brillo::VariantDictionary& properties);
  void InterfaceRemoved(const dbus::ObjectPath& path);
  void PropertiesChanged(const brillo::VariantDictionary& properties);

  // Called when service appeared or vanished.
  void OnServiceAvailable(bool available);

  // Service name owner changed handler.
  void OnServiceOwnerChanged(const std::string& old_owner,
                             const std::string& new_owner);

  // Callback invoked when the value of property |property_name| is changed.
  void OnPropertyChanged(const std::string& property_name);

  // Called when signal is connected to the ObjectProxy.
  void OnSignalConnected(const std::string& interface_name,
                         const std::string& signal_name,
                         bool success);

  std::unique_ptr<fi::w1::wpa_supplicant1Proxy> supplicant_proxy_;
  std::unique_ptr<PropertySet> properties_;
  EventDispatcher* dispatcher_;
  base::RepeatingClosure service_appeared_callback_;
  base::RepeatingClosure service_vanished_callback_;
  bool service_available_;

  base::WeakPtrFactory<SupplicantProcessProxy> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_DBUS_SUPPLICANT_PROCESS_PROXY_H_
