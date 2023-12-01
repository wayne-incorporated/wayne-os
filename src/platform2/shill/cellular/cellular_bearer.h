// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_CELLULAR_BEARER_H_
#define SHILL_CELLULAR_CELLULAR_BEARER_H_

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <gtest/gtest_prod.h>

#include "shill/cellular/apn_list.h"
#include "shill/ipconfig.h"

namespace shill {

class DBusPropertiesProxy;
class ControlInterface;

// A class for observing property changes of a bearer object exposed by
// ModemManager.
class CellularBearer {
 public:
  // ModemManager Bearer Properties.
  static const char kMMApnProperty[];
  static const char kMMApnTypeProperty[];
  static const char kMMUserProperty[];
  static const char kMMPasswordProperty[];
  static const char kMMAllowedAuthProperty[];
  static const char kMMAllowRoamingProperty[];
  static const char kMMIpTypeProperty[];

  enum class IPConfigMethod { kUnknown, kPPP, kStatic, kDHCP };

  // Constructs a cellular bearer for observing property changes of a
  // corresponding bearer object, at the DBus path |dbus_path| of DBus service
  // |dbus_service|,  exposed by ModemManager. The ownership of
  // |control_interface| is not transferred, and should outlive this object.
  //
  // TODO(benchan): Use a context object approach to pass objects like
  // ControlInterface through constructor.
  CellularBearer(ControlInterface* control_interface,
                 const RpcIdentifier& dbus_path,
                 const std::string& dbus_service);
  CellularBearer(const CellularBearer&) = delete;
  CellularBearer& operator=(const CellularBearer&) = delete;

  ~CellularBearer();

  // Initializes this object by creating a DBus properties proxy to observe
  // property changes of the corresponding bearer object exposed by ModemManager
  // and also fetching the current properties of the bearer.  Returns true on
  // success or false if it fails to the DBus properties proxy.
  bool Init();

  // Callback upon property changes of the bearer.
  void OnPropertiesChanged(const std::string& interface,
                           const KeyValueStore& changed_properties);

  const RpcIdentifier& dbus_path() const { return dbus_path_; }
  const std::string& dbus_service() const { return dbus_service_; }

  bool connected() const { return connected_; }
  const std::string& data_interface() const { return data_interface_; }
  IPConfigMethod ipv4_config_method() const { return ipv4_config_method_; }
  const IPConfig::Properties* ipv4_config_properties() const {
    return ipv4_config_properties_.get();
  }
  IPConfigMethod ipv6_config_method() const { return ipv6_config_method_; }
  const IPConfig::Properties* ipv6_config_properties() const {
    return ipv6_config_properties_.get();
  }

  const std::string& apn() const { return apn_; }
  const std::vector<ApnList::ApnType>& apn_types() const { return apn_types_; }

  // Setters for unit tests.
  void set_connected_for_testing(bool connected) { connected_ = connected; }
  void set_data_interface_for_testing(const std::string& data_interface) {
    data_interface_ = data_interface;
  }
  void set_ipv4_config_method_for_testing(IPConfigMethod ipv4_config_method) {
    ipv4_config_method_ = ipv4_config_method;
  }
  void set_ipv4_config_properties_for_testing(
      std::unique_ptr<IPConfig::Properties> ipv4_config_properties) {
    ipv4_config_properties_ = std::move(ipv4_config_properties);
  }
  void set_ipv6_config_method_for_testing(IPConfigMethod ipv6_config_method) {
    ipv6_config_method_ = ipv6_config_method;
  }
  void set_ipv6_config_properties_for_testing(
      std::unique_ptr<IPConfig::Properties> ipv6_config_properties) {
    ipv6_config_properties_ = std::move(ipv6_config_properties);
  }
  void set_apn_type_for_testing(ApnList::ApnType apn_type) {
    apn_types_.push_back(apn_type);
  }

 private:
  // Gets the IP configuration method and properties from |properties|.
  // |address_family| specifies the IP address family of the configuration.
  // |ipconfig_method| and |ipconfig_properties| are used to return the IP
  // configuration method and properties and should be non-NULL.
  void GetIPConfigMethodAndProperties(
      const KeyValueStore& properties,
      IPAddress::Family address_family,
      IPConfigMethod* ipconfig_method,
      std::unique_ptr<IPConfig::Properties>* ipconfig_properties) const;

  // Resets bearer properties.
  void ResetProperties();

  // Updates bearer properties by fetching the current properties of the
  // corresponding bearer object exposed by ModemManager over DBus.
  void UpdateProperties();

  ControlInterface* control_interface_;
  RpcIdentifier dbus_path_;
  std::string dbus_service_;
  std::unique_ptr<DBusPropertiesProxy> dbus_properties_proxy_;
  bool connected_ = false;
  std::string data_interface_;

  // If |ipv4_config_method_| is set to |IPConfigMethod::kStatic|,
  // |ipv4_config_properties_| is guaranteed to contain valid IP configuration
  // properties. Otherwise, |ipv4_config_properties_| is set to nullptr.
  // |ipv6_config_properties_| is handled similarly.
  IPConfigMethod ipv4_config_method_ = IPConfigMethod::kUnknown;
  std::unique_ptr<IPConfig::Properties> ipv4_config_properties_;
  IPConfigMethod ipv6_config_method_ = IPConfigMethod::kUnknown;
  std::unique_ptr<IPConfig::Properties> ipv6_config_properties_;

  // Properties that were used to create the bearer, just the ones we need
  // in the already created bearer
  std::string apn_;
  std::vector<ApnList::ApnType> apn_types_;

  base::WeakPtrFactory<CellularBearer> weak_ptr_factory_{this};
};

}  // namespace shill

#endif  // SHILL_CELLULAR_CELLULAR_BEARER_H_
