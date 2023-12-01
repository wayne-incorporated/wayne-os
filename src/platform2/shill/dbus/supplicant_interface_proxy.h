// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_SUPPLICANT_INTERFACE_PROXY_H_
#define SHILL_DBUS_SUPPLICANT_INTERFACE_PROXY_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "shill/refptr_types.h"
#include "shill/supplicant/supplicant_interface_proxy_interface.h"
#include "supplicant/dbus-proxies.h"

namespace shill {

class SupplicantEventDelegateInterface;

// SupplicantInterfaceProxy. provides access to wpa_supplicant's
// network-interface APIs via D-Bus.  This takes a delegate, which
// is an interface that is used to send notifications of supplicant
// events.  This pointer is not owned by SupplicantInterfaceProxy
// and must outlive the proxy.
class SupplicantInterfaceProxy : public SupplicantInterfaceProxyInterface {
 public:
  SupplicantInterfaceProxy(const scoped_refptr<dbus::Bus>& bus,
                           const RpcIdentifier& object_path,
                           SupplicantEventDelegateInterface* delegate);
  SupplicantInterfaceProxy(const SupplicantInterfaceProxy&) = delete;
  SupplicantInterfaceProxy& operator=(const SupplicantInterfaceProxy&) = delete;

  ~SupplicantInterfaceProxy() override;

  // Implementation of SupplicantInterfaceProxyInterface.
  bool AddNetwork(const KeyValueStore& args, RpcIdentifier* network) override;
  bool EAPLogon() override;
  bool EAPLogoff() override;
  bool Disconnect() override;
  bool FlushBSS(const uint32_t& age) override;
  bool NetworkReply(const RpcIdentifier& network,
                    const std::string& field,
                    const std::string& value) override;
  bool Reassociate() override;
  bool Reattach() override;
  bool RemoveAllNetworks() override;
  bool RemoveNetwork(const RpcIdentifier& network) override;
  bool Roam(const std::string& addr) override;
  bool Scan(const KeyValueStore& args) override;
  bool SelectNetwork(const RpcIdentifier& network) override;
  bool EnableMacAddressRandomization(const std::vector<unsigned char>& mask,
                                     bool sched_scan) override;
  bool DisableMacAddressRandomization() override;
  // The below set functions will always return true, since PropertySet::Set
  // is an async method. Any failures will be logged in the callback.
  bool SetFastReauth(bool enabled) override;
  bool SetScanInterval(int seconds) override;
  bool SetScan(bool enable) override;
  bool GetCapabilities(KeyValueStore* capabilities) override;
  bool AddCred(const KeyValueStore& args, RpcIdentifier* cred) override;
  bool RemoveCred(const RpcIdentifier& cred) override;
  bool RemoveAllCreds() override;
  bool InterworkingSelect() override;
  bool SignalPoll(KeyValueStore* signalInfo) override;

 private:
  class PropertySet : public dbus::PropertySet {
   public:
    PropertySet(dbus::ObjectProxy* object_proxy,
                const std::string& interface_name,
                const PropertyChangedCallback& callback);
    PropertySet(const PropertySet&) = delete;
    PropertySet& operator=(const PropertySet&) = delete;

    brillo::dbus_utils::Property<bool> fast_reauth;
    brillo::dbus_utils::Property<bool> scan;
    brillo::dbus_utils::Property<int32_t> scan_interval;
    brillo::dbus_utils::Property<bool> sched_scan;
    brillo::dbus_utils::Property<std::map<std::string, std::vector<uint8_t>>>
        mac_address_randomization_mask;
    brillo::dbus_utils::Property<brillo::VariantDictionary> capabilities;

   private:
  };

  static const char kInterfaceName[];
  static const char kPropertyFastReauth[];
  static const char kPropertyScan[];
  static const char kPropertyScanInterval[];
  static const char kPropertySchedScan[];
  static const char kPropertyMacAddressRandomizationMask[];
  static const char kPropertyCapabilities[];

  // Signal handlers.
  void BlobAdded(const std::string& blobname);
  void BlobRemoved(const std::string& blobname);
  void BSSAdded(const dbus::ObjectPath& BSS,
                const brillo::VariantDictionary& properties);
  void BSSRemoved(const dbus::ObjectPath& BSS);
  void Certification(const brillo::VariantDictionary& properties);
  void EAP(const std::string& status, const std::string& parameter);
  void InterworkingAPAdded(const dbus::ObjectPath& BSS,
                           const dbus::ObjectPath& cred,
                           const brillo::VariantDictionary& properties);
  void InterworkingSelectDone();
  void NetworkAdded(const dbus::ObjectPath& network,
                    const brillo::VariantDictionary& properties);
  void NetworkRemoved(const dbus::ObjectPath& network);
  void NetworkSelected(const dbus::ObjectPath& network);
  void PropertiesChanged(const brillo::VariantDictionary& properties);
  void ScanDone(bool success);
  void StationAdded(const dbus::ObjectPath& station,
                    const brillo::VariantDictionary& properties);
  void StationRemoved(const dbus::ObjectPath& station);
  void PskMismatch();

  // Callback invoked when the value of property |property_name| is changed.
  void OnPropertyChanged(const std::string& property_name);

  // Called when signal is connected to the ObjectProxy.
  void OnSignalConnected(const std::string& interface_name,
                         const std::string& signal_name,
                         bool success);

  std::unique_ptr<fi::w1::wpa_supplicant1::InterfaceProxy> interface_proxy_;
  std::unique_ptr<PropertySet> properties_;

  // This pointer is owned by the object that created |this|.  That object
  // MUST destroy |this| before destroying itself.
  SupplicantEventDelegateInterface* delegate_;

  base::WeakPtrFactory<SupplicantInterfaceProxy> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_DBUS_SUPPLICANT_INTERFACE_PROXY_H_
