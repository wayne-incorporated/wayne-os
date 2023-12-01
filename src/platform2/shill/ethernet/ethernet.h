// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_ETHERNET_ETHERNET_H_
#define SHILL_ETHERNET_ETHERNET_H_

#include <cstdint>
#include <memory>
#include <string>

#include <linux/if.h>

#include <base/cancelable_callback.h>
#include <base/files/file_path.h>
#include <base/memory/weak_ptr.h>
#include <chromeos/patchpanel/dbus/client.h>

#include "shill/certificate_file.h"
#include "shill/device.h"
#include "shill/event_dispatcher.h"
#include "shill/net/ip_address.h"
#include "shill/refptr_types.h"
#include "shill/store/key_value_store.h"
#include "shill/supplicant/supplicant_eap_state_handler.h"
#include "shill/supplicant/supplicant_event_delegate_interface.h"

namespace shill {

class CertificateFile;
class EapListener;
class EthernetEapProvider;
class EthernetProvider;
class Sockets;
class StoreInterface;
class SupplicantEAPStateHandler;
class SupplicantInterfaceProxyInterface;
class SupplicantProcessProxyInterface;

class Ethernet : public Device, public SupplicantEventDelegateInterface {
 public:
  Ethernet(Manager* manager,
           const std::string& link_name,
           const std::string& mac_address,
           int interface_index);
  Ethernet(const Ethernet&) = delete;
  Ethernet& operator=(const Ethernet&) = delete;

  ~Ethernet() override;

  void Start(EnabledStateChangedCallback callback) override;
  void Stop(EnabledStateChangedCallback callback) override;
  void LinkEvent(unsigned int flags, unsigned int change) override;
  bool Load(const StoreInterface* storage) override;
  bool Save(StoreInterface* storage) override;

  virtual void ConnectTo(EthernetService* service);
  virtual void DisconnectFrom(EthernetService* service);

  // Test to see if conditions are correct for EAP authentication (both
  // credentials and a remote EAP authenticator is present) and initiate
  // an authentication if possible.
  virtual void TryEapAuthentication();

  // Implementation of SupplicantEventDelegateInterface.  These methods
  // are called by SupplicantInterfaceProxy, in response to events from
  // wpa_supplicant.
  void BSSAdded(const RpcIdentifier& BSS,
                const KeyValueStore& properties) override;
  void BSSRemoved(const RpcIdentifier& BSS) override;
  void Certification(const KeyValueStore& properties) override;
  void EAPEvent(const std::string& status,
                const std::string& parameter) override;
  void InterworkingAPAdded(const RpcIdentifier& BSS,
                           const RpcIdentifier& cred,
                           const KeyValueStore& properties) override;
  void InterworkingSelectDone() override;
  void PropertiesChanged(const KeyValueStore& properties) override;
  void ScanDone(const bool& /*success*/) override;
  void StationAdded(const RpcIdentifier& Station,
                    const KeyValueStore& properties) override{};
  void StationRemoved(const RpcIdentifier& Station) override{};
  void PskMismatch() override{};

  std::string GetStorageIdentifier() const override;

  // Inherited from Device and responds to a neighbor reachability event from
  // patchpanel. Restarts network validation if the event type contradicts the
  // current connection state (neighbor failure + kStateOnline, or neighbour
  // reachable + kStateNoConnectivity).
  void OnNeighborReachabilityEvent(
      int interface_index,
      const IPAddress& ip_address,
      patchpanel::Client::NeighborRole role,
      patchpanel::Client::NeighborStatus status) override;

  virtual bool link_up() const { return link_up_; }

  const std::string& permanent_mac_address() const {
    return permanent_mac_address_;
  }

 private:
  friend class EthernetTest;
  friend class EthernetServiceTest;  // For weak_ptr_factory_.

  FRIEND_TEST(EthernetProviderTest, MultipleServices);
  FRIEND_TEST(EthernetProviderTest, UpdateLinkSpeed);
  FRIEND_TEST(EthernetProviderTest, UpdateLinkSpeedNoSelectedService);
  FRIEND_TEST(EthernetTest, RunEthtoolCmd);

  // Return a pointer to the EthernetProvider for Ethernet devices.
  EthernetProvider* GetProvider();

  // Return a pointer to the EAP provider for Ethernet devices.
  EthernetEapProvider* GetEapProvider();

  // Return a reference to the shared service that contains EAP credentials
  // for Ethernet.
  ServiceConstRefPtr GetEapService();

  // Invoked by |eap_listener_| when an EAP authenticator is detected.
  void OnEapDetected();

  // Start and stop a supplicant instance on this link.
  bool StartSupplicant();
  void StopSupplicant();

  // Start the EAP authentication process.
  bool StartEapAuthentication();

  // Change our EAP authentication state.
  void SetIsEapAuthenticated(bool is_eap_authenticated);

  // Callback tasks run as a result of event delegate methods.
  void CertificationTask(const std::string& subject, uint32_t depth);
  void EAPEventTask(const std::string& status, const std::string& parameter);
  void SupplicantStateChangedTask(const std::string& state);

  // Callback task run as a result of TryEapAuthentication().
  void TryEapAuthenticationTask();

  SupplicantProcessProxyInterface* supplicant_process_proxy() const;

  // Accessors for the UsbEthernetMacAddressSource property.
  std::string GetUsbEthernetMacAddressSource(Error* error);

  void RegisterService(EthernetServiceRefPtr service);
  void DeregisterService(EthernetServiceRefPtr service);

  void SetupWakeOnLan();
  // Disable Offload features i the network device.
  // Returns true on success, false on failure
  bool DisableOffloadFeatures();

  void SetUsbEthernetMacAddressSource(const std::string& source,
                                      ResultCallback callback) override;

  // Returns hex coded MAC address in lower case and without colons on success.
  // Otherwise returns an empty string.
  virtual std::string ReadMacAddressFromFile(const base::FilePath& file_path);

  // Callback for when netlink sends response on SetInterfaceMac.
  // It runs |callback| with on success or failure. Updates Ethernet MAC address
  // if |error == 0|;
  void OnSetInterfaceMacResponse(const std::string& mac_address_source,
                                 const std::string& new_mac_address,
                                 ResultCallback callback,
                                 int32_t error);
  // Sets new MAC address and reconnects to the |service_| to renew IP address
  // if needed.
  void set_mac_address(const std::string& mac_address) override;

  // Queries the kernel for a permanent MAC address. Returns a permanent MAC
  // address in lower case on success. Otherwise returns an empty string.
  std::string GetPermanentMacAddressFromKernel();

  // Returns device bus type on success. Otherwise, returns empty string.
  std::string GetDeviceBusType() const;

  void UpdateLinkSpeed();

  // Runs ethtool command and returns true when command is successfully
  // run otherwise returns false. Note that |ifr_data| field of
  // |interface_command| should already be set when passed in.
  // |ifr_name| is always set to the name of the interface associated
  // with that Device.
  bool RunEthtoolCmd(ifreq* interface_command);

  // Gets driver name from ETHTOOL and notifies driver name of an ethernet
  // connection to metrics.
  void NotifyEthernetDriverName();

  EthernetServiceRefPtr service_;
  bool link_up_;

  std::string usb_ethernet_mac_address_source_;

  std::string bus_type_;

  // Track whether we have completed EAP authentication successfully.
  bool is_eap_authenticated_;

  // Track whether an EAP authenticator has been detected on this link.
  bool is_eap_detected_;
  std::unique_ptr<EapListener> eap_listener_;

  // Track the progress of EAP authentication.
  SupplicantEAPStateHandler eap_state_handler_;

  // Proxy instances used to talk to wpa_supplicant.
  std::unique_ptr<SupplicantInterfaceProxyInterface>
      supplicant_interface_proxy_;
  RpcIdentifier supplicant_interface_path_;
  RpcIdentifier supplicant_network_path_;

  // Certificate file instance to generate public key data for remote
  // authentication.
  CertificateFile certificate_file_;

  // Make sure TryEapAuthenticationTask is only queued for execution once
  // at a time.
  base::CancelableOnceClosure try_eap_authentication_callback_;

  std::unique_ptr<Sockets> sockets_;

  std::string permanent_mac_address_;

  base::WeakPtrFactory<Ethernet> weak_ptr_factory_;
};

}  // namespace shill

#endif  // SHILL_ETHERNET_ETHERNET_H_
