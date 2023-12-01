// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_VPN_VPN_PROVIDER_H_
#define SHILL_VPN_VPN_PROVIDER_H_

#include <string>
#include <vector>

#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/ipconfig.h"
#include "shill/provider_interface.h"
#include "shill/refptr_types.h"
#include "shill/technology.h"
#include "shill/virtual_device.h"

namespace shill {

class Error;
class KeyValueStore;
class Manager;

enum class VPNType {
  kARC,
  kIKEv2,
  kL2TPIPsec,
  kOpenVPN,
  kThirdParty,  // Chrome VpnProvider Apps
  kWireGuard,
};

class VPNProvider : public ProviderInterface {
 public:
  // Interface name of the ARC bridge.
  static constexpr base::StringPiece kArcBridgeIfName = "arcbr0";

  // Maps the VPN type between strings and enums. Note that the strings are
  // mainly used in D-Bus interface and profile storage, and we a different set
  // of strings in metrics.
  static std::optional<VPNType> VPNTypeStringToEnum(base::StringPiece type);
  static std::string VPNTypeEnumToString(VPNType type);

  explicit VPNProvider(Manager* manager);
  VPNProvider(const VPNProvider&) = delete;
  VPNProvider& operator=(const VPNProvider&) = delete;

  ~VPNProvider() override;

  // Called by Manager as a part of the Provider interface.  The attributes
  // used for matching services for the VPN provider are the ProviderType,
  // ProviderHost mode and Name parameters.
  void CreateServicesFromProfile(const ProfileRefPtr& profile) override;
  ServiceRefPtr FindSimilarService(const KeyValueStore& args,
                                   Error* error) const override;
  ServiceRefPtr GetService(const KeyValueStore& args, Error* error) override;
  ServiceRefPtr CreateTemporaryService(const KeyValueStore& args,
                                       Error* error) override;
  ServiceRefPtr CreateTemporaryServiceFromProfile(const ProfileRefPtr& profile,
                                                  const std::string& entry_name,
                                                  Error* error) override;
  void Start() override;
  void Stop() override;

  // Clean up a VPN services that has been unloaded and will be deregistered.
  // This removes the VPN provider's reference to this service in its
  // services_ vector.
  void RemoveService(VPNServiceRefPtr service);

  // Returns true if any of the managed VPN services is connecting or connected.
  virtual bool HasActiveService() const;

  // Disconnect any other active VPN services.
  virtual void DisconnectAll();

  // Return a comma-separated string of supported VPN types.
  std::string GetSupportedType();

 private:
  friend class ArcVpnDriverTest;
  friend class L2TPIPsecDriverTest;
  friend class OpenVPNDriverTest;
  friend class VPNProviderTest;
  friend class VPNServiceTest;
  FRIEND_TEST(ThirdPartyVpnDriverTest, SetParameters);
  FRIEND_TEST(VPNProviderTest, ArcDeviceFound);
  FRIEND_TEST(VPNProviderTest, CreateService);
  FRIEND_TEST(VPNProviderTest, CreateArcService);
  FRIEND_TEST(VPNProviderTest, OnDeviceInfoAvailable);
  FRIEND_TEST(VPNProviderTest, RemoveService);
  FRIEND_TEST(VPNServiceTest, AddRemoveVMInterface);
  FRIEND_TEST(VPNServiceTest, Unload);

  // Create a service of type |type| and storage identifier |storage_id|
  // and initial parameters |args|.  Returns a service reference pointer
  // to the newly created service, or populates |error| with an the error
  // that caused this to fail.
  VPNServiceRefPtr CreateServiceInner(const std::string& type,
                                      const std::string& name,
                                      const std::string& storage_id,
                                      Error* error);

  // Calls CreateServiceInner above, and on success registers and adds this
  // service to the provider's list.
  VPNServiceRefPtr CreateService(const std::string& type,
                                 const std::string& name,
                                 const std::string& storage_id,
                                 Error* error);

  // Finds a service of type |type| with its Name property set to |name| and its
  // Provider.Host property set to |host|.
  VPNServiceRefPtr FindService(const std::string& type,
                               const std::string& name,
                               const std::string& host) const;

  Manager* manager_;
  std::vector<VPNServiceRefPtr> services_;
};

}  // namespace shill

#endif  // SHILL_VPN_VPN_PROVIDER_H_
