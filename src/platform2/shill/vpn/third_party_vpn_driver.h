// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_VPN_THIRD_PARTY_VPN_DRIVER_H_
#define SHILL_VPN_THIRD_PARTY_VPN_DRIVER_H_

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <base/functional/callback.h>
#include <gtest/gtest_prod.h>

#include "shill/ipconfig.h"
#include "shill/net/io_handler.h"
#include "shill/vpn/vpn_driver.h"

namespace shill {

class Error;
class FileIO;
class IOHandlerFactory;
class ThirdPartyVpnAdaptorInterface;

class ThirdPartyVpnDriver : public VPNDriver {
 public:
  enum PlatformMessage {
    kConnected = 1,
    kDisconnected,
    kError,
    kLinkDown,
    kLinkUp,
    kLinkChanged,
    kSuspend,
    kResume
  };

  ThirdPartyVpnDriver(Manager* manager, ProcessManager* process_manager);
  ThirdPartyVpnDriver(const ThirdPartyVpnDriver&) = delete;
  ThirdPartyVpnDriver& operator=(const ThirdPartyVpnDriver&) = delete;

  ~ThirdPartyVpnDriver() override;

  // UpdateConnectionState is called by DBus adaptor when
  // "UpdateConnectionState" method is called on the DBus interface.
  void UpdateConnectionState(Service::ConnectState connection_state,
                             std::string* error_message);

  // SendPacket is called by the DBus adaptor when "SendPacket" method is called
  // on the DBus interface.
  void SendPacket(const std::vector<uint8_t>& data, std::string* error_message);

  // SetParameters is called by the DBus adaptor when "SetParameter" method is
  // called on the DBus interface.
  void SetParameters(const std::map<std::string, std::string>& parameters,
                     std::string* error_message,
                     std::string* warning_message);

  void ClearExtensionId(Error* error);
  bool SetExtensionId(const std::string& value, Error* error);

  // Implementation of VPNDriver
  void InitPropertyStore(PropertyStore* store) override;
  base::TimeDelta ConnectAsync(EventHandler* handler) override;
  std::unique_ptr<IPConfig::Properties> GetIPv4Properties() const override;
  std::unique_ptr<IPConfig::Properties> GetIPv6Properties() const override;
  void Disconnect() override;
  void OnConnectTimeout() override;

  void OnDefaultPhysicalServiceEvent(
      DefaultPhysicalServiceEvent event) override;

  bool Load(const StoreInterface* storage,
            const std::string& storage_id) override;
  bool Save(StoreInterface* storage,
            const std::string& storage_id,
            bool save_credentials) override;

  void OnBeforeSuspend(ResultCallback callback) override;
  void OnAfterResume() override;

  const std::string& object_path_suffix() const { return object_path_suffix_; }

 private:
  friend class ThirdPartyVpnDriverTest;
  FRIEND_TEST(ThirdPartyVpnDriverTest, ConnectAndDisconnect);
  FRIEND_TEST(ThirdPartyVpnDriverTest, ReconnectionEvents);
  FRIEND_TEST(ThirdPartyVpnDriverTest, PowerEvents);
  FRIEND_TEST(ThirdPartyVpnDriverTest, OnConnectTimeout);
  FRIEND_TEST(ThirdPartyVpnDriverTest, SetParameters);
  FRIEND_TEST(ThirdPartyVpnDriverTest, UpdateConnectionState);
  FRIEND_TEST(ThirdPartyVpnDriverTest, SendPacket);

  // Resets the internal state and deallocates all resources - closes the
  // handle to tun device, IO handler if open and deactivates itself with the
  // |thirdpartyvpn_adaptor_| if active.
  void Cleanup();

  // First do Cleanup(). Then if there's a service associated through
  // ConnectAsync, notify it to sets its state to Service::kStateFailure, sets
  // the failure reason to |failure|, sets its ErrorDetails property to
  // |error_details|, and disassociates from the service.
  void FailService(Service::ConnectFailure failure,
                   base::StringPiece error_details);

  void OnLinkReady(const std::string& link_name, int interface_index);

  // This function first checks if a value is present for a particular |key| in
  // the dictionary |parameters|.
  // If present it ensures the value is a valid IP address and then sets it to
  // the |target|.
  // The flag |mandatory| when set to true, makes the function treat a missing
  // key as an error. The function adds to |error_messages|, when there is a
  // failure.
  // This function supports only IPV4 addresses now.
  void ProcessIp(const std::map<std::string, std::string>& parameters,
                 const char* key,
                 std::string* target,
                 bool mandatory,
                 std::string* error_message);

  // This function first checks if a value is present for a particular |key| in
  // the dictionary |parameters|.
  // If present it treats the value as a list of string separated by
  // |delimiter|. Each string value is verified to be a valid IP address,
  // deleting ones that are not. The list of string is set to |target|.
  // The flag |mandatory| when set to true, makes the function treat a missing
  // key as an error. The function adds to |error_message|, when there is a
  // failure and |warn_message| when there is a warning.
  void ProcessIPArray(const std::map<std::string, std::string>& parameters,
                      const char* key,
                      char delimiter,
                      std::vector<std::string>* target,
                      bool mandatory,
                      std::string* error_message,
                      std::string* warn_message);

  // This function first checks if a value is present for a particular |key| in
  // the dictionary |parameters|.
  // If present it treats the value as a list of string separated by
  // |delimiter|. Each string value is verified to be a valid IP address in
  // CIDR format, deleting ones that are not. The list of string is set to
  // |target|. The flag |mandatory| when set to true, makes the function treat a
  // missing key as an error. The function adds to |error_message|, when there
  // is a failure and |warn_message| when there is a warning.
  void ProcessIPArrayCIDR(const std::map<std::string, std::string>& parameters,
                          const char* key,
                          char delimiter,
                          std::vector<std::string>* target,
                          bool mandatory,
                          std::string* error_message,
                          std::string* warn_message);

  // This function first checks if a value is present for a particular |key| in
  // the dictionary |parameters|.
  // If present it treats the value as a list of string separated by
  // |delimiter|. The list of string is set to |target|.
  // The flag |mandatory| when set to true, makes the function treat a missing
  // key as an error. The function adds to |error_messages|, when there is a
  // failure.
  void ProcessSearchDomainArray(
      const std::map<std::string, std::string>& parameters,
      const char* key,
      char delimiter,
      std::vector<std::string>* target,
      bool mandatory,
      std::string* error_message);

  // This function first checks if a value is present for a particular |key| in
  // the dictionary |parameters|.
  // If present it treats the value as an integer and verifies if the value lies
  // between |min_value| and |max_value|. It then updates |target| with the
  // integer value if it is in range.
  // The flag |mandatory| when set to true, makes the function treat a missing
  // key as an error. The function adds to |error_messages|, when there is a
  // failure.
  void ProcessInt32(const std::map<std::string, std::string>& parameters,
                    const char* key,
                    int32_t* target,
                    int32_t min_value,
                    int32_t max_value,
                    bool mandatory,
                    std::string* error_message);

  // This function first checks if a value is present for a particular |key| in
  // the dictionary |parameters|.
  // If present it treats the value as a boolean. It then updates |target|
  // with the boolean value if it is valid;
  // The flag |mandatory| when set to true, makes the function treat a missing
  // key as an error. The function adds to |error_messages|, when there is a
  // failure.
  void ProcessBoolean(const std::map<std::string, std::string>& parameters,
                      const char* key,
                      bool* target,
                      bool mandatory,
                      std::string* error_message);

  // These functions are called whe there is input and error in the tun
  // interface.
  void OnInput(InputData* data);
  void OnInputError(const std::string& error);

  static const Property kProperties[];

  // This variable keeps track of the active instance. There can be multiple
  // instance of this class at a time but only one would be active that can
  // communicate with the VPN client over DBUS.
  static ThirdPartyVpnDriver* active_client_;

  // ThirdPartyVpnAdaptorInterface manages the DBus communication and provides
  // an unique identifier for the ThirdPartyVpnDriver.
  std::unique_ptr<ThirdPartyVpnAdaptorInterface> adaptor_interface_;

  // Object path suffix is made of Extension ID and name that collectively
  // identifies the configuration of the third party VPN client.
  std::string object_path_suffix_;

  // File descriptor for the tun device.
  int tun_fd_;

  // Configuration properties of the virtual VPN device set by the VPN client.
  std::unique_ptr<IPConfig::Properties> ipv4_properties_;
  bool ip_properties_set_;

  IOHandlerFactory* io_handler_factory_;

  // IO handler triggered when there is an error or data ready for read in the
  // tun device.
  std::unique_ptr<IOHandler> io_handler_;

  // The object is used to write to tun device.
  FileIO* file_io_;

  // Set used to identify duplicate entries in inclusion and exclusion list.
  std::set<std::string> known_cidrs_;

  // The boolean indicates if parameters are expected from the VPN client.
  bool parameters_expected_;

  // Flag indicating whether the extension supports reconnections - a feature
  // that wasn't in the original API.  If not, we won't send link_* or
  // suspend/resume signals.
  bool reconnect_supported_;

  EventHandler* event_handler_ = nullptr;

  std::string interface_name_;
  int interface_index_ = -1;

  base::WeakPtrFactory<ThirdPartyVpnDriver> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_VPN_THIRD_PARTY_VPN_DRIVER_H_
