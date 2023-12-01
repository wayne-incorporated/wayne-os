// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_VPN_VPN_DRIVER_H_
#define SHILL_VPN_VPN_DRIVER_H_

#include <memory>
#include <string>
#include <vector>

#include <base/cancelable_callback.h>
#include <base/memory/weak_ptr.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/callbacks.h"
#include "shill/eap_credentials.h"
#include "shill/mockable.h"
#include "shill/service.h"
#include "shill/store/key_value_store.h"
#include "shill/vpn/vpn_provider.h"

namespace shill {

class ControlInterface;
class Error;
class EventDispatcher;
class Manager;
class Metrics;
class ProcessManager;
class PropertyStore;
class StoreInterface;

class VPNDriver {
 public:
  // Note that the Up and Down events are triggered by whether the default
  // physical service is online. This works in most cases, but in some
  // scenarios, we may want to connect to a VPN service when the service is not
  // online but only connected (e.g., the VPN server is in the same IP prefix on
  // the LAN), events based on the connected state is more meaningful in those
  // cases.
  enum DefaultPhysicalServiceEvent {
    // The default physical service becomes online from any other state.
    kDefaultPhysicalServiceUp,
    // There is no online physical service any more.
    kDefaultPhysicalServiceDown,
    // The default physical service changed from an online service to another
    // online service.
    kDefaultPhysicalServiceChanged,
  };

  // Passed in and registered in ConnectAsync(). Currently implemented by
  // VPNService.
  class EventHandler {
   public:
    // Invoked on connection or reconnection done. The interface name and index
    // of the VPN interface are passed via parameters. GetIPv4Properties() is
    // ready now.
    virtual void OnDriverConnected(const std::string& if_name,
                                   int if_index) = 0;

    // When a failure happens, the driver will clean up its internal state. This
    // event is supposed to be triggered only once before the next call of
    // ConnectAsync().
    virtual void OnDriverFailure(Service::ConnectFailure failure,
                                 base::StringPiece error_details) = 0;

    // Indicates the driver is trying reconnecting now. Note that this event
    // might be triggered multiple times before OnConnected or OnFailure
    // happens. |timeout| suggests the handler how long this connection attempt
    // might take at maximum.
    virtual void OnDriverReconnecting(base::TimeDelta timeout) = 0;

   protected:
    ~EventHandler() = default;
  };

  // Might be returned by ConnectAsync() or OnDriverReconnecting(). Indicates
  // the VPNService should not set a timeout for this connection attempt.
  static constexpr base::TimeDelta kTimeoutNone = base::Seconds(0);

  virtual ~VPNDriver();

  // When this function is called, a VPNDriver is responsible for 1) creating
  // the network interface (either by interacting with DeviceInfo or by letting
  // another program do this), 2) starting and configuring the VPN tunnel, and
  // 3) after VPN is connected and the network interface is known by DeviceInfo,
  // invoking callbacks in |handler| to notify the VPNService of connection
  // success (or other events).
  // Returns a timeout value which suggests the handler how long this connection
  // attempt might take at maximum.
  virtual base::TimeDelta ConnectAsync(EventHandler* handler) = 0;
  virtual void Disconnect() = 0;
  virtual std::unique_ptr<IPConfig::Properties> GetIPv4Properties() const = 0;
  virtual std::unique_ptr<IPConfig::Properties> GetIPv6Properties() const = 0;

  // Makes the VPN driver fail because of the connection timeout. The driver
  // will clean up its internal state, and invokes OnDriverFailure to notify the
  // event handler of the failure reason.
  virtual void OnConnectTimeout() = 0;

  // Registers properties with |store|. These properties are exposed and can be
  // read and/or written via RPC. The list of properties is controlled by: 1)
  // all properties in |properties| are included, 2) GetProvider() provides a
  // read-only "Provider" property, 3) the inherited class can override this
  // function to register more properties.
  virtual void InitPropertyStore(PropertyStore* store);

  // This group of functions control the interaction between persistent
  // |storage| and |args_|. Also see the function with the same names in Service
  // and VPNService.
  virtual bool Load(const StoreInterface* storage,
                    const std::string& storage_id);
  void MigrateDeprecatedStorage(StoreInterface* storage,
                                const std::string& storage_id);
  virtual bool Save(StoreInterface* storage,
                    const std::string& storage_id,
                    bool save_credentials);
  virtual void UnloadCredentials();

  // Power management events.
  virtual void OnBeforeSuspend(ResultCallback callback);
  virtual void OnAfterResume();
  virtual void OnDefaultPhysicalServiceEvent(DefaultPhysicalServiceEvent event);

  mockable std::string GetHost() const;

  VPNType vpn_type() const { return vpn_type_; }
  KeyValueStore* args() { return &args_; }
  const KeyValueStore* const_args() const { return &args_; }
  const EapCredentials* eap_credentials() const {
    return eap_credentials_.get();
  }

 protected:
  // Represents a property in |args_|, which can be read and/or written over
  // RPC, and loaded from and/or saved to storage (the accessibility is
  // controlled by flags). Each inherited class should define the list of
  // properties it has, and pass this list to the constructor of this class.
  struct Property {
    enum Flags {
      kEphemeral = 1 << 0,   // Never load or save.
      kCredential = 1 << 1,  // Save if saving credentials (crypted).
      kWriteOnly = 1 << 2,   // Never read over RPC.
      kReadOnly = 1 << 3,    // Never write over RPC.
      kArray = 1 << 4,       // Property is an array of strings.
    };

    const char* property;
    int flags;
  };

  VPNDriver(Manager* manager,
            ProcessManager* process_manager,
            VPNType vpn_type,
            const Property* properties,
            size_t property_count,
            bool use_eap = false);
  VPNDriver(const VPNDriver&) = delete;
  VPNDriver& operator=(const VPNDriver&) = delete;

  ControlInterface* control_interface() const;
  EventDispatcher* dispatcher() const;
  Metrics* metrics() const;
  Manager* manager() const { return manager_; }
  ProcessManager* process_manager() const { return process_manager_; }

  // Registered for "Provider" property, which can be read over RPC. All
  // accessible properties defined in |properties_| are included.
  virtual KeyValueStore GetProvider(Error* error);

 private:
  friend class VPNDriverTest;

  static const char kCredentialPrefix[];

  void ClearMappedStringProperty(const size_t& index, Error* error);
  void ClearMappedStringsProperty(const size_t& index, Error* error);
  std::string GetMappedStringProperty(const size_t& index, Error* error);
  std::vector<std::string> GetMappedStringsProperty(const size_t& index,
                                                    Error* error);
  bool SetMappedStringProperty(const size_t& index,
                               const std::string& value,
                               Error* error);
  bool SetMappedStringsProperty(const size_t& index,
                                const std::vector<std::string>& value,
                                Error* error);

  Manager* manager_;
  ProcessManager* process_manager_;

  const VPNType vpn_type_;
  const Property* const properties_;
  const size_t property_count_;
  KeyValueStore args_;

  std::unique_ptr<EapCredentials> eap_credentials_;
};

}  // namespace shill

#endif  // SHILL_VPN_VPN_DRIVER_H_
