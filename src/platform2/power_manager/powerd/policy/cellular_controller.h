// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_POLICY_CELLULAR_CONTROLLER_H_
#define POWER_MANAGER_POWERD_POLICY_CELLULAR_CONTROLLER_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#if USE_CELLULAR
#include "modemmanager/dbus-proxies.h"
#endif
#include "power_manager/common/power_constants.h"
#include "power_manager/powerd/policy/user_proximity_handler.h"
#if USE_CELLULAR
#include "power_manager/powerd/system/dbus_objectmanager_wrapper.h"
#endif
#include "power_manager/powerd/system/dbus_wrapper.h"
#if USE_CELLULAR
#include <shill/dbus-proxies.h>
#include "shill/dbus/client/client.h"
#endif
#if USE_QRTR  // TODO(b/188798246): Remove this once qc-netmgr is merged back
              // into modemmanager.
#include "upstart/dbus-proxies.h"
#endif

namespace power_manager {

class PrefsInterface;

namespace policy {

// CellularController initiates power-related changes to the cellular chipset.
class CellularController : public UserProximityHandler::Delegate {
 public:
#if USE_QRTR  // TODO(b/188798246): Remove this once qc-netmgr is merged back
              // into modemmanager.
  enum class Type {
    kQrtr,
    kMbim,
  };
  struct PacketMetadata {
    uint32_t port;
    uint32_t node;
  };
#endif  // USE_QRTR
  // Performs work on behalf of CellularController.
  class Delegate {
   public:
    virtual ~Delegate() = default;

    // Updates the transmit power to |power| via the dynamic power reduction
    // signal controlled by the specified GPIO number.
    virtual void SetCellularTransmitPower(RadioTransmitPower power,
                                          int64_t dpr_gpio_number) = 0;
  };

  CellularController();
  CellularController(const CellularController&) = delete;
  CellularController& operator=(const CellularController&) = delete;

  ~CellularController() override;

  // Ownership of raw pointers remains with the caller.
  void Init(Delegate* delegate,
            PrefsInterface* prefs,
            system::DBusWrapperInterface* dbus_wrapper);

  // Called when the tablet mode changes.
  void HandleTabletModeChange(TabletMode mode);
  // Called when the modem state changes
  void HandleModemStateChange(ModemState state);
  // Called when the regulatory domain changes
  void HandleModemRegulatoryDomainChange(CellularRegulatoryDomain domain);
  // UserProximityHandler::Delegate overrides:
  void ProximitySensorDetected(UserProximity proximity) override;
  void HandleProximityChange(UserProximity proximity) override;

 private:
  // Updates transmit power via |delegate_|.
  void UpdateTransmitPower();

  RadioTransmitPower DetermineTransmitPower() const;
  void InitPowerLevel(const std::string& power_levels);
  void InitRegulatoryDomainMapping(const std::string& domain_offsets);
  RadioTransmitPower GetPowerIndexFromString(const std::string& name);
#if USE_CELLULAR
  void SetCellularTransmitPowerInModemManager(RadioTransmitPower power);
  void OnModemManagerServiceAvailable(bool available);
  void InitModemManagerSarInterface();

  void ModemManagerInterfacesAdded(
      const dbus::ObjectPath& object_path,
      const system::DBusInterfaceToProperties& properties);
  void ModemManagerInterfacesRemoved(
      const dbus::ObjectPath& object_path,
      const std::vector<std::string>& interfaces);

  // DBusObjectManagerProxyDelegate method callbacks
  void OnGetManagedObjectsReplySuccess(
      const system::DBusObjectsWithProperties& dbus_objects_with_properties);

  // Service name owner changed handler.
  void OnServiceOwnerChanged(const std::string& old_owner,
                             const std::string& new_owner);

  // Setup Shill dbus proxies
  void InitShillProxyInterface();
  void OnShillReady(bool success);
  void OnShillReset(bool reset);
  void OnShillDeviceChanged(const shill::Client::Device* const device);

#endif        // USE_CELLULAR
#if USE_QRTR  // TODO(b/188798246): Remove this once qc-netmgr is merged back
              // into modemmanager.
  bool InitQrtrSocket();
  void OnFileCanReadWithoutBlocking();
  void EmitEvent(const char* event);
  void OnDataAvailable(CellularController* cc);
  void ProcessQrtrPacket(uint32_t node, uint32_t port, int size);
  int Recv(void* buf, size_t size, void* metadata);
  int Send(const void* data, size_t size, const void* metadata);
  bool StartServiceLookup(uint32_t service,
                          uint16_t version_major,
                          uint16_t version_minor);
  bool StopServiceLookup(uint32_t service,
                         uint16_t version_major,
                         uint16_t version_minor);
#endif  // USE_QRTR

  Delegate* delegate_ = nullptr;  // Not owned.
  system::DBusWrapperInterface* dbus_wrapper_ = nullptr;

  TabletMode tablet_mode_ = TabletMode::UNSUPPORTED;
  UserProximity proximity_ = UserProximity::UNKNOWN;
  ModemState state_ = ModemState::UNKNOWN;
  CellularRegulatoryDomain regulatory_domain_ =
      CellularRegulatoryDomain::UNKNOWN;

  // True if powerd has been configured to set cellular transmit power in
  // response to tablet mode or proximity changes.
  bool set_transmit_power_for_tablet_mode_ = false;
  bool set_transmit_power_for_proximity_ = false;
  bool set_default_proximity_state_far_ = false;
  bool use_modemmanager_for_dynamic_sar_ = false;
  bool use_multi_power_level_dynamic_sar_ = false;
  bool use_regulatory_domain_for_dynamic_sar_ = false;
  std::map<RadioTransmitPower, uint32_t> level_mappings_;
  // Regulatory domain to offset mapping
  std::map<CellularRegulatoryDomain, uint32_t> regulatory_domain_mappings_;

#if USE_QRTR  // TODO(b/188798246): Remove this once qc-netmgr is merged back
              // into modemmanager.
  base::ScopedFD socket_;
  std::vector<uint8_t> buffer_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> watcher_;
  std::unique_ptr<com::ubuntu::Upstart0_6Proxy> upstart_proxy_;
#endif  // USE_QRTR

  // GPIO number for the dynamic power reduction signal of a built-in cellular
  // modem.
  int64_t dpr_gpio_number_ = -1;
#if USE_CELLULAR
  std::unique_ptr<org::freedesktop::ModemManager1::Modem::SarProxy>
      mm_sar_proxy_;
  std::unique_ptr<system::DBusObjectManagerProxyInterface> mm_obj_proxy_;
  std::unique_ptr<org::chromium::flimflam::ManagerProxy> shill_manager_proxy_;
  std::unique_ptr<org::chromium::flimflam::DeviceProxy> shill_device_proxy_;
  bool shill_ready_{false};
  std::unique_ptr<shill::Client> shill_;
#endif  // USE_CELLULAR
  base::WeakPtrFactory<CellularController> weak_ptr_factory_;
};

}  // namespace policy
}  // namespace power_manager

#endif  // POWER_MANAGER_POWERD_POLICY_CELLULAR_CONTROLLER_H_
