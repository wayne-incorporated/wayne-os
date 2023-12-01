// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "modemfwd/modem.h"

#include <map>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/strings/string_util.h>
#include <base/unguessable_token.h>
#include <brillo/dbus/dbus_method_invoker.h>
#include <brillo/strings/string_utils.h>
#include <chromeos/dbus/service_constants.h>
#include <chromeos/switches/modemfwd_switches.h>
#include <dbus/modemfwd/dbus-constants.h>
#include <ModemManager/ModemManager.h>
#include <re2/re2.h>

#include "modemfwd/logging.h"
#include "modemfwd/modem_helper.h"
#include "modemmanager/dbus-proxies.h"

namespace {

class Inhibitor {
 public:
  Inhibitor(std::unique_ptr<org::freedesktop::ModemManager1Proxy> mm_proxy,
            const std::string& physdev_uid)
      : mm_proxy_(std::move(mm_proxy)), physdev_uid_(physdev_uid) {}

  bool SetInhibited(bool inhibited) {
    brillo::ErrorPtr error_unused;
    return mm_proxy_->InhibitDevice(physdev_uid_, inhibited, &error_unused);
  }

 private:
  std::unique_ptr<org::freedesktop::ModemManager1Proxy> mm_proxy_;
  std::string physdev_uid_;
};

std::unique_ptr<Inhibitor> GetInhibitor(
    scoped_refptr<dbus::Bus> bus, const dbus::ObjectPath& mm_object_path) {
  // Get the MM object backing this modem, and retrieve its Device property.
  // This is the mm_physdev_uid we use for inhibition during updates.
  if (!mm_object_path.IsValid()) {
    LOG(WARNING) << __func__ << " " << mm_object_path.value() << " is invalid";
    return nullptr;
  }

  auto mm_device = bus->GetObjectProxy(modemmanager::kModemManager1ServiceName,
                                       mm_object_path);
  if (!mm_device)
    return nullptr;

  brillo::ErrorPtr error;
  auto resp = brillo::dbus_utils::CallMethodAndBlock(
      mm_device, dbus::kDBusPropertiesInterface, dbus::kDBusPropertiesGet,
      &error, std::string(modemmanager::kModemManager1ModemInterface),
      std::string(MM_MODEM_PROPERTY_DEVICE));
  if (!resp)
    return nullptr;

  std::string mm_physdev_uid;
  if (!brillo::dbus_utils::ExtractMethodCallResults(resp.get(), &error,
                                                    &mm_physdev_uid)) {
    return nullptr;
  }

  EVLOG(1) << "Modem " << mm_object_path.value() << " has physdev UID "
           << mm_physdev_uid;
  auto mm_proxy = std::make_unique<org::freedesktop::ModemManager1Proxy>(
      bus, modemmanager::kModemManager1ServiceName);
  return std::make_unique<Inhibitor>(std::move(mm_proxy), mm_physdev_uid);
}

std::string GetModemPrimaryPort(scoped_refptr<dbus::Bus> bus,
                                const dbus::ObjectPath& mm_object_path) {
  const std::vector<char const*> port_re_patterns{
      "wwan\\dmbim\\d",  // Catch wwan0mbim0
      "cdc-wdm\\d"       // Catch cdc-wdm0
  };

  // Get the MM object backing this modem, and retrieve its Device property.
  // This is the mm_physdev_uid we use for inhibition during updates.
  if (!mm_object_path.IsValid()) {
    LOG(WARNING) << __func__ << " " << mm_object_path.value() << " is invalid";
    return "";
  }

  auto mm_device = bus->GetObjectProxy(modemmanager::kModemManager1ServiceName,
                                       mm_object_path);
  if (!mm_device)
    return "";

  brillo::ErrorPtr error;
  auto resp = brillo::dbus_utils::CallMethodAndBlock(
      mm_device, dbus::kDBusPropertiesInterface, dbus::kDBusPropertiesGet,
      &error, std::string(modemmanager::kModemManager1ModemInterface),
      std::string(MM_MODEM_PROPERTY_PRIMARYPORT));
  if (!resp)
    return "";

  std::string primary_port;
  if (!brillo::dbus_utils::ExtractMethodCallResults(resp.get(), &error,
                                                    &primary_port)) {
    return "";
  }

  // Confirm the primary_port takes a format we're expecting
  const std::string combined_port_re_pattern =
      "^(" + brillo::string_utils::Join("|", port_re_patterns) + ")";
  LazyRE2 modem_matcher = {combined_port_re_pattern.c_str()};
  if (!RE2::FullMatch(primary_port, *modem_matcher))
    return "";

  return primary_port;
}

}  // namespace

namespace modemfwd {

class ModemImpl : public Modem {
 public:
  ModemImpl(const std::string& device_id,
            const std::string& equipment_id,
            const std::string& carrier_id,
            const std::string& firmware_revision,
            const std::string& primary_port,
            std::unique_ptr<Inhibitor> inhibitor,
            ModemHelper* helper)
      : device_id_(device_id),
        equipment_id_(equipment_id),
        carrier_id_(carrier_id),
        primary_port_(primary_port),
        inhibitor_(std::move(inhibitor)),
        helper_(helper) {
    if (!helper->GetFirmwareInfo(&installed_firmware_, firmware_revision)) {
      LOG(WARNING) << "Could not fetch installed firmware information";
    }
  }
  ModemImpl(const ModemImpl&) = delete;
  ModemImpl& operator=(const ModemImpl&) = delete;

  ~ModemImpl() override = default;

  // modemfwd::Modem overrides.
  std::string GetDeviceId() const override { return device_id_; }

  std::string GetEquipmentId() const override { return equipment_id_; }

  std::string GetCarrierId() const override { return carrier_id_; }

  std::string GetPrimaryPort() const override { return primary_port_; }

  int GetHeartbeatFailures() const override { return heartbeat_failures_; }

  void ResetHeartbeatFailures() override { heartbeat_failures_ = 0; }

  void IncrementHeartbeatFailures() override { heartbeat_failures_++; }

  std::string GetMainFirmwareVersion() const override {
    return installed_firmware_.main_version;
  }

  std::string GetOemFirmwareVersion() const override {
    return installed_firmware_.oem_version;
  }

  std::string GetCarrierFirmwareId() const override {
    return installed_firmware_.carrier_uuid;
  }

  std::string GetCarrierFirmwareVersion() const override {
    return installed_firmware_.carrier_version;
  }

  std::string GetAssocFirmwareVersion(std::string fw_tag) const override {
    std::map<std::string, std::string>::const_iterator pos =
        installed_firmware_.assoc_versions.find(fw_tag);
    if (pos == installed_firmware_.assoc_versions.end())
      return "";
    else
      return pos->second;
  }

  bool SetInhibited(bool inhibited) override {
    if (!inhibitor_) {
      EVLOG(1) << "Inhibiting unavailable on this modem";
      return false;
    }
    return inhibitor_->SetInhibited(inhibited);
  }

  bool FlashFirmwares(const std::vector<FirmwareConfig>& configs) override {
    return helper_->FlashFirmwares(configs);
  }

  bool ClearAttachAPN(const std::string& carrier_uuid) override {
    return helper_->ClearAttachAPN(carrier_uuid);
  }

 private:
  int heartbeat_failures_;
  std::string heartbeat_port_;
  std::string device_id_;
  std::string equipment_id_;
  std::string carrier_id_;
  std::string primary_port_;
  std::unique_ptr<Inhibitor> inhibitor_;
  FirmwareInfo installed_firmware_;
  ModemHelper* helper_;
};

std::unique_ptr<Modem> CreateModem(
    scoped_refptr<dbus::Bus> bus,
    std::unique_ptr<org::chromium::flimflam::DeviceProxy> device,
    ModemHelperDirectory* helper_directory) {
  std::string object_path = device->GetObjectPath().value();
  DVLOG(1) << "Creating modem proxy for " << object_path;

  brillo::ErrorPtr error;
  brillo::VariantDictionary properties;
  if (!device->GetProperties(&properties, &error)) {
    LOG(WARNING) << "Could not get properties for modem " << object_path;
    return nullptr;
  }

  // If we don't have a device ID, modemfwd can't do anything with this modem,
  // so check it first and just return if we can't find it.
  std::string device_id;
  if (!properties[shill::kDeviceIdProperty].GetValue(&device_id)) {
    LOG(INFO) << "Modem " << object_path << " has no device ID, ignoring";
    return nullptr;
  }

  // Equipment ID is also pretty important since we use it as a stable
  // identifier that can distinguish between modems of the same type.
  std::string equipment_id;
  if (!properties[shill::kEquipmentIdProperty].GetValue(&equipment_id)) {
    LOG(INFO) << "Modem " << object_path << " has no equipment ID, ignoring";
    return nullptr;
  }
  std::string firmware_revision;
  if (!properties[shill::kFirmwareRevisionProperty].GetValue(
          &firmware_revision)) {
    LOG(INFO) << "Modem " << object_path << " has no firmware revision";
  }
  // This property may not exist and it's not a big deal if it doesn't.
  std::map<std::string, std::string> operator_info;
  std::string carrier_id;
  if (properties[shill::kHomeProviderProperty].GetValue(&operator_info))
    carrier_id = operator_info[shill::kOperatorUuidKey];

  // Get a helper object for inhibiting the modem, if possible.
  std::unique_ptr<Inhibitor> inhibitor;
  std::string mm_object_path;
  if (!properties[shill::kDBusObjectProperty].GetValue(&mm_object_path)) {
    LOG(INFO) << "Modem " << object_path << " has no ModemManager object";
  } else {
    inhibitor = GetInhibitor(bus, dbus::ObjectPath(mm_object_path));
  }
  if (!inhibitor)
    LOG(INFO) << "Inhibiting modem " << object_path << " will not be possible";

  // Use the device ID to grab a helper.
  ModemHelper* helper = helper_directory->GetHelperForDeviceId(device_id);
  if (!helper) {
    LOG(INFO) << "No helper found to update modems with ID [" << device_id
              << "]";
    return nullptr;
  }

  std::string primary_port =
      GetModemPrimaryPort(bus, dbus::ObjectPath(mm_object_path));

  return std::make_unique<ModemImpl>(device_id, equipment_id, carrier_id,
                                     firmware_revision, primary_port,
                                     std::move(inhibitor), helper);
}

// StubModem acts like a modem with a particular device ID but does not
// actually talk to a real modem. This allows us to use it for force-
// flashing.
class StubModem : public Modem {
 public:
  StubModem(const std::string& device_id,
            const std::string& carrier_uuid,
            ModemHelper* helper,
            FirmwareInfo installed_firmware)
      : carrier_id_(carrier_uuid),
        device_id_(device_id),
        equipment_id_(base::UnguessableToken().Create().ToString()),
        helper_(helper),
        installed_firmware_(installed_firmware) {}
  StubModem(const StubModem&) = delete;
  StubModem& operator=(const StubModem&) = delete;

  ~StubModem() override = default;

  // modemfwd::Modem overrides.
  std::string GetDeviceId() const override { return device_id_; }

  std::string GetEquipmentId() const override { return equipment_id_; }

  std::string GetCarrierId() const override { return carrier_id_; }

  std::string GetPrimaryPort() const override { return primary_port_; }

  int GetHeartbeatFailures() const override { return heartbeat_failures_; }

  void ResetHeartbeatFailures() override { heartbeat_failures_ = 0; }

  void IncrementHeartbeatFailures() override { heartbeat_failures_++; }

  std::string GetMainFirmwareVersion() const override {
    return installed_firmware_.main_version;
  }

  std::string GetOemFirmwareVersion() const override {
    return installed_firmware_.oem_version;
  }

  std::string GetCarrierFirmwareId() const override {
    return installed_firmware_.carrier_uuid;
  }

  std::string GetCarrierFirmwareVersion() const override {
    return installed_firmware_.carrier_version;
  }

  std::string GetAssocFirmwareVersion(std::string) const override { return ""; }

  bool SetInhibited(bool inhibited) override { return true; }

  bool FlashFirmwares(const std::vector<FirmwareConfig>& configs) override {
    return helper_->FlashFirmwares(configs);
  }

  bool ClearAttachAPN(const std::string& carrier_uuid) override {
    return helper_->ClearAttachAPN(carrier_uuid);
  }

 private:
  int heartbeat_failures_;
  std::string heartbeat_port_;
  std::string carrier_id_;
  std::string primary_port_;
  std::string device_id_;
  std::string equipment_id_;
  ModemHelper* helper_;
  FirmwareInfo installed_firmware_;
};

std::unique_ptr<Modem> CreateStubModem(const std::string& device_id,
                                       const std::string& carrier_uuid,
                                       ModemHelperDirectory* helper_directory,
                                       bool use_real_fw_info) {
  // Use the device ID to grab a helper.
  ModemHelper* helper = helper_directory->GetHelperForDeviceId(device_id);
  if (!helper) {
    LOG(INFO) << "No helper found to update modems with ID [" << device_id
              << "]";
    return nullptr;
  }
  FirmwareInfo installed_firmware;
  if (use_real_fw_info && !helper->GetFirmwareInfo(&installed_firmware, "")) {
    LOG(ERROR) << "Could not fetch installed firmware information";
    return nullptr;
  }
  return std::make_unique<StubModem>(device_id, carrier_uuid, helper,
                                     std::move(installed_firmware));
}

}  // namespace modemfwd
