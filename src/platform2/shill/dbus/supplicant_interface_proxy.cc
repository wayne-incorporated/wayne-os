// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/supplicant_interface_proxy.h"

#include <utility>

#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>

#include "shill/logging.h"
#include "shill/supplicant/supplicant_event_delegate_interface.h"
#include "shill/supplicant/wpa_supplicant.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kDBus;
static std::string ObjectID(const dbus::ObjectPath* p) {
  return p->value();
}
}  // namespace Logging

const char SupplicantInterfaceProxy::kInterfaceName[] =
    "fi.w1.wpa_supplicant1.Interface";
const char SupplicantInterfaceProxy::kPropertyFastReauth[] = "FastReauth";
const char SupplicantInterfaceProxy::kPropertyScan[] = "Scan";
const char SupplicantInterfaceProxy::kPropertyScanInterval[] = "ScanInterval";
const char SupplicantInterfaceProxy::kPropertySchedScan[] = "SchedScan";
const char SupplicantInterfaceProxy::kPropertyMacAddressRandomizationMask[] =
    "MACAddressRandomizationMask";
const char SupplicantInterfaceProxy::kPropertyCapabilities[] = "Capabilities";

SupplicantInterfaceProxy::PropertySet::PropertySet(
    dbus::ObjectProxy* object_proxy,
    const std::string& interface_name,
    const PropertyChangedCallback& callback)
    : dbus::PropertySet(object_proxy, interface_name, callback) {
  RegisterProperty(kPropertyFastReauth, &fast_reauth);
  RegisterProperty(kPropertyScan, &scan);
  RegisterProperty(kPropertyScanInterval, &scan_interval);
  RegisterProperty(kPropertySchedScan, &sched_scan);
  RegisterProperty(kPropertyMacAddressRandomizationMask,
                   &mac_address_randomization_mask);
  RegisterProperty(kPropertyCapabilities, &capabilities);
}

SupplicantInterfaceProxy::SupplicantInterfaceProxy(
    const scoped_refptr<dbus::Bus>& bus,
    const RpcIdentifier& object_path,
    SupplicantEventDelegateInterface* delegate)
    : interface_proxy_(new fi::w1::wpa_supplicant1::InterfaceProxy(
          bus, WPASupplicant::kDBusAddr, object_path)),
      delegate_(delegate) {
  // Register properties.
  properties_.reset(new PropertySet(
      interface_proxy_->GetObjectProxy(), kInterfaceName,
      base::BindRepeating(&SupplicantInterfaceProxy::OnPropertyChanged,
                          weak_factory_.GetWeakPtr())));

  // Register signal handlers.
  auto on_connected_callback = base::BindRepeating(
      &SupplicantInterfaceProxy::OnSignalConnected, weak_factory_.GetWeakPtr());
  interface_proxy_->RegisterScanDoneSignalHandler(
      base::BindRepeating(&SupplicantInterfaceProxy::ScanDone,
                          weak_factory_.GetWeakPtr()),
      on_connected_callback);
  interface_proxy_->RegisterBSSAddedSignalHandler(
      base::BindRepeating(&SupplicantInterfaceProxy::BSSAdded,
                          weak_factory_.GetWeakPtr()),
      on_connected_callback);
  interface_proxy_->RegisterBSSRemovedSignalHandler(
      base::BindRepeating(&SupplicantInterfaceProxy::BSSRemoved,
                          weak_factory_.GetWeakPtr()),
      on_connected_callback);
  interface_proxy_->RegisterBlobAddedSignalHandler(
      base::BindRepeating(&SupplicantInterfaceProxy::BlobAdded,
                          weak_factory_.GetWeakPtr()),
      on_connected_callback);
  interface_proxy_->RegisterBlobRemovedSignalHandler(
      base::BindRepeating(&SupplicantInterfaceProxy::BlobRemoved,
                          weak_factory_.GetWeakPtr()),
      on_connected_callback);
  interface_proxy_->RegisterCertificationSignalHandler(
      base::BindRepeating(&SupplicantInterfaceProxy::Certification,
                          weak_factory_.GetWeakPtr()),
      on_connected_callback);
  interface_proxy_->RegisterEAPSignalHandler(
      base::BindRepeating(&SupplicantInterfaceProxy::EAP,
                          weak_factory_.GetWeakPtr()),
      on_connected_callback);
  interface_proxy_->RegisterNetworkAddedSignalHandler(
      base::BindRepeating(&SupplicantInterfaceProxy::NetworkAdded,
                          weak_factory_.GetWeakPtr()),
      on_connected_callback);
  interface_proxy_->RegisterNetworkRemovedSignalHandler(
      base::BindRepeating(&SupplicantInterfaceProxy::NetworkRemoved,
                          weak_factory_.GetWeakPtr()),
      on_connected_callback);
  interface_proxy_->RegisterNetworkSelectedSignalHandler(
      base::BindRepeating(&SupplicantInterfaceProxy::NetworkSelected,
                          weak_factory_.GetWeakPtr()),
      on_connected_callback);
  interface_proxy_->RegisterPropertiesChangedSignalHandler(
      base::BindRepeating(&SupplicantInterfaceProxy::PropertiesChanged,
                          weak_factory_.GetWeakPtr()),
      on_connected_callback);
  interface_proxy_->RegisterInterworkingAPAddedSignalHandler(
      base::BindRepeating(&SupplicantInterfaceProxy::InterworkingAPAdded,
                          weak_factory_.GetWeakPtr()),
      on_connected_callback);
  interface_proxy_->RegisterInterworkingSelectDoneSignalHandler(
      base::BindRepeating(&SupplicantInterfaceProxy::InterworkingSelectDone,
                          weak_factory_.GetWeakPtr()),
      on_connected_callback);
  interface_proxy_->RegisterStationAddedSignalHandler(
      base::BindRepeating(&SupplicantInterfaceProxy::StationAdded,
                          weak_factory_.GetWeakPtr()),
      on_connected_callback);
  interface_proxy_->RegisterStationRemovedSignalHandler(
      base::BindRepeating(&SupplicantInterfaceProxy::StationRemoved,
                          weak_factory_.GetWeakPtr()),
      on_connected_callback);
  interface_proxy_->RegisterPskMismatchSignalHandler(
      base::BindRepeating(&SupplicantInterfaceProxy::PskMismatch,
                          weak_factory_.GetWeakPtr()),
      on_connected_callback);

  // Connect property signals and initialize cached values. Based on
  // recommendations from src/dbus/property.h.
  properties_->ConnectSignals();
  properties_->GetAll();
}

SupplicantInterfaceProxy::~SupplicantInterfaceProxy() {
  interface_proxy_->ReleaseObjectProxy(base::DoNothing());
}

bool SupplicantInterfaceProxy::AddNetwork(const KeyValueStore& args,
                                          RpcIdentifier* network) {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  brillo::VariantDictionary dict =
      KeyValueStore::ConvertToVariantDictionary(args);
  dbus::ObjectPath path;
  brillo::ErrorPtr error;
  if (!interface_proxy_->AddNetwork(dict, &path, &error)) {
    LOG(ERROR) << "Failed to add network: " << error->GetCode() << " "
               << error->GetMessage();
    return false;
  }
  *network = path;
  return true;
}

bool SupplicantInterfaceProxy::EAPLogoff() {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  brillo::ErrorPtr error;
  if (!interface_proxy_->EAPLogoff(&error)) {
    LOG(ERROR) << "Failed to EPA logoff " << error->GetCode() << " "
               << error->GetMessage();
    return false;
  }
  return true;
}

bool SupplicantInterfaceProxy::EAPLogon() {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  brillo::ErrorPtr error;
  if (!interface_proxy_->EAPLogon(&error)) {
    LOG(ERROR) << "Failed to EAP logon: " << error->GetCode() << " "
               << error->GetMessage();
    return false;
  }
  return true;
}

bool SupplicantInterfaceProxy::Disconnect() {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  brillo::ErrorPtr error;
  if (!interface_proxy_->Disconnect(&error)) {
    // Don't log as an error because this happens when lower layers disconnect
    // before shill does.
    LOG(INFO) << "Failed to disconnect: " << error->GetCode() << " "
              << error->GetMessage();
    return false;
  }
  return true;
}

bool SupplicantInterfaceProxy::FlushBSS(const uint32_t& age) {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  brillo::ErrorPtr error;
  if (!interface_proxy_->FlushBSS(age, &error)) {
    LOG(ERROR) << "Failed to flush BSS: " << error->GetCode() << " "
               << error->GetMessage();
    return false;
  }
  return true;
}

bool SupplicantInterfaceProxy::NetworkReply(const RpcIdentifier& network,
                                            const std::string& field,
                                            const std::string& value) {
  SLOG(&interface_proxy_->GetObjectPath(), 2)
      << __func__ << " network: " << network.value() << " field: " << field
      << " value: " << value;
  brillo::ErrorPtr error;
  if (!interface_proxy_->NetworkReply(network, field, value, &error)) {
    LOG(ERROR) << "Failed to network reply: " << error->GetCode() << " "
               << error->GetMessage();
    return false;
  }
  return true;
}

bool SupplicantInterfaceProxy::Roam(const std::string& addr) {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  brillo::ErrorPtr error;
  if (!interface_proxy_->Roam(addr, &error)) {
    LOG(ERROR) << "Failed to Roam: " << error->GetCode() << " "
               << error->GetMessage();
    return false;
  }
  return true;
}

bool SupplicantInterfaceProxy::Reassociate() {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  brillo::ErrorPtr error;
  if (!interface_proxy_->Reassociate(&error)) {
    LOG(ERROR) << "Failed to reassociate: " << error->GetCode() << " "
               << error->GetMessage();
    return false;
  }
  return true;
}

bool SupplicantInterfaceProxy::Reattach() {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  brillo::ErrorPtr error;
  if (!interface_proxy_->Reattach(&error)) {
    LOG(ERROR) << "Failed to reattach: " << error->GetCode() << " "
               << error->GetMessage();
    return false;
  }
  return true;
}

bool SupplicantInterfaceProxy::RemoveAllNetworks() {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  brillo::ErrorPtr error;
  if (!interface_proxy_->RemoveAllNetworks(&error)) {
    LOG(ERROR) << "Failed to remove all networks: " << error->GetCode() << " "
               << error->GetMessage();
    return false;
  }
  return true;
}

bool SupplicantInterfaceProxy::InterworkingSelect() {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  brillo::ErrorPtr error;
  if (!interface_proxy_->InterworkingSelect(&error)) {
    LOG(ERROR) << "Failed to start passpoint interworking selection: "
               << error->GetCode() << " " << error->GetMessage();
    return false;
  }
  return true;
}

bool SupplicantInterfaceProxy::RemoveNetwork(const RpcIdentifier& network) {
  SLOG(&interface_proxy_->GetObjectPath(), 2)
      << __func__ << ": " << network.value();
  brillo::ErrorPtr error;
  if (!interface_proxy_->RemoveNetwork(network, &error)) {
    LOG(ERROR) << "Failed to remove network: " << error->GetCode() << " "
               << error->GetMessage();
    // RemoveNetwork can fail with three different errors.
    //
    // If RemoveNetwork fails with a NetworkUnknown error, supplicant has
    // already removed the network object, so return true as if
    // RemoveNetwork removes the network object successfully.
    //
    // As shill always passes a valid network object path, RemoveNetwork
    // should not fail with an InvalidArgs error. Return false in such case
    // as something weird may have happened. Similarly, return false in case
    // of an UnknownError.
    if (error->GetCode() != WPASupplicant::kErrorNetworkUnknown) {
      return false;
    }
  }
  return true;
}

bool SupplicantInterfaceProxy::Scan(const KeyValueStore& args) {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  brillo::VariantDictionary dict =
      KeyValueStore::ConvertToVariantDictionary(args);
  brillo::ErrorPtr error;
  if (!interface_proxy_->Scan(dict, &error)) {
    // Don't log as an error because this is expected to happen if the radio is
    // busy.
    LOG(INFO) << "Failed to scan: " << error->GetCode() << " "
              << error->GetMessage();
    return false;
  }
  return true;
}

bool SupplicantInterfaceProxy::SelectNetwork(const RpcIdentifier& network) {
  SLOG(&interface_proxy_->GetObjectPath(), 2)
      << __func__ << ": " << network.value();
  brillo::ErrorPtr error;
  if (!interface_proxy_->SelectNetwork(network, &error)) {
    LOG(ERROR) << "Failed to select network: " << error->GetCode() << " "
               << error->GetMessage();
    return false;
  }
  return true;
}

bool SupplicantInterfaceProxy::SignalPoll(KeyValueStore* signalInfo) {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  brillo::ErrorPtr error;
  brillo::VariantDictionary properties;
  if (!interface_proxy_->SignalPoll(&properties, &error)) {
    LOG(ERROR) << "Failed to poll signal: " << error->GetCode() << " "
               << error->GetMessage();
    return false;
  }
  *signalInfo = KeyValueStore::ConvertFromVariantDictionary(properties);
  return true;
}

bool SupplicantInterfaceProxy::EnableMacAddressRandomization(
    const std::vector<unsigned char>& mask, bool sched_scan) {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  // The MACRandomizationMask property is a map(type_string, ipmask_array)
  // where type_string is scan type ("scan" || "sched_scan" || "pno") and
  // ipmask specifies the corresponding mask as an array of bytes.
  std::map<std::string, std::vector<uint8_t>> mac_randomization_args;
  mac_randomization_args.insert(
      std::pair<std::string, std::vector<uint8_t>>("scan", mask));
  if (sched_scan)
    mac_randomization_args.insert(
        std::pair<std::string, std::vector<uint8_t>>("sched_scan", mask));

  if (!(properties_->mac_address_randomization_mask.SetAndBlock(
          mac_randomization_args))) {
    LOG(ERROR) << "Failed to enable MAC address randomization";
    return false;
  }
  return true;
}

bool SupplicantInterfaceProxy::DisableMacAddressRandomization() {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  // Send an empty map to disable Randomization for all scan types.
  std::map<std::string, std::vector<uint8_t>> mac_randomization_empty;
  if (!(properties_->mac_address_randomization_mask.SetAndBlock(
          mac_randomization_empty))) {
    LOG(ERROR) << "Failed to disable MAC address randomization";
    return false;
  }
  return true;
}

bool SupplicantInterfaceProxy::SetFastReauth(bool enabled) {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__ << ": " << enabled;
  if (!properties_->fast_reauth.SetAndBlock(enabled)) {
    LOG(ERROR) << __func__ << " failed: " << enabled;
    return false;
  }
  return true;
}

bool SupplicantInterfaceProxy::SetScanInterval(int32_t scan_interval) {
  SLOG(&interface_proxy_->GetObjectPath(), 2)
      << __func__ << ": " << scan_interval;
  if (!properties_->scan_interval.SetAndBlock(scan_interval)) {
    LOG(ERROR) << __func__ << " failed: " << scan_interval;
    return false;
  }
  return true;
}

bool SupplicantInterfaceProxy::SetScan(bool enable) {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__ << ": " << enable;
  if (!properties_->scan.SetAndBlock(enable)) {
    LOG(ERROR) << __func__ << " failed: " << enable;
    return false;
  }
  return true;
}

bool SupplicantInterfaceProxy::GetCapabilities(KeyValueStore* capabilities) {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  CHECK(capabilities);

  if (!properties_->capabilities.GetAndBlock() ||
      !properties_->capabilities.is_valid()) {
    LOG(ERROR) << "Failed to obtain interface capabilities";
    return false;
  }

  *capabilities = KeyValueStore::ConvertFromVariantDictionary(
      properties_->capabilities.value());

  return true;
}

bool SupplicantInterfaceProxy::AddCred(const KeyValueStore& args,
                                       RpcIdentifier* cred) {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  brillo::VariantDictionary dict =
      KeyValueStore::ConvertToVariantDictionary(args);
  dbus::ObjectPath path;
  brillo::ErrorPtr error;
  if (!interface_proxy_->AddCred(dict, &path, &error)) {
    LOG(ERROR) << "Failed to add credential: " << error->GetCode() << " "
               << error->GetMessage();
    return false;
  }
  *cred = path;
  return true;
}

bool SupplicantInterfaceProxy::RemoveCred(const RpcIdentifier& cred) {
  SLOG(&interface_proxy_->GetObjectPath(), 2)
      << __func__ << ": " << cred.value();
  brillo::ErrorPtr error;
  if (!interface_proxy_->RemoveCred(cred, &error)) {
    LOG(ERROR) << "Failed to remove credential: " << error->GetCode() << " "
               << error->GetMessage();
    return false;
  }
  return true;
}

bool SupplicantInterfaceProxy::RemoveAllCreds() {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  brillo::ErrorPtr error;
  if (!interface_proxy_->RemoveAllCreds(&error)) {
    LOG(ERROR) << "Failed to remove all credentials: " << error->GetCode()
               << " " << error->GetMessage();
    return false;
  }
  return true;
}

void SupplicantInterfaceProxy::BlobAdded(const std::string& /*blobname*/) {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  // XXX
}

void SupplicantInterfaceProxy::BlobRemoved(const std::string& /*blobname*/) {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  // XXX
}

void SupplicantInterfaceProxy::BSSAdded(
    const dbus::ObjectPath& BSS, const brillo::VariantDictionary& properties) {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  KeyValueStore store = KeyValueStore::ConvertFromVariantDictionary(properties);
  delegate_->BSSAdded(BSS, store);
}

void SupplicantInterfaceProxy::Certification(
    const brillo::VariantDictionary& properties) {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  KeyValueStore store = KeyValueStore::ConvertFromVariantDictionary(properties);
  delegate_->Certification(store);
}

void SupplicantInterfaceProxy::EAP(const std::string& status,
                                   const std::string& parameter) {
  SLOG(&interface_proxy_->GetObjectPath(), 2)
      << __func__ << ": status " << status << ", parameter " << parameter;
  delegate_->EAPEvent(status, parameter);
}

void SupplicantInterfaceProxy::BSSRemoved(const dbus::ObjectPath& BSS) {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  delegate_->BSSRemoved(BSS);
}

void SupplicantInterfaceProxy::NetworkAdded(
    const dbus::ObjectPath& /*network*/,
    const brillo::VariantDictionary& /*properties*/) {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  // XXX
}

void SupplicantInterfaceProxy::NetworkRemoved(
    const dbus::ObjectPath& /*network*/) {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  // TODO(quiche): Pass this up to the delegate, so that it can clean its
  // rpcid_by_service_ map. crbug.com/207648
}

void SupplicantInterfaceProxy::NetworkSelected(
    const dbus::ObjectPath& /*network*/) {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  // XXX
}

void SupplicantInterfaceProxy::PropertiesChanged(
    const brillo::VariantDictionary& properties) {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  KeyValueStore store = KeyValueStore::ConvertFromVariantDictionary(properties);
  delegate_->PropertiesChanged(store);
}

void SupplicantInterfaceProxy::InterworkingAPAdded(
    const dbus::ObjectPath& BSS,
    const dbus::ObjectPath& cred,
    const brillo::VariantDictionary& properties) {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  KeyValueStore store = KeyValueStore::ConvertFromVariantDictionary(properties);
  delegate_->InterworkingAPAdded(BSS, cred, std::move(store));
}

void SupplicantInterfaceProxy::InterworkingSelectDone() {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  delegate_->InterworkingSelectDone();
}

void SupplicantInterfaceProxy::ScanDone(bool success) {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__ << ": " << success;
  delegate_->ScanDone(success);
}

void SupplicantInterfaceProxy::StationAdded(
    const dbus::ObjectPath& station,
    const brillo::VariantDictionary& properties) {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  KeyValueStore store = KeyValueStore::ConvertFromVariantDictionary(properties);
  delegate_->StationAdded(station, store);
}

void SupplicantInterfaceProxy::StationRemoved(const dbus::ObjectPath& station) {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  delegate_->StationRemoved(station);
}

void SupplicantInterfaceProxy::PskMismatch() {
  SLOG(&interface_proxy_->GetObjectPath(), 2) << __func__;
  delegate_->PskMismatch();
}

void SupplicantInterfaceProxy::OnPropertyChanged(
    const std::string& property_name) {
  SLOG(&interface_proxy_->GetObjectPath(), 2)
      << __func__ << ": " << property_name;
}

void SupplicantInterfaceProxy::OnSignalConnected(
    const std::string& interface_name,
    const std::string& signal_name,
    bool success) {
  SLOG(&interface_proxy_->GetObjectPath(), 2)
      << __func__ << ": interface: " << interface_name
      << " signal: " << signal_name << " success: " << success;
  if (!success) {
    LOG(ERROR) << "Failed to connect signal " << signal_name << " to interface "
               << interface_name;
  }
}

}  // namespace shill
