// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/ethernet/ethernet.h"

#include <linux/ethtool.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <linux/if.h>  // NOLINT - Needs definitions from netinet/ether.h
#include <linux/netdevice.h>
#include <linux/sockios.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <utility>

#include <memory>
#include <set>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/shill/dbus-constants.h>

#include "shill/adaptor_interfaces.h"
#include "shill/control_interface.h"
#include "shill/device.h"
#include "shill/device_id.h"
#include "shill/device_info.h"
#include "shill/eap_credentials.h"
#include "shill/ethernet/eap_listener.h"
#include "shill/ethernet/ethernet_eap_provider.h"
#include "shill/ethernet/ethernet_provider.h"
#include "shill/ethernet/ethernet_service.h"
#include "shill/event_dispatcher.h"
#include "shill/logging.h"
#include "shill/manager.h"
#include "shill/net/rtnl_handler.h"
#include "shill/profile.h"
#include "shill/refptr_types.h"
#include "shill/store/property_accessor.h"
#include "shill/store/store_interface.h"
#include "shill/supplicant/supplicant_interface_proxy_interface.h"
#include "shill/supplicant/supplicant_manager.h"
#include "shill/supplicant/supplicant_process_proxy_interface.h"
#include "shill/supplicant/wpa_supplicant.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kEthernet;
static std::string ObjectID(const Ethernet* e) {
  return e->GetRpcIdentifier().value();
}
}  // namespace Logging

namespace {

// Path to file with |ethernet_mac0| VPD field value.
constexpr char kVpdEthernetMacFilePath[] = "/sys/firmware/vpd/ro/ethernet_mac0";
// Path to file with |dock_mac| VPD field value.
constexpr char kVpdDockMacFilePath[] = "/sys/firmware/vpd/ro/dock_mac";

// Name of the /drivers/net/veth.c driver. This driver is only used in tast and
// should be ignored when reporting driver names in NotifyEthernetDriverName().
constexpr char kVethDriverName[] = "veth";
// Constant used to notify metrics of failed attempt to get ethernet driver name
// from ETHTOOL.
constexpr char kEthernetDriverNameError[] = "error";

// kDriverNameSize represents maximal length of driver name, this number is
// taken from definition of driver field of ethtool_dvrinfo struct.
constexpr int kDriverNameSize = 32;

// Factor used to convert mbps to kbps.
constexpr uint32_t kMbpsToKbpsFactor = 1e3;

bool IsValidMac(const std::string& mac_address) {
  if (mac_address.length() != 12) {
    return false;
  }
  return base::ContainsOnlyChars(mac_address, "0123456789abcdef");
}

// NETDEV_FEATURE_COUNT in kernel is < 60 in 5.10 kernel, and has 64 as upper
// bound (since netdev_features_t is typedef'ed to u64 in kernel).
#define MAX_FEATURE_COUNT 64

// This represents the maximum number of u32 blocks needed to store a bit mask
// for all available features (This is similar to ETHTOOL_DEV_FEATURE_WORDS in
// kernel).
#define MAX_FEATURE_BLOCKS ((MAX_FEATURE_COUNT + 31) / 32)
// Features that need to be disabled on potentially untrusted devices. Please
// see go/disable-offloading-features for more context. Feature Strings are
// taken from netdev_features_strings[] in kernel.
constexpr std::array<const char*, 6> kFeaturesToDisable = {
    "tx-generic-segmentation",       // NETIF_F_GSO (aka ethtool's gso feature)
    "rx-gro",                        // NETIF_F_GRO (aka ethtool's gro feature)
    "tx-tcp-segmentation",           // NETIF_F_TSO_ECN (part of ethtool's tso)
    "tx-tcp-ecn-segmentation",       // NETIF_F_TSO (part of ethtool's tso)
    "tx-tcp-mangleid-segmentation",  // NETIF_F_TSO_MANGLEID (ethtools's tso)
    "tx-tcp6-segmentation",          // NETIF_F_TSO6 (part of ethtool's tso)
};

// The BIOS / firmware marks the external facing PCI ports with a special
// "external-facing" tag. That is used by the kernel to determine whether
// a PCI device is attached to an internal port or external port. Please
// note that not all platforms shall be able to distinguish between internal /
// external PCI devices (because this needs BIOS/firmware changes). However
// any platforms that support external PCI devices (i.e. thunderbolt / USB4)
// shall be able to (since those shall be new platforms hence forward).
static bool IsExternalPciDev(const std::string& ifname) {
  auto device_id = DeviceId::CreateFromSysfs(base::FilePath(
      base::StringPrintf("/sys/class/net/%s/device", ifname.c_str())));

  constexpr DeviceId kPciDevicePattern{DeviceId::BusType::kPci,
                                       DeviceId::LocationType::kExternal};
  return (device_id && device_id->Match(kPciDevicePattern));
}

}  // namespace

Ethernet::Ethernet(Manager* manager,
                   const std::string& link_name,
                   const std::string& mac_address,
                   int interface_index)
    : Device(manager,
             link_name,
             mac_address,
             interface_index,
             Technology::kEthernet),
      link_up_(false),
      bus_type_(GetDeviceBusType()),
      is_eap_authenticated_(false),
      is_eap_detected_(false),
      eap_listener_(std::make_unique<EapListener>(interface_index, link_name)),
      sockets_(std::make_unique<Sockets>()),
      permanent_mac_address_(GetPermanentMacAddressFromKernel()),
      weak_ptr_factory_(this) {
  PropertyStore* store = this->mutable_store();
  store->RegisterConstBool(kEapAuthenticationCompletedProperty,
                           &is_eap_authenticated_);
  store->RegisterConstBool(kEapAuthenticatorDetectedProperty,
                           &is_eap_detected_);
  store->RegisterConstBool(kLinkUpProperty, &link_up_);
  store->RegisterConstString(kDeviceBusTypeProperty, &bus_type_);
  store->RegisterDerivedString(
      kUsbEthernetMacAddressSourceProperty,
      StringAccessor(std::make_unique<CustomAccessor<Ethernet, std::string>>(
          this, &Ethernet::GetUsbEthernetMacAddressSource, nullptr)));

  eap_listener_->set_request_received_callback(base::BindRepeating(
      &Ethernet::OnEapDetected, weak_ptr_factory_.GetWeakPtr()));
  SLOG(this, 2) << "Ethernet device " << link_name << " initialized.";

  if (bus_type_ == kDeviceBusTypeUsb) {
    // Force change MAC address to |permanent_mac_address_| if
    // |mac_address_| != |permanent_mac_address_|.
    SetUsbEthernetMacAddressSource(kUsbEthernetMacAddressSourceUsbAdapterMac,
                                   base::DoNothing());
  }
}

Ethernet::~Ethernet() {}

void Ethernet::Start(EnabledStateChangedCallback callback) {
  if (IsExternalPciDev(link_name())) {
    if (!DisableOffloadFeatures()) {
      LOG(ERROR) << link_name()
                 << " Interface disabled due to security reasons "
                 << "(failed to disable Offload features)";
      std::move(callback).Run(Error(Error::kPermissionDenied));
      return;
    }
  }

  rtnl_handler()->SetInterfaceFlags(interface_index(), IFF_UP, IFF_UP);
  LOG(INFO) << "Registering " << link_name() << " with manager.";
  if (!service_) {
    service_ = GetProvider()->CreateService(weak_ptr_factory_.GetWeakPtr());
  }
  RegisterService(service_);

  NotifyEthernetDriverName();

  std::move(callback).Run(Error(Error::kSuccess));
}

void Ethernet::Stop(EnabledStateChangedCallback callback) {
  DeregisterService(service_);
  // EthernetProvider::DeregisterService will ResetEthernet() when the Service
  // being deregistered is the only Service remaining (instead of releasing the
  // Service entirely) so that the ethernet_any service continues to live. When
  // this happens, disassociate the EthernetService here as well.
  if (!service_->HasEthernet()) {
    service_ = nullptr;
  }
  StopSupplicant();

  std::move(callback).Run(Error(Error::kSuccess));
}

void Ethernet::LinkEvent(unsigned int flags, unsigned int change) {
  Device::LinkEvent(flags, change);
  if ((flags & IFF_LOWER_UP) != 0 && !link_up_) {
    link_up_ = true;
    adaptor()->EmitBoolChanged(kLinkUpProperty, link_up_);
    // We SetupWakeOnLan() here, instead of in Start(), because with
    // r8139, "ethtool -s eth0 wol g" fails when no cable is plugged
    // in.
    if (service_) {
      manager()->UpdateService(service_);
      service_->OnVisibilityChanged();
    }
    SetupWakeOnLan();
    eap_listener_->Start();
  } else if ((flags & IFF_LOWER_UP) == 0 && link_up_) {
    link_up_ = false;
    adaptor()->EmitBoolChanged(kLinkUpProperty, link_up_);
    DropConnection();
    if (service_) {
      manager()->UpdateService(service_);
      service_->OnVisibilityChanged();
    }
    is_eap_detected_ = false;
    adaptor()->EmitBoolChanged(kEapAuthenticatorDetectedProperty,
                               is_eap_detected_);
    GetEapProvider()->ClearCredentialChangeCallback(this);
    SetIsEapAuthenticated(false);
    StopSupplicant();
    eap_listener_->Stop();
  }
}

bool Ethernet::Load(const StoreInterface* storage) {
  const std::string id = GetStorageIdentifier();
  if (!storage->ContainsGroup(id)) {
    SLOG(this, 2) << "Device is not available in the persistent store: " << id;
    return false;
  }
  return Device::Load(storage);
}

bool Ethernet::Save(StoreInterface* storage) {
  return Device::Save(storage);
}

void Ethernet::ConnectTo(EthernetService* service) {
  CHECK(service_) << "Service should not be null";
  CHECK(service == service_.get()) << "Ethernet was asked to connect the "
                                   << "wrong service?";
  if (!link_up_) {
    return;
  }
  SelectService(service);
  auto dhcp_opts = manager()->CreateDefaultDHCPOption();
  dhcp_opts.use_arp_gateway = false;
  Network::StartOptions opts = {
      .dhcp = dhcp_opts,
      .accept_ra = true,
      .ignore_link_monitoring = service->link_monitor_disabled(),
      .probing_configuration =
          manager()->GetPortalDetectorProbingConfiguration(),
  };
  GetPrimaryNetwork()->Start(opts);
  SetServiceState(Service::kStateConfiguring);

  // Update link speeds. link speeds are expected to be constant during the L2
  // connection for ethernet.
  UpdateLinkSpeed();
}

std::string Ethernet::GetStorageIdentifier() const {
  if (!permanent_mac_address_.empty()) {
    return "device_" + permanent_mac_address_;
  }
  return Device::GetStorageIdentifier();
}

void Ethernet::DisconnectFrom(EthernetService* service) {
  CHECK(service_) << "Service should not be null";
  CHECK(service == service_.get()) << "Ethernet was asked to disconnect the "
                                   << "wrong service?";
  DropConnection();
}

EthernetProvider* Ethernet::GetProvider() {
  EthernetProvider* provider = manager()->ethernet_provider();
  CHECK(provider);
  return provider;
}

void Ethernet::TryEapAuthentication() {
  try_eap_authentication_callback_.Reset(base::BindOnce(
      &Ethernet::TryEapAuthenticationTask, weak_ptr_factory_.GetWeakPtr()));
  dispatcher()->PostTask(FROM_HERE,
                         try_eap_authentication_callback_.callback());
}

void Ethernet::BSSAdded(const RpcIdentifier& path,
                        const KeyValueStore& properties) {
  NOTREACHED() << __func__ << " is not implemented for Ethernet";
}

void Ethernet::BSSRemoved(const RpcIdentifier& path) {
  NOTREACHED() << __func__ << " is not implemented for Ethernet";
}

void Ethernet::Certification(const KeyValueStore& properties) {
  std::string subject;
  uint32_t depth;
  if (WPASupplicant::ExtractRemoteCertification(properties, &subject, &depth)) {
    dispatcher()->PostTask(
        FROM_HERE,
        base::BindOnce(&Ethernet::CertificationTask,
                       weak_ptr_factory_.GetWeakPtr(), subject, depth));
  }
}

void Ethernet::EAPEvent(const std::string& status,
                        const std::string& parameter) {
  dispatcher()->PostTask(
      FROM_HERE,
      base::BindOnce(&Ethernet::EAPEventTask, weak_ptr_factory_.GetWeakPtr(),
                     status, parameter));
}

void Ethernet::PropertiesChanged(const KeyValueStore& properties) {
  if (!properties.Contains<std::string>(
          WPASupplicant::kInterfacePropertyState)) {
    return;
  }
  dispatcher()->PostTask(
      FROM_HERE,
      base::BindOnce(
          &Ethernet::SupplicantStateChangedTask, weak_ptr_factory_.GetWeakPtr(),
          properties.Get<std::string>(WPASupplicant::kInterfacePropertyState)));
}

void Ethernet::ScanDone(const bool& /*success*/) {
  NOTREACHED() << __func__ << " is not implemented for Ethernet";
}

void Ethernet::InterworkingAPAdded(const RpcIdentifier& /*BSS*/,
                                   const RpcIdentifier& /*cred*/,
                                   const KeyValueStore& /*properties*/) {
  NOTREACHED() << __func__ << " is not implemented for Ethernet";
}

void Ethernet::InterworkingSelectDone() {
  NOTREACHED() << __func__ << " is not implemented for Ethernet";
}

EthernetEapProvider* Ethernet::GetEapProvider() {
  EthernetEapProvider* eap_provider = manager()->ethernet_eap_provider();
  CHECK(eap_provider);
  return eap_provider;
}

ServiceConstRefPtr Ethernet::GetEapService() {
  ServiceConstRefPtr eap_service = GetEapProvider()->service();
  CHECK(eap_service);
  return eap_service;
}

void Ethernet::OnEapDetected() {
  is_eap_detected_ = true;
  adaptor()->EmitBoolChanged(kEapAuthenticatorDetectedProperty,
                             is_eap_detected_);
  eap_listener_->Stop();
  GetEapProvider()->SetCredentialChangeCallback(
      this, base::BindRepeating(&Ethernet::TryEapAuthentication,
                                weak_ptr_factory_.GetWeakPtr()));
  TryEapAuthentication();
}

bool Ethernet::StartSupplicant() {
  if (supplicant_interface_proxy_) {
    return true;
  }

  RpcIdentifier interface_path;
  KeyValueStore create_interface_args;
  create_interface_args.Set<std::string>(WPASupplicant::kInterfacePropertyName,
                                         link_name());
  create_interface_args.Set<std::string>(
      WPASupplicant::kInterfacePropertyDriver, WPASupplicant::kDriverWired);
  create_interface_args.Set<std::string>(
      WPASupplicant::kInterfacePropertyConfigFile,
      WPASupplicant::kSupplicantConfPath);
  if (!supplicant_process_proxy()->CreateInterface(create_interface_args,
                                                   &interface_path)) {
    // Interface might've already been created, try to retrieve it.
    if (!supplicant_process_proxy()->GetInterface(link_name(),
                                                  &interface_path)) {
      LOG(ERROR) << __func__ << ": Failed to create interface with supplicant.";
      StopSupplicant();
      return false;
    }
  }

  supplicant_interface_proxy_ =
      control_interface()->CreateSupplicantInterfaceProxy(this, interface_path);
  supplicant_interface_path_ = interface_path;
  return true;
}

bool Ethernet::StartEapAuthentication() {
  KeyValueStore params;
  GetEapService()->eap()->PopulateSupplicantProperties(&certificate_file_,
                                                       &params);
  params.Set<std::string>(WPASupplicant::kNetworkPropertyEapKeyManagement,
                          WPASupplicant::kKeyManagementIeee8021X);
  params.Set<uint32_t>(WPASupplicant::kNetworkPropertyEapolFlags, 0);
  params.Set<uint32_t>(WPASupplicant::kNetworkPropertyScanSSID, 0);

  if (service_) {
    service_->ClearEAPCertification();
  }
  eap_state_handler_.Reset();

  if (!supplicant_network_path_.value().empty()) {
    if (!supplicant_interface_proxy_->RemoveNetwork(supplicant_network_path_)) {
      LOG(ERROR) << "Failed to remove network: "
                 << supplicant_network_path_.value();
      return false;
    }
  }
  if (!supplicant_interface_proxy_->AddNetwork(params,
                                               &supplicant_network_path_)) {
    LOG(ERROR) << "Failed to add network";
    return false;
  }
  CHECK(!supplicant_network_path_.value().empty());

  LOG(INFO) << LoggingTag() << ": Triggering EAP authentication";
  supplicant_interface_proxy_->SelectNetwork(supplicant_network_path_);
  supplicant_interface_proxy_->EAPLogon();
  return true;
}

void Ethernet::StopSupplicant() {
  if (supplicant_interface_proxy_) {
    supplicant_interface_proxy_->EAPLogoff();
  }
  supplicant_interface_proxy_.reset();
  if (!supplicant_interface_path_.value().empty()) {
    if (!supplicant_process_proxy()->RemoveInterface(
            supplicant_interface_path_)) {
      LOG(ERROR) << __func__ << ": Failed to remove interface from supplicant.";
    }
  }
  supplicant_network_path_ = RpcIdentifier("");
  supplicant_interface_path_ = RpcIdentifier("");
  SetIsEapAuthenticated(false);
}

void Ethernet::SetIsEapAuthenticated(bool is_eap_authenticated) {
  if (is_eap_authenticated == is_eap_authenticated_) {
    return;
  }

  // If our EAP authentication state changes, we have now joined a different
  // network.  Restart the DHCP process and any other connection state.
  if (service_) {
    DisconnectFrom(service_.get());
    ConnectTo(service_.get());
  }
  is_eap_authenticated_ = is_eap_authenticated;
  adaptor()->EmitBoolChanged(kEapAuthenticationCompletedProperty,
                             is_eap_authenticated_);
}

void Ethernet::CertificationTask(const std::string& subject, uint32_t depth) {
  CHECK(service_) << "Ethernet " << link_name() << " " << __func__
                  << " with no service.";
  service_->AddEAPCertification(subject, depth);
}

void Ethernet::EAPEventTask(const std::string& status,
                            const std::string& parameter) {
  LOG(INFO) << "In " << __func__ << " with status " << status << ", parameter "
            << parameter;
  Service::ConnectFailure failure = Service::kFailureNone;
  if (eap_state_handler_.ParseStatus(status, parameter, &failure)) {
    LOG(INFO) << "EAP authentication succeeded!";
    SetIsEapAuthenticated(true);
  } else if (failure != Service::Service::kFailureNone) {
    LOG(INFO) << "EAP authentication failed!";
    SetIsEapAuthenticated(false);
  }
}

void Ethernet::SupplicantStateChangedTask(const std::string& state) {
  LOG(INFO) << "Supplicant state changed to " << state;
}

void Ethernet::TryEapAuthenticationTask() {
  if (!GetEapService()->Is8021xConnectable()) {
    if (is_eap_authenticated_) {
      LOG(INFO) << "EAP Service lost 802.1X credentials; "
                << "terminating EAP authentication.";
    } else {
      LOG(INFO) << "EAP Service lacks 802.1X credentials; "
                << "not doing EAP authentication.";
    }
    StopSupplicant();
    return;
  }

  if (!is_eap_detected_) {
    LOG(WARNING) << "EAP authenticator not detected; "
                 << "not doing EAP authentication.";
    return;
  }
  if (!StartSupplicant()) {
    LOG(ERROR) << "Failed to start supplicant.";
    return;
  }
  StartEapAuthentication();
}

SupplicantProcessProxyInterface* Ethernet::supplicant_process_proxy() const {
  return manager()->supplicant_manager()->proxy();
}

void Ethernet::SetupWakeOnLan() {
  struct ethtool_wolinfo wake_on_lan_command;
  struct ifreq interface_command;

  memset(&interface_command, 0, sizeof(interface_command));
  memset(&wake_on_lan_command, 0, sizeof(wake_on_lan_command));
  wake_on_lan_command.cmd = ETHTOOL_SWOL;
  if (manager()->IsWakeOnLanEnabled()) {
    wake_on_lan_command.wolopts = WAKE_MAGIC;
  }
  interface_command.ifr_data = &wake_on_lan_command;

  if (!RunEthtoolCmd(&interface_command)) {
    PLOG(WARNING) << "Failed to enable wake-on-lan";
    return;
  }
}

bool Ethernet::DisableOffloadFeatures() {
  struct ifreq interface_command;
  memset(&interface_command, 0, sizeof(interface_command));

  LOG(INFO) << LoggingTag() << ": Disabling offloading features";
  // Prepare and send a ETHTOOL_GSSET_INFO(ETH_SS_FEATURES) command to
  // get number of features.
  struct {
    struct ethtool_sset_info sset_info;
    uint32_t num_features;
  } sset_info_buf;
  memset(&sset_info_buf, 0, sizeof(sset_info_buf));
  struct ethtool_sset_info* sset_info = &sset_info_buf.sset_info;
  sset_info->cmd = ETHTOOL_GSSET_INFO;
  sset_info->reserved = 0;
  sset_info->sset_mask = 1ULL << ETH_SS_FEATURES;
  interface_command.ifr_data = sset_info;
  bool res = RunEthtoolCmd(&interface_command);
  if (!res) {
    PLOG(ERROR) << LoggingTag()
                << ": ETHTOOL_GSSET_INFO(ETH_SS_FEATURES) failed.";
    return false;
  }
  if (!sset_info->sset_mask || !sset_info_buf.num_features) {
    LOG(ERROR) << LoggingTag()
               << ": ETHTOOL_GSSET_INFO(ETH_SS_FEATURES) failed.";
    return false;
  }

  // Get the number of features
  uint32_t num_features = sset_info_buf.num_features;
  uint32_t num_feature_blocks = (num_features + 31) / 32;

  // Now prepare and send ETHTOOL_GSTRINGS(ETH_SS_FEATURES), to actually
  // get the all the feature strings, for this device.
  struct GstringsBuf {
    ethtool_gstrings gstrings;
    char features[MAX_FEATURE_COUNT][ETH_GSTRING_LEN];
  };
  auto gstrings_buf = std::make_unique<GstringsBuf>();
  memset(gstrings_buf.get(), 0, sizeof(GstringsBuf));
  struct ethtool_gstrings* gstrings = &gstrings_buf->gstrings;
  gstrings->cmd = ETHTOOL_GSTRINGS;
  gstrings->string_set = ETH_SS_FEATURES;
  gstrings->len = num_features;
  interface_command.ifr_data = gstrings;
  if (!RunEthtoolCmd(&interface_command)) {
    PLOG(ERROR) << LoggingTag()
                << ": ETHTOOL_GSTRINGS(ETH_SS_FEATURES) failed.";
    return false;
  }

  // Ensure strings are null terminated
  unsigned int i;
  for (i = 0; i < num_features; i++)
    gstrings_buf->features[i][ETH_GSTRING_LEN - 1] = 0;

  // Prepare & send a ETHTOOL_GFEATURES command to get the current state of
  // features
  struct {
    struct ethtool_gfeatures gfeatures;
    ethtool_get_features_block feature_block[MAX_FEATURE_BLOCKS];
  } gfeatures_buf;
  memset(&gfeatures_buf, 0, sizeof(gfeatures_buf));
  struct ethtool_gfeatures* gfeatures = &gfeatures_buf.gfeatures;
  gfeatures->cmd = ETHTOOL_GFEATURES;
  gfeatures->size = num_feature_blocks;
  interface_command.ifr_data = gfeatures;
  if (!RunEthtoolCmd(&interface_command)) {
    PLOG(ERROR) << LoggingTag() << ": ETHTOOL_GFEATURES command failed.";
    return false;
  }

  // Prepare & send a ETHTOOL_SFEATURES command to enable/disable the features
  // features we need
  struct {
    struct ethtool_sfeatures sfeatures;
    ethtool_set_features_block feature_block[MAX_FEATURE_BLOCKS];
  } sfeatures_buf;
  memset(&sfeatures_buf, 0, sizeof(sfeatures_buf));
  struct ethtool_sfeatures* sfeatures = &sfeatures_buf.sfeatures;
  sfeatures->cmd = ETHTOOL_SFEATURES;
  sfeatures->size = num_feature_blocks;

  int ret = true;

  std::set<std::string> features_to_disable(kFeaturesToDisable.begin(),
                                            kFeaturesToDisable.end());

  for (i = 0; i < num_features && !features_to_disable.empty(); i++) {
    std::string feature = gstrings_buf->features[i];
    if (features_to_disable.find(feature) == features_to_disable.end())
      continue;

    features_to_disable.erase(feature);

    uint32_t block_num = i / 32;
    uint32_t feature_mask = 1 << (i % 32);

    if (feature_mask & gfeatures->features[block_num].never_changed) {
      LOG(ERROR) << "[Not Allowed] cannot disable [" << i << "] " << feature;
      ret = false;
      continue;
    }
    if (feature_mask & ~gfeatures->features[block_num].available) {
      LOG(ERROR) << "[Not Available] cannot disable [" << i << "] " << feature;
      // OK to return success since device does not support the feature.
      continue;
    }
    if (!(feature_mask & gfeatures->features[block_num].active)) {
      LOG(INFO) << "[Already Disabled] Not disabling [" << i << "] " << feature;
      // OK to return success since device has it already disabled.
      continue;
    }
    sfeatures->features[block_num].valid |= feature_mask;
    sfeatures->features[block_num].requested &= ~feature_mask;
    LOG(INFO) << LoggingTag() << ": Disabling [" << i << "] " << feature;
  }

  for (const auto& feature : features_to_disable)
    LOG(INFO) << "[No Such Feature] Skipped disabling: " << feature;

  interface_command.ifr_data = sfeatures;
  if (!RunEthtoolCmd(&interface_command)) {
    PLOG(ERROR) << "Failed to disable offloading features.";
    return false;
  }
  LOG(INFO) << LoggingTag() << ": Disabled offloading features successfully";

  return ret;
}

std::string Ethernet::GetUsbEthernetMacAddressSource(Error* error) {
  return usb_ethernet_mac_address_source_;
}

void Ethernet::RegisterService(EthernetServiceRefPtr service) {
  if (!service) {
    return;
  }
  GetProvider()->RegisterService(service);
}

void Ethernet::DeregisterService(EthernetServiceRefPtr service) {
  if (!service) {
    return;
  }
  GetProvider()->DeregisterService(service);
}

void Ethernet::SetUsbEthernetMacAddressSource(const std::string& source,
                                              ResultCallback callback) {
  SLOG(this, 2) << __func__ << " " << source;

  if (bus_type_ != kDeviceBusTypeUsb) {
    Error error;
    Error::PopulateAndLog(FROM_HERE, &error, Error::kIllegalOperation,
                          "Not allowed on non-USB devices: " + bus_type_);
    std::move(callback).Run(error);
    return;
  }

  std::string new_mac_address;
  if (source == kUsbEthernetMacAddressSourceDesignatedDockMac) {
    new_mac_address =
        ReadMacAddressFromFile(base::FilePath(kVpdDockMacFilePath));
  } else if (source == kUsbEthernetMacAddressSourceBuiltinAdapterMac) {
    new_mac_address =
        ReadMacAddressFromFile(base::FilePath(kVpdEthernetMacFilePath));
  } else if (source == kUsbEthernetMacAddressSourceUsbAdapterMac) {
    new_mac_address = permanent_mac_address_;
  } else {
    Error error;
    Error::PopulateAndLog(FROM_HERE, &error, Error::kInvalidArguments,
                          "Unknown source: " + source);
    std::move(callback).Run(error);
    return;
  }

  if (new_mac_address.empty()) {
    Error error;
    Error::PopulateAndLog(
        FROM_HERE, &error, Error::kNotFound,
        "Failed to find out new MAC address for source: " + source);
    std::move(callback).Run(error);
    return;
  }

  if (new_mac_address == mac_address()) {
    SLOG(this, 4) << __func__ << " new MAC address is equal to the old one";
    if (usb_ethernet_mac_address_source_ != source) {
      usb_ethernet_mac_address_source_ = source;
      adaptor()->EmitStringChanged(kUsbEthernetMacAddressSourceProperty,
                                   usb_ethernet_mac_address_source_);
    }
    std::move(callback).Run(Error(Error::kSuccess));
    return;
  }

  SLOG(this, 2) << "Send netlink request to change MAC address for "
                << link_name() << " device from " << mac_address() << " to "
                << new_mac_address;

  rtnl_handler()->SetInterfaceMac(
      interface_index(), ByteString::CreateFromHexString(new_mac_address),
      base::BindOnce(&Ethernet::OnSetInterfaceMacResponse,
                     weak_ptr_factory_.GetWeakPtr(), source, new_mac_address,
                     std::move(callback)));
}

std::string Ethernet::ReadMacAddressFromFile(const base::FilePath& file_path) {
  std::string mac_address;
  if (!base::ReadFileToString(file_path, &mac_address)) {
    PLOG(ERROR) << "Unable to read MAC address from file: "
                << file_path.value();
    return std::string();
  }
  base::RemoveChars(base::ToLowerASCII(mac_address), ":", &mac_address);
  if (!IsValidMac(mac_address)) {
    LOG(ERROR) << "MAC address from file " << file_path.value()
               << " is invalid: " << mac_address;
    return std::string();
  }
  return mac_address;
}

void Ethernet::OnSetInterfaceMacResponse(const std::string& mac_address_source,
                                         const std::string& new_mac_address,
                                         ResultCallback callback,
                                         int32_t error) {
  if (error) {
    LOG(ERROR) << __func__ << " received response with error "
               << strerror(error);
    if (!callback.is_null()) {
      std::move(callback).Run(Error(Error::kOperationFailed));
    }
    return;
  }

  SLOG(this, 2) << __func__ << " received successful response";

  usb_ethernet_mac_address_source_ = mac_address_source;
  adaptor()->EmitStringChanged(kUsbEthernetMacAddressSourceProperty,
                               usb_ethernet_mac_address_source_);

  set_mac_address(new_mac_address);
  if (!callback.is_null()) {
    std::move(callback).Run(Error(Error::kSuccess));
  }
}

void Ethernet::set_mac_address(const std::string& new_mac_address) {
  SLOG(this, 2) << __func__ << " " << new_mac_address;

  ProfileRefPtr profile;
  if (service_) {
    profile = service_->profile();
  }
  // Abandon and adopt service if service storage identifier will change after
  // changing ethernet MAC address.
  if (permanent_mac_address_.empty() && profile &&
      !service_->HasStorageIdentifier()) {
    profile->AbandonService(service_);
    Device::set_mac_address(new_mac_address);
    profile->AdoptService(service_);
  } else {
    Device::set_mac_address(new_mac_address);
  }

  if (service_) {
    DisconnectFrom(service_.get());
    ConnectTo(service_.get());
  }
}

std::string Ethernet::GetPermanentMacAddressFromKernel() {
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));

  constexpr int kPermAddrBufferSize =
      sizeof(struct ethtool_perm_addr) + MAX_ADDR_LEN;
  char perm_addr_buffer[kPermAddrBufferSize];
  memset(perm_addr_buffer, 0, kPermAddrBufferSize);
  struct ethtool_perm_addr* perm_addr = static_cast<struct ethtool_perm_addr*>(
      static_cast<void*>(perm_addr_buffer));
  perm_addr->cmd = ETHTOOL_GPERMADDR;
  perm_addr->size = MAX_ADDR_LEN;

  ifr.ifr_data = perm_addr;

  if (!RunEthtoolCmd(&ifr)) {
    PLOG(WARNING) << "Failed to read permanent MAC address.";
    return std::string();
  }

  if (perm_addr->size != ETH_ALEN) {
    LOG(WARNING) << "Invalid permanent MAC address size: " << perm_addr->size;
    return std::string();
  }

  ByteString mac_address(perm_addr->data, ETH_ALEN);
  if (mac_address.IsZero()) {
    // All-zero permanent MAC address ("00:00:00:00:00:00") is not meaningful,
    // no matter if it is expected (e.g., for veths) or not.
    LOG(WARNING) << "Permanent MAC address on " << link_name()
                 << " is all zeros. Perhaps veth interface?";
    return std::string();
  }

  std::string mac_address_str = base::ToLowerASCII(mac_address.HexEncode());
  if (!IsValidMac(mac_address_str)) {
    LOG(ERROR) << "Invalid permanent MAC address: " << mac_address_str;
    return std::string();
  }
  return mac_address_str;
}

std::string Ethernet::GetDeviceBusType() const {
  auto device_id = DeviceId::CreateFromSysfs(base::FilePath(
      base::StringPrintf("/sys/class/net/%s/device", link_name().c_str())));

  constexpr DeviceId kPciDevicePattern{DeviceId::BusType::kPci};
  if (device_id && device_id->Match(kPciDevicePattern)) {
    return kDeviceBusTypePci;
  }
  constexpr DeviceId kUsbDevicePattern{DeviceId::BusType::kUsb};
  if (device_id && device_id->Match(kUsbDevicePattern)) {
    return kDeviceBusTypeUsb;
  }
  return std::string();
}

void Ethernet::UpdateLinkSpeed() {
  if (!selected_service()) {
    return;
  }

  struct ethtool_cmd ecmd;
  struct ifreq ifr;

  memset(&ecmd, 0, sizeof(ecmd));
  memset(&ifr, 0, sizeof(ifr));
  ecmd.cmd = ETHTOOL_GSET;
  ifr.ifr_data = &ecmd;

  if (!RunEthtoolCmd(&ifr)) {
    PLOG(ERROR) << LoggingTag() << " " << __func__
                << " ETHTOOL_GSET command failed ";
    return;
  }
  // Value we get from ecmd is mbps, convert it to kbps to keep
  // with other technologies.
  selected_service()->SetUplinkSpeedKbps(ethtool_cmd_speed(&ecmd) *
                                         kMbpsToKbpsFactor);
  selected_service()->SetDownlinkSpeedKbps(ethtool_cmd_speed(&ecmd) *
                                           kMbpsToKbpsFactor);
}

bool Ethernet::RunEthtoolCmd(ifreq* interface_command) {
  int sock = sockets_->Socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_IP);
  if (sock < 0) {
    return false;
  }
  ScopedSocketCloser socket_closer(sockets_.get(), sock);

  strncpy(interface_command->ifr_name, link_name().c_str(),
          sizeof(interface_command->ifr_name));

  return sockets_->Ioctl(sock, SIOCETHTOOL, interface_command) >= 0;
}

void Ethernet::OnNeighborReachabilityEvent(
    int net_interface_index,
    const IPAddress& ip_address,
    patchpanel::Client::NeighborRole role,
    patchpanel::Client::NeighborStatus status) {
  DCHECK(net_interface_index == interface_index());

  using Role = patchpanel::Client::NeighborRole;
  using Status = patchpanel::Client::NeighborStatus;
  if (role != Role::kGateway && role != Role::kGatewayAndDnsServer) {
    return;
  }

  if (!selected_service()) {
    LOG(INFO) << LoggingTag()
              << ": No selected service, ignoring neighbor reachability event";
    return;
  }

  // When a reachability failure event is received and the connection is thought
  // to be healthy, make sure that network validation runs to confirm if there
  // is no link connectivity anymore.
  if (status == Status::kFailed &&
      selected_service()->state() == Service::kStateOnline) {
    LOG(INFO) << LoggingTag()
              << ": gateway reachability failure in 'online' state.";
    // Network validation is expected to time out, do not force a restart in
    // case some other mechanism has already triggered a revalidation which
    // would otherwise get cancelled.
    UpdatePortalDetector(/*restart=*/false);
  }

  // When a reachability success event is received and the connection is thought
  // to be unhealthy, make sure that network validation runs to confirm if link
  // connectivity has been recovered.
  if (status == Status::kReachable &&
      selected_service()->state() == Service::kStateNoConnectivity) {
    LOG(INFO) << LoggingTag()
              << ": gateway reachability event in 'no-connectivity' state.";
    // Validation should be confirmed as soon as possible. If Internet is
    // validation is expected to be short so a restart is always forced.
    UpdatePortalDetector(/*restart=*/true);
  }
}

void Ethernet::NotifyEthernetDriverName() {
  struct ethtool_drvinfo drv;
  struct ifreq ifr;
  char dvrname[kDriverNameSize];
  std::string driver;

  memset(&drv, 0, sizeof(drv));
  memset(&ifr, 0, sizeof(ifr));

  drv.cmd = ETHTOOL_GDRVINFO;
  ifr.ifr_data = &drv;

  if (!RunEthtoolCmd(&ifr)) {
    PLOG(ERROR) << LoggingTag() << ": Failed to get ethernet driver name";
    driver = kEthernetDriverNameError;
  } else {
    strncpy(dvrname, drv.driver, sizeof(dvrname));
    // Add a trailing \0 to avoid driver name we got from dvr.driver
    // is not \0 terminated.
    dvrname[kDriverNameSize - 1] = '\0';
    driver = dvrname;
  }

  // Ignore virtual ethernet interfaces used in tast to simulate a physical
  // ethernet network interface.
  if (driver == kVethDriverName) {
    return;
  }

  Metrics::EthernetDriver driver_enum;
  if (driver == "alx") {
    driver_enum = Metrics::kEthernetDriverAlx;
  } else if (driver == "aqc111") {
    driver_enum = Metrics::kEthernetDriverAqc111;
  } else if (driver == "asix") {
    driver_enum = Metrics::kEthernetDriverAsix;
  } else if (driver == "atlantic") {
    driver_enum = Metrics::kEthernetDriverAtlantic;
  } else if (driver == "ax88179_178a") {
    driver_enum = Metrics::kEthernetDriverAx88179_178a;
  } else if (driver == "cdc_eem") {
    driver_enum = Metrics::kEthernetDriverCdcEem;
  } else if (driver == "cdc_ether") {
    driver_enum = Metrics::kEthernetDriverCdcEther;
  } else if (driver == "cdc_mbim") {
    driver_enum = Metrics::kEthernetDriverCdcMbim;
  } else if (driver == "cdc_ncm") {
    driver_enum = Metrics::kEthernetDriverCdcNcm;
  } else if (driver == "dm9601") {
    driver_enum = Metrics::kEthernetDriverDm9601;
  } else if (driver == "e100") {
    driver_enum = Metrics::kEthernetDriverE100;
  } else if (driver == "e1000") {
    driver_enum = Metrics::kEthernetDriverE1000;
  } else if (driver == "e1000e") {
    driver_enum = Metrics::kEthernetDriverE1000e;
  } else if (driver == "igb") {
    driver_enum = Metrics::kEthernetDriverIgb;
  } else if (driver == "igbvf") {
    driver_enum = Metrics::kEthernetDriverIgbvf;
  } else if (driver == "igc") {
    driver_enum = Metrics::kEthernetDriverIgc;
  } else if (driver == "ipheth") {
    driver_enum = Metrics::kEthernetDriverIpheth;
  } else if (driver == "jme") {
    driver_enum = Metrics::kEthernetDriverJme;
  } else if (driver == "mcs7830") {
    driver_enum = Metrics::kEthernetDriverMcs7830;
  } else if (driver == "pegasus") {
    driver_enum = Metrics::kEthernetDriverPegasus;
  } else if (driver == "r8152") {
    driver_enum = Metrics::kEthernetDriverR8152;
  } else if (driver == "r8169") {
    driver_enum = Metrics::kEthernetDriverR8169;
  } else if (driver == "rtl8150") {
    driver_enum = Metrics::kEthernetDriverRtl8150;
  } else if (driver == "smsc75xx") {
    driver_enum = Metrics::kEthernetDriverSmsc75xx;
  } else if (driver == "smsc95xx") {
    driver_enum = Metrics::kEthernetDriverSmsc95xx;
  } else if (driver == "tg3") {
    driver_enum = Metrics::kEthernetDriverTg3;
  } else if (driver == "error") {
    driver_enum = Metrics::kEthernetDriverError;
  } else {
    LOG(WARNING) << LoggingTag() << ": Unknown ethernet driver name " << '"'
                 << driver << '"';
    driver_enum = Metrics::kEthernetDriverUnknown;
  }
  metrics()->SendEnumToUMA(Metrics::kMetricEthernetDriver, driver_enum);
}

}  // namespace shill
