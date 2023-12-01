// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/wifi.h"

#include <inttypes.h>
#include <limits.h>
#include <linux/if.h>  // Needs definitions from netinet/ether.h
#include <linux/nl80211.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <string.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/numerics/safe_conversions.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <chromeos/dbus/service_constants.h>

#if !defined(DISABLE_FLOSS)
#include "shill/bluetooth/bluetooth_manager_interface.h"
#endif  // DISABLE_FLOSS
#include "shill/control_interface.h"
#include "shill/dbus/dbus_control.h"
#include "shill/device.h"
#include "shill/eap_credentials.h"
#include "shill/error.h"
#include "shill/logging.h"
#include "shill/manager.h"
#include "shill/metrics.h"
#include "shill/net/ieee80211.h"
#include "shill/net/ip_address.h"
#include "shill/net/netlink_manager.h"
#include "shill/net/netlink_message.h"
#include "shill/net/nl80211_message.h"
#include "shill/net/rtnl_handler.h"
#include "shill/net/shill_time.h"
#include "shill/network/dhcp_controller.h"
#include "shill/scope_logger.h"
#include "shill/store/key_value_store.h"
#include "shill/store/property_accessor.h"
#include "shill/supplicant/supplicant_eap_state_handler.h"
#include "shill/supplicant/supplicant_interface_proxy_interface.h"
#include "shill/supplicant/supplicant_manager.h"
#include "shill/supplicant/supplicant_network_proxy_interface.h"
#include "shill/supplicant/supplicant_process_proxy_interface.h"
#include "shill/supplicant/wpa_supplicant.h"
#include "shill/technology.h"
#include "shill/wifi/passpoint_credentials.h"
#include "shill/wifi/wake_on_wifi.h"
#include "shill/wifi/wifi_cqm.h"
#include "shill/wifi/wifi_endpoint.h"
#include "shill/wifi/wifi_link_statistics.h"
#include "shill/wifi/wifi_metrics_utils.h"
#include "shill/wifi/wifi_phy.h"
#include "shill/wifi/wifi_provider.h"
#include "shill/wifi/wifi_rf.h"
#include "shill/wifi/wifi_service.h"
#include "shill/wifi/wifi_state.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kWiFi;
static std::string ObjectID(const WiFi* w) {
  return w->GetRpcIdentifier().value();
}
}  // namespace Logging

// statics
const char* const WiFi::kDefaultBgscanMethod =
    WPASupplicant::kNetworkBgscanMethodSimple;
const uint16_t WiFi::kDefaultScanIntervalSeconds = 60;

// Scan interval while connected.
const uint16_t WiFi::kBackgroundScanIntervalSeconds = 360;
// Default background scan interval when there is only one endpoint on the
// network. We'd like to strike a balance between 1) not triggering too
// frequently with poor signal, 2) hardly triggering at all with good signal,
// and 3) being able to discover additional APs that weren't initially visible.
const int WiFi::kSingleEndpointBgscanIntervalSeconds = 86400;
// Age (in seconds) beyond which a BSS cache entry will not be preserved,
// across a suspend/resume.
const time_t WiFi::kMaxBSSResumeAgeSeconds = 10;
const char WiFi::kInterfaceStateUnknown[] = "shill-unknown";
const int WiFi::kNumFastScanAttempts = 3;

// The default random MAC mask is FF:FF:FF:00:00:00. Bits which are a 1 in
// the mask stay the same during randomization, and bits which are 0 are
// randomized. This mask means the OUI will remain unchanged but the last
// three octets will be different.
const std::vector<unsigned char> WiFi::kRandomMacMask{255, 255, 255, 0, 0, 0};

const char WiFi::kWakeOnWiFiNotSupported[] = "Wake on WiFi not supported";

namespace {
const uint16_t kDefaultBgscanShortIntervalSeconds = 64;
const uint16_t kSingleEndpointBgscanShortIntervalSeconds = 360;
const int32_t kDefaultBgscanSignalThresholdDbm = -72;
// Delay between scans when supplicant finds "No suitable network".
const time_t kRescanIntervalSeconds = 1;
const base::TimeDelta kPendingTimeout = base::Seconds(15);
const int kMaxRetryCreateInterfaceAttempts = 6;
const base::TimeDelta kRetryCreateInterfaceInterval = base::Seconds(10);
const int16_t kDefaultDisconnectDbm = 0;
const int16_t kDefaultDisconnectThresholdDbm = -75;
const int kInvalidMaxSSIDs = -1;

// Maximum time between two link monitor failures to declare this link (network)
// as unreliable.
constexpr auto kLinkUnreliableThreshold = base::Minutes(60);
// Mark a unreliable service as reliable if no more link monitor failures in
// the below timeout after this unreliable service became connected again.
constexpr auto kLinkUnreliableResetTimeout = base::Minutes(5);

bool IsPrintableAsciiChar(char c) {
  return (c >= ' ' && c <= '~');
}

// Is the state of wpa_supplicant indicating that it is currently possibly
// attempting to connect to a network (e.g. is it associating?).
bool IsWPAStateConnectionInProgress(const std::string& state) {
  return state == WPASupplicant::kInterfaceStateAuthenticating ||
         state == WPASupplicant::kInterfaceStateAssociating ||
         state == WPASupplicant::kInterfaceStateAssociated ||
         state == WPASupplicant::kInterfaceState4WayHandshake ||
         state == WPASupplicant::kInterfaceStateGroupHandshake;
}
}  // namespace

WiFi::WiFi(Manager* manager,
           const std::string& link,
           const std::string& address,
           int interface_index,
           uint32_t phy_index,
           std::unique_ptr<WakeOnWiFiInterface> wake_on_wifi)
    : Device(manager, link, address, interface_index, Technology::kWiFi),
      provider_(manager->wifi_provider()),
      time_(Time::GetInstance()),
      supplicant_connect_attempts_(0),
      supplicant_present_(false),
      supplicant_state_(kInterfaceStateUnknown),
      supplicant_bss_(RpcIdentifier("(unknown)")),
      supplicant_assoc_status_(IEEE_80211::kStatusCodeSuccessful),
      supplicant_auth_status_(IEEE_80211::kStatusCodeSuccessful),
      supplicant_disconnect_reason_(IEEE_80211::kReasonCodeInvalid),
      disconnect_signal_dbm_(kDefaultDisconnectDbm),
      disconnect_threshold_dbm_(kDefaultDisconnectThresholdDbm),
      max_ssids_per_scan_(kInvalidMaxSSIDs),
      supplicant_auth_mode_(WPASupplicant::kAuthModeUnknown),
      need_bss_flush_(false),
      resumed_at_((struct timeval){0}),
      fast_scans_remaining_(kNumFastScanAttempts),
      has_already_completed_(false),
      is_roaming_in_progress_(false),
      pending_eap_failure_(Service::kFailureNone),
      is_debugging_connection_(false),
      eap_state_handler_(new SupplicantEAPStateHandler()),
      last_link_monitor_failed_time_(0),
      bgscan_short_interval_seconds_(kDefaultBgscanShortIntervalSeconds),
      bgscan_signal_threshold_dbm_(kDefaultBgscanSignalThresholdDbm),
      scan_interval_seconds_(kDefaultScanIntervalSeconds),
      netlink_manager_(NetlinkManager::GetInstance()),
      random_mac_supported_(false),
      random_mac_enabled_(false),
      sched_scan_supported_(false),
      broadcast_probe_was_skipped_(false),
      interworking_select_enabled_(true),
      hs20_bss_count_(0),
      need_interworking_select_(false),
      last_interworking_select_timestamp_(std::nullopt),
      receive_byte_count_at_connect_(0),
      wifi_link_statistics_(new WiFiLinkStatistics()),
      phy_index_(phy_index),
      wifi_cqm_(new WiFiCQM(metrics(), this)),
      wake_on_wifi_(std::move(wake_on_wifi)),
      weak_ptr_factory_while_started_(this),
      weak_ptr_factory_(this) {
  scoped_supplicant_listener_.reset(
      new SupplicantManager::ScopedSupplicantListener(
          manager->supplicant_manager(),
          base::BindRepeating(&WiFi::OnSupplicantPresence,
                              weak_ptr_factory_.GetWeakPtr())));

  PropertyStore* store = this->mutable_store();
  store->RegisterDerivedString(
      kBgscanMethodProperty,
      StringAccessor(new CustomAccessor<WiFi, std::string>(
          this, &WiFi::GetBgscanMethod, &WiFi::SetBgscanMethod,
          &WiFi::ClearBgscanMethod)));
  HelpRegisterDerivedUint16(store, kBgscanShortIntervalProperty,
                            &WiFi::GetBgscanShortInterval,
                            &WiFi::SetBgscanShortInterval);
  HelpRegisterDerivedInt32(store, kBgscanSignalThresholdProperty,
                           &WiFi::GetBgscanSignalThreshold,
                           &WiFi::SetBgscanSignalThreshold);
  store->RegisterConstBool(kMacAddressRandomizationSupportedProperty,
                           &random_mac_supported_);
  HelpRegisterDerivedBool(store, kMacAddressRandomizationEnabledProperty,
                          &WiFi::GetRandomMacEnabled,
                          &WiFi::SetRandomMacEnabled);

  store->RegisterDerivedKeyValueStore(
      kLinkStatisticsProperty,
      KeyValueStoreAccessor(new CustomAccessor<WiFi, KeyValueStore>(
          this, &WiFi::GetLinkStatistics, nullptr)));

  // TODO(quiche): Decide if scan_pending_ is close enough to
  // "currently scanning" that we don't care, or if we want to track
  // scan pending/currently scanning/no scan scheduled as a tri-state
  // kind of thing.
  HelpRegisterConstDerivedBool(store, kScanningProperty, &WiFi::GetScanPending);
  HelpRegisterDerivedUint16(store, kScanIntervalProperty,
                            &WiFi::GetScanInterval, &WiFi::SetScanInterval);
  HelpRegisterConstDerivedBool(store, kWakeOnWiFiSupportedProperty,
                               &WiFi::GetWakeOnWiFiSupported);

  HelpRegisterDerivedBool(store, kPasspointInterworkingSelectEnabledProperty,
                          &WiFi::GetInterworkingSelectEnabled,
                          &WiFi::SetInterworkingSelectEnabled);

  if (wake_on_wifi_) {
    wake_on_wifi_->InitPropertyStore(store);
  }
  ScopeLogger::GetInstance()->RegisterScopeEnableChangedCallback(
      ScopeLogger::kWiFi, base::BindRepeating(&WiFi::OnWiFiDebugScopeChanged,
                                              weak_ptr_factory_.GetWeakPtr()));
  CHECK(netlink_manager_);
  netlink_handler_ = base::BindRepeating(&WiFi::HandleNetlinkBroadcast,
                                         weak_ptr_factory_.GetWeakPtr());
  netlink_manager_->AddBroadcastHandler(netlink_handler_);
  wifi_state_ = std::make_unique<WiFiState>();
  SLOG(this, 2) << "WiFi device " << link_name() << " initialized.";
}

WiFi::~WiFi() {
  netlink_manager_->RemoveBroadcastHandler(netlink_handler_);
}

void WiFi::Start(EnabledStateChangedCallback callback) {
  SLOG(this, 2) << "WiFi " << link_name() << " starting.";
  if (enabled()) {
    return;
  }
  Metrics::WiFiAdapterInfo hw_info{
      .vendor_id = Metrics::kWiFiStructuredMetricsErrorValue,
      .product_id = Metrics::kWiFiStructuredMetricsErrorValue,
      .subsystem_id = Metrics::kWiFiStructuredMetricsErrorValue};
  GetDeviceHardwareIds(&hw_info.vendor_id, &hw_info.product_id,
                       &hw_info.subsystem_id);
  metrics()->NotifyWiFiAdapterStateChanged(true, hw_info);

  // TODO(b/244630773): Get rid of this call altogether once phy capabilities
  // are tracked in WiFiPhy.
  GetPhyInfo();
  // Connect to WPA supplicant if it's already present. If not, we'll connect to
  // it when it appears.
  supplicant_connect_attempts_ = 0;
  ConnectToSupplicant();
  if (wake_on_wifi_) {
    wake_on_wifi_->Start();
  }

  std::move(callback).Run(Error(Error::kSuccess));
}

void WiFi::Stop(EnabledStateChangedCallback callback) {
  SLOG(this, 2) << "WiFi " << link_name() << " stopping.";
  // Unlike other devices, we leave the DBus name watcher in place here, because
  // WiFi callbacks expect notifications even if the device is disabled.
  Metrics::WiFiAdapterInfo hw_info{
      .vendor_id = Metrics::kWiFiStructuredMetricsErrorValue,
      .product_id = Metrics::kWiFiStructuredMetricsErrorValue,
      .subsystem_id = Metrics::kWiFiStructuredMetricsErrorValue};
  GetDeviceHardwareIds(&hw_info.vendor_id, &hw_info.product_id,
                       &hw_info.subsystem_id);
  metrics()->NotifyWiFiAdapterStateChanged(false, hw_info);
  DropConnection();
  StopScanTimer();
  for (const auto& endpoint : endpoint_by_rpcid_) {
    provider_->OnEndpointRemoved(endpoint.second);
  }
  endpoint_by_rpcid_.clear();
  for (const auto& map_entry : rpcid_by_service_) {
    RemoveNetwork(map_entry.second);
  }
  rpcid_by_service_.clear();
  // Remove all the credentials registered in supplicant.
  for (const auto& creds : provider_->GetCredentials()) {
    RemoveCred(creds);
  }
  pending_matches_.clear();
  hs20_bss_count_ = 0;
  need_interworking_select_ = false;
  // Remove interface from supplicant.
  if (supplicant_present_ && supplicant_interface_proxy_) {
    supplicant_process_proxy()->RemoveInterface(supplicant_interface_path_);
  }
  pending_scan_results_.reset();
  current_service_ = nullptr;  // breaks a reference cycle
  pending_service_ = nullptr;  // breaks a reference cycle
  // Reset autoconnect cooldown time for all WiFi services to 0. When WiFi
  // interface is toggled off-and-on (which is often used to fix issues by
  // resetting states), the cooldown time should be reset so that it does not
  // block auto-connection in the next adapter session.
  provider_->ResetServicesAutoConnectCooldownTime();
  is_debugging_connection_ = false;
  SetPhyState(WiFiState::PhyState::kIdle, WiFiState::ScanMethod::kNone,
              __func__);
  StopPendingTimer();
  StopReconnectTimer();
  StopRequestingStationInfo();

  // TODO(b/248054832): Move this deregistration into WiFiProvider.
  provider_->DeregisterDeviceFromPhy(this, phy_index_);

  weak_ptr_factory_while_started_.InvalidateWeakPtrs();

  SLOG(this, 2) << "WiFi " << link_name() << " supplicant_interface_proxy_ "
                << (supplicant_interface_proxy_.get() ? "is set."
                                                      : "is not set.");
  SLOG(this, 2) << "WiFi " << link_name() << " pending_service_ "
                << (pending_service_.get() ? "is set." : "is not set.");
  SLOG(this, 2) << "WiFi " << link_name() << " has "
                << endpoint_by_rpcid_.size() << " EndpointMap entries.";

  std::move(callback).Run(Error(Error::kSuccess));
}

void WiFi::Scan(Error* /*error*/, const std::string& reason) {
  if ((wifi_state_->GetPhyState() != WiFiState::PhyState::kIdle) ||
      (current_service_.get() && current_service_->IsConnecting())) {
    SLOG(this, 2) << "Ignoring scan request while scanning or connecting.";
    return;
  }
  SLOG(this, 1) << __func__ << " on " << link_name() << " from " << reason;
  // Needs to send a D-Bus message, but may be called from D-Bus
  // signal handler context (via Manager::RequestScan). So defer work
  // to event loop.
  dispatcher()->PostTask(
      FROM_HERE, base::BindOnce(&WiFi::ScanTask,
                                weak_ptr_factory_while_started_.GetWeakPtr()));
}

int16_t WiFi::GetSignalLevelForActiveService() {
  return current_service_ ? current_service_->SignalLevel()
                          : WiFiService::SignalLevelMin;
}

bool WiFi::AddCred(const PasspointCredentialsRefPtr& credentials) {
  SLOG(this, 2) << __func__;
  CHECK(credentials);

  if (!supplicant_present_) {
    // Supplicant is not here yet, the credentials will be pushed later.
    credentials->SetSupplicantId(DBusControl::NullRpcIdentifier());
    return false;
  }

  RpcIdentifier id;
  KeyValueStore properties;
  if (!credentials->ToSupplicantProperties(&properties)) {
    LOG(ERROR) << "failed to get supplicant properties from passpoint "
               << "credentials " << credentials->id();
    return false;
  }
  if (!supplicant_interface_proxy_->AddCred(properties, &id)) {
    LOG(ERROR) << "failed add passpoint credentials " << credentials->id()
               << " to supplicant";
    credentials->SetSupplicantId(DBusControl::NullRpcIdentifier());
    return false;
  }
  credentials->SetSupplicantId(id);
  // There's a new credentials set, we'll need to try matching them.
  need_interworking_select_ = true;
  return true;
}

bool WiFi::RemoveCred(const PasspointCredentialsRefPtr& credentials) {
  SLOG(this, 2) << __func__;
  CHECK(credentials);

  if (!supplicant_present_ || !enabled()) {
    // Supplicant is not here, there's not credentials to remove.
    // Just invalidate the path.
    credentials->SetSupplicantId(DBusControl::NullRpcIdentifier());
    return false;
  }

  if (credentials->supplicant_id() == DBusControl::NullRpcIdentifier()) {
    LOG(ERROR) << "credentials " << credentials->id()
               << " not registered in supplicant.";
    return false;
  }

  RpcIdentifier id(credentials->supplicant_id());
  credentials->SetSupplicantId(DBusControl::NullRpcIdentifier());

  if (!supplicant_interface_proxy_->RemoveCred(id)) {
    // The only reason for a failure here would be an invalid D-Bus path.
    LOG(ERROR) << "failed to remove credentials " << credentials->id()
               << " from supplicant with path " << id.value();
    return false;
  }
  return true;
}

void WiFi::EnsureScanAndConnectToBestService(Error* error) {
  // If the radio is currently idle, start a scan.  Otherwise, wait until the
  // radio becomes idle.
  if (wifi_state_->GetPhyState() == WiFiState::PhyState::kIdle) {
    wifi_state_->SetEnsuredScanState(WiFiState::EnsuredScanState::kScanning);
    Scan(error, "Starting ensured scan.");
  } else {
    wifi_state_->SetEnsuredScanState(WiFiState::EnsuredScanState::kWaiting);
  }
}

void WiFi::AddPendingScanResult(const RpcIdentifier& path,
                                const KeyValueStore& properties,
                                bool is_removal) {
  // BSS events might come immediately after Stop(). Don't bother stashing them
  // at all.
  if (!enabled()) {
    return;
  }

  if (!pending_scan_results_) {
    pending_scan_results_.reset(new PendingScanResults(
        base::BindOnce(&WiFi::PendingScanResultsHandler,
                       weak_ptr_factory_while_started_.GetWeakPtr())));
    dispatcher()->PostTask(FROM_HERE,
                           pending_scan_results_->callback.callback());
  }
  pending_scan_results_->results.emplace_back(path, properties, is_removal);
}

void WiFi::BSSAdded(const RpcIdentifier& path,
                    const KeyValueStore& properties) {
  // Called from a D-Bus signal handler, and may need to send a D-Bus
  // message. So defer work to event loop.
  AddPendingScanResult(path, properties, false);
}

void WiFi::BSSRemoved(const RpcIdentifier& path) {
  // Called from a D-Bus signal handler, and may need to send a D-Bus
  // message. So defer work to event loop.
  AddPendingScanResult(path, {}, true);
}

void WiFi::Certification(const KeyValueStore& properties) {
  dispatcher()->PostTask(
      FROM_HERE,
      base::BindOnce(&WiFi::CertificationTask,
                     weak_ptr_factory_while_started_.GetWeakPtr(), properties));
}

void WiFi::EAPEvent(const std::string& status, const std::string& parameter) {
  dispatcher()->PostTask(
      FROM_HERE, base::BindOnce(&WiFi::EAPEventTask,
                                weak_ptr_factory_while_started_.GetWeakPtr(),
                                status, parameter));
}

void WiFi::PropertiesChanged(const KeyValueStore& properties) {
  SLOG(this, 2) << __func__;
  // Called from D-Bus signal handler, but may need to send a D-Bus
  // message. So defer work to event loop.
  dispatcher()->PostTask(
      FROM_HERE, base::BindOnce(&WiFi::PropertiesChangedTask,
                                weak_ptr_factory_.GetWeakPtr(), properties));
}

void WiFi::ScanDone(const bool& success) {
  // This log line should be kept at INFO level to support the Shill log
  // processor.
  LOG(INFO) << __func__;

  if (!enabled()) {
    SLOG(this, 2) << "Ignoring scan completion while disabled";
    return;
  }

  // Defer handling of scan result processing, because that processing
  // may require the the registration of new D-Bus objects. And such
  // registration can't be done in the context of a D-Bus signal
  // handler.
  if (pending_scan_results_) {
    pending_scan_results_->is_complete = true;
    return;
  }
  if (success) {
    scan_failed_callback_.Cancel();
    dispatcher()->PostTask(
        FROM_HERE,
        base::BindOnce(&WiFi::ScanDoneTask,
                       weak_ptr_factory_while_started_.GetWeakPtr()));
  } else {
    scan_failed_callback_.Reset(base::BindOnce(
        &WiFi::ScanFailedTask, weak_ptr_factory_while_started_.GetWeakPtr()));
    dispatcher()->PostDelayedTask(FROM_HERE, scan_failed_callback_.callback(),
                                  kPostScanFailedDelay);
  }
}

void WiFi::PskMismatch() {
  dispatcher()->PostTask(
      FROM_HERE, base::BindOnce(&WiFi::PskMismatchTask,
                                weak_ptr_factory_while_started_.GetWeakPtr()));
}

void WiFi::InterworkingAPAdded(const RpcIdentifier& BSS,
                               const RpcIdentifier& cred,
                               const KeyValueStore& properties) {
  SLOG(this, 2) << __func__;

  if (!enabled()) {
    // Ignore spurious match events emitted after Stop().
    SLOG(this, 2) << "Ignoring interworking matches while being disabled.";
    return;
  }

  // Add the new match to the list. It'll be processed when the whole matching
  // sequence will be finished.
  pending_matches_.emplace_back(BSS, cred, properties);
}

void WiFi::InterworkingSelectDone() {
  SLOG(this, 2) << __func__;

  metrics()->SendSparseToUMA(Metrics::kMetricPasspointInterworkingMatches,
                             pending_matches_.size());

  if (last_interworking_select_timestamp_) {
    metrics()->SendToUMA(
        Metrics::kMetricPasspointInterworkingDurationMillis,
        (base::Time::Now() - *last_interworking_select_timestamp_)
            .InMilliseconds());
  }
  last_interworking_select_timestamp_ = std::nullopt;

  if (!enabled()) {
    SLOG(this, 2) << "Ignoring interworking done while being disabled.";
    return;
  }

  if (pending_matches_.empty()) {
    // No matches, nothing to do.
    return;
  }

  // Ensure credentials are available through their supplicant identifier.
  std::map<RpcIdentifier, PasspointCredentialsRefPtr> creds_by_rpcid;
  for (const auto& c : provider_->GetCredentials()) {
    creds_by_rpcid[c->supplicant_id()] = c;
  }

  // Translate each interworking match to a credential match by finding the
  // real references behind supplicant ids. Some credentials set or BSS might
  // be missing because they can be removed while the selection is in progress,
  // in such case the match is ignored.
  std::vector<WiFiProvider::PasspointMatch> matches;
  for (const auto& m : pending_matches_) {
    PasspointCredentialsRefPtr creds = creds_by_rpcid[m.cred_path];
    if (!creds) {
      LOG(WARNING) << "Passpoint credentials not found: "
                   << m.cred_path.value();
      continue;
    }

    WiFiEndpointRefPtr endpoint = endpoint_by_rpcid_[m.bss_path];
    if (!endpoint) {
      LOG(WARNING) << "endpoint not found: " << m.bss_path.value();
      continue;
    }

    const std::string type_str =
        m.properties.Get<std::string>(WPASupplicant::kCredentialsMatchType);
    WiFiProvider::MatchPriority type = WiFiProvider::MatchPriority::kUnknown;
    if (type_str == WPASupplicant::kCredentialsMatchTypeHome) {
      type = WiFiProvider::MatchPriority::kHome;
    } else if (type_str == WPASupplicant::kCredentialsMatchTypeRoaming) {
      type = WiFiProvider::MatchPriority::kRoaming;
    } else if (type_str == WPASupplicant::kCredentialsMatchTypeUnknown) {
      type = WiFiProvider::MatchPriority::kUnknown;
    } else {
      NOTREACHED() << __func__ << " unknown match type: " << type_str;
    }

    matches.emplace_back(creds, endpoint, type);
  }
  pending_matches_.clear();
  if (!matches.empty()) {
    provider_->OnPasspointCredentialsMatches(std::move(matches));
  }
}

void WiFi::ConnectTo(WiFiService* service, Error* error) {
  CHECK(service) << "Can't connect to NULL service.";
  RpcIdentifier network_rpcid;

  // Ignore this connection attempt if suppplicant is not present.
  // This is possible when we try to connect right after WiFi
  // boostrapping is completed (through weaved). Refer to b/24605760
  // for more information.
  // Once supplicant is detected, shill will auto-connect to this
  // service (if this service is configured for auto-connect) when
  // it is discovered in the scan.
  if (!supplicant_present_) {
    LOG(WARNING) << "Trying to connect before supplicant is present";
    return;
  }

  // Reject the connection attempt if the service uses WEP security and WEP is
  // not supported by the WiFi device.
  if (service->IsSecurityMatch(kSecurityWep) && !SupportsWEP()) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kWepNotSupported,
        base::StringPrintf(
            "%s: cannot connect to %s, WEP is not supported on this device",
            link_name().c_str(), service->log_name().c_str()));
    return;
  }

  // TODO(quiche): Handle cases where already connected.
  if (pending_service_ && pending_service_ == service) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kInProgress,
        base::StringPrintf(
            "%s: ignoring ConnectTo %s, which is already pending",
            link_name().c_str(), service->log_name().c_str()));
    return;
  }

  if (pending_service_ && pending_service_ != service) {
    LOG(INFO) << "Connecting to: " << service->log_name() << ", "
              << "mode: " << service->mode() << ", "
              << "key management: " << service->key_management() << ", "
              << "AP physical mode: " << service->ap_physical_mode() << ", "
              << "frequency: " << service->frequency();
    // This is a signal to SetPendingService(nullptr) to not modify the scan
    // state since the overall story arc isn't reflected by the disconnect.
    // It is, instead, described by the transition to either kScanFoundNothing
    // or kScanConnecting (made by |SetPendingService|, below).
    if (wifi_state_->GetScanMethod() != WiFiState::ScanMethod::kNone) {
      SetPhyState(WiFiState::PhyState::kTransitionToConnecting,
                  wifi_state_->GetScanMethod(), __func__);
    }
    // Explicitly disconnect pending service.
    pending_service_->set_expecting_disconnect(true);
    DisconnectFrom(pending_service_.get());
  }

  Error unused_error;
  network_rpcid = FindNetworkRpcidForService(service, &unused_error);
  const auto [new_mac, mac_policy_change] = service->UpdateMACAddress();
  if (network_rpcid.value().empty()) {
    KeyValueStore service_params =
        service->GetSupplicantConfigurationParameters();
    const uint32_t scan_ssid = 1;  // "True": Use directed probe.
    service_params.Set<uint32_t>(WPASupplicant::kNetworkPropertyScanSSID,
                                 scan_ssid);
    std::string bgscan_string = AppendBgscan(service, &service_params);
    service_params.Set<uint32_t>(WPASupplicant::kNetworkPropertyDisableVHT,
                                 provider_->disable_vht());
    if (!supplicant_interface_proxy_->AddNetwork(service_params,
                                                 &network_rpcid)) {
      Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                            "Failed to add network");
      SetPhyState(WiFiState::PhyState::kIdle, wifi_state_->GetScanMethod(),
                  __func__);
      return;
    }
    CHECK(!network_rpcid.value().empty());  // No DBus path should be empty.
    service->set_bgscan_string(bgscan_string);
    rpcid_by_service_[service] = network_rpcid;
  } else if (mac_policy_change || !new_mac.empty()) {
    // During AddNetwork() (above) MAC and policy are being configured, but here
    // we need to send an explicit update.
    std::unique_ptr<SupplicantNetworkProxyInterface> supplicant_network_proxy =
        control_interface()->CreateSupplicantNetworkProxy(network_rpcid);
    KeyValueStore kv;
    if (mac_policy_change) {
      service->SetSupplicantMACPolicy(kv);
    }
    if (!new_mac.empty()) {
      kv.Set(WPASupplicant::kNetworkPropertyMACAddrValue, new_mac);
    }
    if (!supplicant_network_proxy->SetProperties(kv)) {
      LOG(ERROR) << "Failed to change MAC for network: "
                 << network_rpcid.value();
      return;
    }
  }

  if (service->HasRecentConnectionIssues()) {
    SetConnectionDebugging(true);
  }

  wifi_link_statistics_->Reset();
  service->EmitConnectionAttemptEvent();
  if (current_service_) {
    // If we're already connected, |SelectNetwork| will make wpa_supplicant
    // disconnect the current service before connecting to the new service.
    current_service_->set_expecting_disconnect(true);
  }
  supplicant_interface_proxy_->SelectNetwork(network_rpcid);
  SetPendingService(service);
  CHECK(current_service_.get() != pending_service_.get());

  GetPrimaryNetwork()->Stop();
  // SelectService here (instead of in LinkEvent, like Ethernet), so
  // that, if we fail to bring up L2, we can attribute failure correctly.
  //
  // TODO(quiche): When we add code for dealing with connection failures,
  // reconsider if this is the right place to change the selected service.
  // see discussion in crbug.com/203282.
  SelectService(service);
  EmitMACAddress(new_mac);
}

void WiFi::DisconnectFromIfActive(WiFiService* service) {
  SLOG(this, 2) << __func__ << " service " << service->log_name();

  if (service != current_service_ && service != pending_service_) {
    if (!service->IsActive(nullptr)) {
      SLOG(this, 2) << "In " << __func__ << "(): " << service->log_name()
                    << " is not active, no need to initiate disconnect";
      return;
    }
  }

  DisconnectFrom(service);
}

void WiFi::DisconnectFrom(WiFiService* service) {
  SLOG(this, 2) << __func__ << " service " << service->log_name();

  if (service != current_service_ && service != pending_service_) {
    // TODO(quiche): Once we have asynchronous reply support, we should
    // generate a D-Bus error here. (crbug.com/206812)
    LOG(WARNING) << "In " << __func__ << "(): "
                 << " ignoring request to disconnect from: "
                 << service->log_name()
                 << " which is neither current nor pending";
    return;
  }

  if (pending_service_ && service != pending_service_) {
    // TODO(quiche): Once we have asynchronous reply support, we should
    // generate a D-Bus error here. (crbug.com/206812)
    LOG(WARNING) << "In " << __func__ << "(): "
                 << " ignoring request to disconnect from: "
                 << service->log_name() << " which is not the pending service.";
    return;
  }

  if (!pending_service_ && service != current_service_) {
    // TODO(quiche): Once we have asynchronous reply support, we should
    // generate a D-Bus error here. (crbug.com/206812)
    LOG(WARNING) << "In " << __func__ << "(): "
                 << " ignoring request to disconnect from: "
                 << service->log_name() << " which is not the current service.";
    return;
  }

  if (pending_service_) {
    // Since wpa_supplicant has not yet set CurrentBSS, we can't depend
    // on this to drive the service state back to idle.  Do that here.
    // Update service state for pending service.
    disconnect_signal_dbm_ = pending_service_->SignalLevel();
    // |expecting_disconnect()| implies that it wasn't a failure to connect.
    // For example we're cancelling pending_service_ before we actually
    // attempted to connect.
    bool is_attempt_failure = !pending_service_->expecting_disconnect();
    ServiceDisconnected(pending_service_, is_attempt_failure);
  } else if (service) {
    disconnect_signal_dbm_ = service->SignalLevel();
  }

  SetPendingService(nullptr);
  StopReconnectTimer();
  StopRequestingStationInfo();

  if (!supplicant_present_) {
    LOG(ERROR) << "In " << __func__ << "(): "
               << "wpa_supplicant is not present; silently resetting "
               << "current_service_.";
    if (current_service_ == selected_service()) {
      DropConnection();
    }
    current_service_ = nullptr;
    return;
  }

  bool disconnect_in_progress = true;
  // We'll call RemoveNetwork and reset |current_service_| after
  // supplicant notifies us that the CurrentBSS has changed.
  if (!supplicant_interface_proxy_->Disconnect()) {
    disconnect_in_progress = false;
  }

  if (supplicant_state_ != WPASupplicant::kInterfaceStateCompleted ||
      !disconnect_in_progress) {
    // Can't depend on getting a notification of CurrentBSS change.
    // So effect changes immediately.  For instance, this can happen when
    // a disconnect is triggered by a BSS going away.
    Error unused_error;
    RemoveNetworkForService(service, &unused_error);
    if (service == selected_service()) {
      DropConnection();
    } else {
      SLOG(this, 5) << __func__ << " skipping DropConnection, "
                    << "selected_service is "
                    << (selected_service() ? selected_service()->log_name()
                                           : "(null)");
    }
    current_service_ = nullptr;
  }

  CHECK(current_service_ == nullptr ||
        current_service_.get() != pending_service_.get());
}

bool WiFi::DisableNetwork(const RpcIdentifier& network) {
  std::unique_ptr<SupplicantNetworkProxyInterface> supplicant_network_proxy =
      control_interface()->CreateSupplicantNetworkProxy(network);
  if (!supplicant_network_proxy->SetEnabled(false)) {
    LOG(ERROR) << "DisableNetwork for " << network.value() << " failed.";
    return false;
  }
  return true;
}

bool WiFi::RemoveNetwork(const RpcIdentifier& network) {
  return supplicant_interface_proxy_->RemoveNetwork(network);
}

bool WiFi::IsIdle() const {
  return !current_service_ && !pending_service_;
}

void WiFi::ClearCachedCredentials(const WiFiService* service) {
  // Give up on the connection attempt for the pending service immediately since
  // the credential for it had already changed. This will allow the Manager to
  // start a new connection attempt for the pending service immediately without
  // waiting for the pending connection timeout.
  // current_service_ will get disconnect notification from the CurrentBSS
  // change event, so no need to explicitly disconnect here.
  if (service == pending_service_) {
    LOG(INFO) << "Disconnect pending service: credential changed";
    DisconnectFrom(pending_service_.get());
  }

  Error unused_error;
  RemoveNetworkForService(service, &unused_error);
}

void WiFi::NotifyEndpointChanged(const WiFiEndpointConstRefPtr& endpoint) {
  provider_->OnEndpointUpdated(endpoint);
}

std::string WiFi::AppendBgscan(WiFiService* service,
                               KeyValueStore* service_params) const {
  std::string method = bgscan_method_;
  int short_interval = bgscan_short_interval_seconds_;
  int signal_threshold = bgscan_signal_threshold_dbm_;
  int scan_interval = kBackgroundScanIntervalSeconds;
  if (method.empty()) {
    // If multiple APs are detected for this SSID, configure the default method
    // with pre-set parameters. Otherwise, use extended scan intervals.
    method = kDefaultBgscanMethod;
    if (service->GetBSSIDConnectableEndpointCount() <= 1) {
      SLOG(2) << "Background scan intervals extended -- single connectable "
              << "endpoint for Service.";
      short_interval = kSingleEndpointBgscanShortIntervalSeconds;
      scan_interval = kSingleEndpointBgscanIntervalSeconds;
    }
  } else if (method == WPASupplicant::kNetworkBgscanMethodNone) {
    SLOG(2) << "Background scan disabled -- chose None method.";
  } else {
    // If the background scan method was explicitly specified, honor the
    // configured background scan interval.
    scan_interval = scan_interval_seconds_;
  }
  std::string config_string;
  if (method != WPASupplicant::kNetworkBgscanMethodNone) {
    config_string =
        base::StringPrintf("%s:%d:%d:%d", method.c_str(), short_interval,
                           signal_threshold, scan_interval);
  }
  SLOG(4) << "Background scan: '" << config_string << "'";
  service_params->Set<std::string>(WPASupplicant::kNetworkPropertyBgscan,
                                   config_string);
  return config_string;
}

bool WiFi::ReconfigureBgscan(WiFiService* service) {
  SLOG(this, 4) << __func__ << " for " << service->log_name();
  KeyValueStore bgscan_params;
  std::string bgscan_string = AppendBgscan(service, &bgscan_params);
  if (service->bgscan_string() == bgscan_string) {
    SLOG(this, 4) << "No change in bgscan parameters.";
    return false;
  }

  Error unused_error;
  RpcIdentifier id = FindNetworkRpcidForService(service, &unused_error);
  if (id.value().empty()) {
    return false;
  }

  std::unique_ptr<SupplicantNetworkProxyInterface> network_proxy =
      control_interface()->CreateSupplicantNetworkProxy(id);
  if (!network_proxy->SetProperties(bgscan_params)) {
    LOG(ERROR) << "SetProperties for " << id.value() << " failed.";
    return false;
  }
  LOG(INFO) << "Updated bgscan parameters: " << bgscan_string;
  service->set_bgscan_string(bgscan_string);
  return true;
}

bool WiFi::ReconfigureBgscanForRelevantServices() {
  bool ret = true;
  if (current_service_) {
    ret = ReconfigureBgscan(current_service_.get()) && ret;
  }
  if (pending_service_) {
    ret = ReconfigureBgscan(pending_service_.get()) && ret;
  }
  return ret;
}

std::string WiFi::GetBgscanMethod(Error* /* error */) {
  return bgscan_method_.empty() ? kDefaultBgscanMethod : bgscan_method_;
}

bool WiFi::SetBgscanMethod(const std::string& method, Error* error) {
  if (method != WPASupplicant::kNetworkBgscanMethodSimple &&
      method != WPASupplicant::kNetworkBgscanMethodLearn &&
      method != WPASupplicant::kNetworkBgscanMethodNone) {
    const auto error_message =
        base::StringPrintf("Unrecognized bgscan method %s", method.c_str());
    LOG(WARNING) << error_message;
    error->Populate(Error::kInvalidArguments, error_message);
    return false;
  }
  if (bgscan_method_ == method) {
    return false;
  }
  bgscan_method_ = method;
  return ReconfigureBgscanForRelevantServices();
}

bool WiFi::SetBgscanShortInterval(const uint16_t& seconds, Error* /*error*/) {
  if (bgscan_short_interval_seconds_ == seconds) {
    return false;
  }
  bgscan_short_interval_seconds_ = seconds;
  return ReconfigureBgscanForRelevantServices();
}

bool WiFi::SetBgscanSignalThreshold(const int32_t& dbm, Error* /*error*/) {
  if (bgscan_signal_threshold_dbm_ == dbm) {
    return false;
  }
  bgscan_signal_threshold_dbm_ = dbm;
  return ReconfigureBgscanForRelevantServices();
}

bool WiFi::SetScanInterval(const uint16_t& seconds, Error* /*error*/) {
  if (scan_interval_seconds_ == seconds) {
    return false;
  }
  scan_interval_seconds_ = seconds;
  if (enabled()) {
    StartScanTimer();
  }
  // The scan interval affects both foreground scans (handled by
  // |scan_timer_callback_|), and background scans (handled by
  // supplicant).
  return ReconfigureBgscanForRelevantServices();
}

bool WiFi::GetRandomMacEnabled(Error* /*error*/) {
  return random_mac_enabled_;
}

bool WiFi::SetRandomMacEnabled(const bool& enabled, Error* error) {
  if (!supplicant_present_ || !supplicant_interface_proxy_.get()) {
    SLOG(this, 2) << "Ignoring random MAC while supplicant is not present.";
    return false;
  }

  if (random_mac_enabled_ == enabled) {
    return false;
  }
  if (!random_mac_supported_) {
    const std::string message =
        "This WiFi device does not support MAC address randomization";
    LOG(ERROR) << message;
    if (error) {
      error->Populate(Error::kNotSupported, message, FROM_HERE);
    }
    return false;
  }
  if ((enabled && supplicant_interface_proxy_->EnableMacAddressRandomization(
                      kRandomMacMask, sched_scan_supported_)) ||
      (!enabled &&
       supplicant_interface_proxy_->DisableMacAddressRandomization())) {
    random_mac_enabled_ = enabled;
    return true;
  }
  return false;
}

void WiFi::ClearBgscanMethod(Error* /*error*/) {
  bgscan_method_.clear();
}

bool WiFi::SetInterworkingSelectEnabled(const bool& enabled,
                                        Error* /* error */) {
  if (interworking_select_enabled_ == enabled) {
    // No-op
    return false;
  }
  interworking_select_enabled_ = enabled;
  if (interworking_select_enabled_) {
    // Interworking selection has just been enabled, we want to try a selection
    // after next scan.
    need_interworking_select_ = true;
  }
  return true;
}

void WiFi::AssocStatusChanged(const int32_t new_assoc_status) {
  SLOG(this, 2) << "WiFi " << link_name()
                << " supplicant updated AssocStatusCode to " << new_assoc_status
                << " (was " << supplicant_assoc_status_ << ")";
  if (supplicant_auth_status_ != IEEE_80211::kStatusCodeSuccessful) {
    LOG(WARNING) << "Supplicant authentication status is set to "
                 << supplicant_auth_status_
                 << " despite getting a new association status.";
    supplicant_auth_status_ = IEEE_80211::kStatusCodeSuccessful;
  }
  supplicant_assoc_status_ = new_assoc_status;
}

void WiFi::AuthStatusChanged(const int32_t new_auth_status) {
  SLOG(this, 2) << "WiFi " << link_name()
                << " supplicant updated AuthStatusCode to " << new_auth_status
                << " (was " << supplicant_auth_status_ << ")";
  if (supplicant_assoc_status_ != IEEE_80211::kStatusCodeSuccessful) {
    LOG(WARNING) << "Supplicant association status is set to "
                 << supplicant_assoc_status_
                 << " despite getting a new authentication status.";
    supplicant_assoc_status_ = IEEE_80211::kStatusCodeSuccessful;
  }
  supplicant_auth_status_ = new_auth_status;
}

void WiFi::CurrentBSSChanged(const RpcIdentifier& new_bss) {
  LOG(INFO) << "WiFi " << link_name() << " CurrentBSS "
            << supplicant_bss_.value() << " -> " << new_bss.value();

  // Store signal strength of BSS when disconnecting.
  if (supplicant_bss_.value() != WPASupplicant::kCurrentBSSNull &&
      new_bss.value() == WPASupplicant::kCurrentBSSNull) {
    const WiFiEndpointConstRefPtr endpoint(GetCurrentEndpoint());
    if (endpoint == nullptr) {
      LOG(ERROR) << "Can't get endpoint for current supplicant BSS "
                 << supplicant_bss_.value();
      // Default to value that will not imply out of range error in
      // ServiceDisconnected or PendingTimeoutHandler.
      disconnect_signal_dbm_ = kDefaultDisconnectDbm;
    } else {
      disconnect_signal_dbm_ = endpoint->signal_strength();
      LOG(INFO) << "Current BSS signal strength at disconnect: "
                << disconnect_signal_dbm_;
    }
  }

  RpcIdentifier old_bss = supplicant_bss_;
  supplicant_bss_ = new_bss;
  has_already_completed_ = false;
  is_roaming_in_progress_ = false;
  if (current_service_) {
    current_service_->SetIsRekeyInProgress(false);
  }
  metrics()->NotifyBSSIDChanged();

  // Any change in CurrentBSS means supplicant is actively changing our
  // connectivity.  We no longer need to track any previously pending
  // reconnect.
  StopReconnectTimer();
  StopRequestingStationInfo();

  if (new_bss.value() == WPASupplicant::kCurrentBSSNull) {
    HandleDisconnect();
    if (!provider_->GetHiddenSSIDList().empty()) {
      // Before disconnecting, wpa_supplicant probably scanned for
      // APs. So, in the normal case, we defer to the timer for the next scan.
      //
      // However, in the case of hidden SSIDs, supplicant knows about
      // at most one of them. (That would be the hidden SSID we were
      // connected to, if applicable.)
      //
      // So, in this case, we initiate an immediate scan. This scan
      // will include the hidden SSIDs we know about (up to the limit of
      // kScanMAxSSIDsPerScan).
      //
      // We may want to reconsider this immediate scan, if/when shill
      // takes greater responsibility for scanning (vs. letting
      // supplicant handle most of it).
      Scan(nullptr, __func__);
    }
  } else {
    HandleRoam(new_bss, old_bss);
  }

  // Reset the EAP handler only after calling HandleDisconnect() above
  // so our EAP state could be used to detect a failed authentication.
  eap_state_handler_->Reset();
  pending_eap_failure_ = Service::kFailureNone;

  // If we are selecting a new service, or if we're clearing selection
  // of a something other than the pending service, call SelectService.
  // Otherwise skip SelectService, since this will cause the pending
  // service to be marked as Idle.
  if (current_service_ || selected_service() != pending_service_) {
    SelectService(current_service_);
  }

  // Invariant check: a Service can either be current, or pending, but
  // not both.
  CHECK(current_service_.get() != pending_service_.get() ||
        current_service_.get() == nullptr);

  // If we are no longer debugging a problematic WiFi connection, return
  // to the debugging level indicated by the WiFi debugging scope.
  if ((!current_service_ || !current_service_->HasRecentConnectionIssues()) &&
      (!pending_service_ || !pending_service_->HasRecentConnectionIssues())) {
    SetConnectionDebugging(false);
  }
}

void WiFi::DisconnectReasonChanged(const int32_t new_value) {
  int32_t sanitized_value =
      (new_value == INT32_MIN) ? INT32_MAX : abs(new_value);
  if (sanitized_value > IEEE_80211::kReasonCodeMax) {
    LOG(WARNING) << "Received disconnect reason " << sanitized_value
                 << " from supplicant greater than kReasonCodeMax."
                 << " Perhaps WiFiReasonCode needs to be updated.";
    sanitized_value = IEEE_80211::kReasonCodeMax;
  }
  auto new_reason = static_cast<IEEE_80211::WiFiReasonCode>(sanitized_value);

  std::string update;
  if (supplicant_disconnect_reason_ != IEEE_80211::kReasonCodeInvalid) {
    update = base::StringPrintf(" from %d", supplicant_disconnect_reason_);
  }

  std::string new_disconnect_description = "Success";
  if (new_reason != 0) {
    new_disconnect_description = IEEE_80211::ReasonToString(new_reason);
  }

  LOG(INFO) << base::StringPrintf(
      "WiFi %s supplicant updated DisconnectReason%s to %d (%s)",
      link_name().c_str(), update.c_str(), new_reason,
      new_disconnect_description.c_str());
  supplicant_disconnect_reason_ = new_reason;

  Metrics::WiFiDisconnectByWhom by_whom = (new_value < 0)
                                              ? Metrics::kDisconnectedNotByAp
                                              : Metrics::kDisconnectedByAp;
  metrics()->Notify80211Disconnect(by_whom, new_reason);

  WiFiService* affected_service =
      current_service_.get() ? current_service_.get() : pending_service_.get();

  if (!affected_service) {
    SLOG(this, 2) << "WiFi " << link_name()
                  << " received a disconnection reason change while not"
                  << " connected or connecting";
    return;
  }

  // wpa_supplicant does not distinguish if a reason code is associated with
  // a connection attempt failure or disconnection from a connected service. The
  // metrics for attempt failure is handled in |ServiceDisconnected| so here
  // only emit a disconnection event when the reason code change is not
  // associated with a connection attempt failure.
  if (IsConnectionAttemptFailure(*affected_service)) {
    SLOG(this, 2) << "WiFi " << link_name()
                  << " received a disconnection reason change associated with"
                  << " a connection attempt failure";
    return;
  }
  // The case where the device is roaming is handled separately in
  // |HandleRoam()|.
  Metrics::WiFiDisconnectionType disconnect_type =
      Metrics::kWiFiDisconnectionTypeUnknown;
  if (affected_service->explicitly_disconnected() ||
      affected_service->expecting_disconnect()) {
    disconnect_type = Metrics::kWiFiDisconnectionTypeExpectedUserAction;
  } else {
    disconnect_type =
        by_whom == Metrics::kDisconnectedNotByAp
            ? Metrics::kWiFiDisconnectionTypeUnexpectedSTADisconnect
            : Metrics::kWiFiDisconnectionTypeUnexpectedAPDisconnect;
  }
  affected_service->EmitDisconnectionEvent(disconnect_type,
                                           supplicant_disconnect_reason_);
}

void WiFi::CurrentAuthModeChanged(const std::string& auth_mode) {
  if (auth_mode != WPASupplicant::kAuthModeInactive &&
      auth_mode != WPASupplicant::kAuthModeUnknown) {
    supplicant_auth_mode_ = auth_mode;
  }
}

bool WiFi::IsStateTransitionConnectionMaintenance(
    const WiFiService& service) const {
  // In some cases we see changes in wpa_supplicant's state that are caused by
  // a "maintenance" event that does not really necessarily reflect a change
  // in the high-level user-visible "connected" state. For example, rekeying
  // will trigger a transition from |kInterfaceStateCompleted| to
  // |kInterfaceStateGroupHandshake| and back to |kInterfaceStateCompleted|,
  // but it's not a full connection attempt.
  return service.is_rekey_in_progress();
}

bool WiFi::IsConnectionAttemptFailure(const WiFiService& service) const {
  bool is_attempt_failure =
      pending_service_ && (&service != current_service_.get());
  // In some cases (for example when the 4-way handshake is still ongoing),
  // |pending_service_| has already been reset to |nullptr| since we had already
  // gone through Auth+Assoc stages. It is still a failure to attempt to connect
  // when we fail then, for example during the handshake. Because of that we
  // also have to check the state of wpa_supplicant to see if it was in the
  // middle of e.g. the 4-way handshake when it reported a failure. However, to
  // ensure that we don't incorrectly classify "maintenance" operations (e.g.
  // rekeying) as connection *attempt* failures rather than disconnections, we
  // also need to verify that we're not currently performing a "maintenance"
  // operation that would temporarily move the state back from "connected" to
  // "handshake" (rekeying case) or "associating" (roaming case) or similar.
  // If all those conditions (state is compatible with in-progress connection
  // and there is no ongoing "maintenance" operation) then a failure implies
  // a failed *attempted* connection rather than a disconnection.
  if (!is_attempt_failure) {
    is_attempt_failure = IsWPAStateConnectionInProgress(supplicant_state_) &&
                         !IsStateTransitionConnectionMaintenance(service);
  }
  return is_attempt_failure;
}

void WiFi::HandleDisconnect() {
  // Identify the affected service. We expect to get a disconnect
  // event when we fall off a Service that we were connected
  // to. However, we also allow for the case where we get a disconnect
  // event while attempting to connect from a disconnected state.
  WiFiService* affected_service =
      current_service_.get() ? current_service_.get() : pending_service_.get();

  if (!affected_service) {
    SLOG(this, 2) << "WiFi " << link_name()
                  << " disconnected while not connected or connecting";
    return;
  }

  SLOG(this, 2) << "WiFi " << link_name() << " disconnected from "
                << " (or failed to connect to) "
                << affected_service->log_name();

  if (affected_service == current_service_.get() && pending_service_.get()) {
    // Current service disconnected intentionally for network switching,
    // set service state to idle.
    affected_service->SetState(Service::kStateIdle);
  } else {
    bool is_attempt_failure = IsConnectionAttemptFailure(*affected_service);
    // Perform necessary handling for disconnected service.
    ServiceDisconnected(affected_service, is_attempt_failure);
  }

  current_service_ = nullptr;

  if (affected_service == selected_service()) {
    // If our selected service has disconnected, destroy IP configuration state.
    DropConnection();
  }

  Error error;
  if (!DisableNetworkForService(affected_service, &error)) {
    if (error.type() == Error::kNotFound) {
      SLOG(this, 2) << "WiFi " << link_name() << " disconnected from "
                    << " (or failed to connect to) service "
                    << affected_service->log_name() << ", "
                    << "but could not find supplicant network to disable.";
    } else {
      LOG(ERROR) << "DisableNetwork failed on " << link_name()
                 << "for: " << affected_service->log_name() << ".";
    }
  }

  // Negate signal_strength (goes from dBm to -dBm) because the metrics don't
  // seem to handle negative values well.  Now everything's positive.
  metrics()->SendToUMA(Metrics::kMetricWiFiSignalAtDisconnect,
                       -disconnect_signal_dbm_);
  affected_service->NotifyCurrentEndpoint(nullptr);
  metrics()->SendToUMA(Metrics::kMetricWiFiDisconnect,
                       affected_service->explicitly_disconnected());

  if (affected_service == pending_service_.get()) {
    // The attempt to connect to |pending_service_| failed. Clear
    // |pending_service_|, to indicate we're no longer in the middle
    // of a connect request.
    SetPendingService(nullptr);
  } else if (pending_service_) {
    // We've attributed the disconnection to what was the
    // |current_service_|, rather than the |pending_service_|.
    //
    // If we're wrong about that (i.e. supplicant reported this
    // CurrentBSS change after attempting to connect to
    // |pending_service_|), we're depending on supplicant to retry
    // connecting to |pending_service_|, and delivering another
    // CurrentBSS change signal in the future.
    //
    // Log this fact, to help us debug (in case our assumptions are
    // wrong).
    SLOG(this, 2) << "WiFi " << link_name()
                  << " pending connection to: " << pending_service_->log_name()
                  << " after disconnect";
  }

  // If we disconnect, initially scan at a faster frequency, to make sure
  // we've found all available APs.
  RestartFastScanAttempts();
}

void WiFi::ServiceDisconnected(WiFiServiceRefPtr affected_service,
                               bool is_attempt_failure) {
  SLOG(this, 1) << __func__ << " service " << affected_service->log_name();

  // Check if service was explicitly disconnected due to failure or
  // is explicitly disconnected by user.
  if (!affected_service->IsInFailState() &&
      !affected_service->explicitly_disconnected() &&
      !affected_service->expecting_disconnect()) {
    // Check auth/assoc status codes and send metric if a status code indicates
    // failure (otherwise logs and UMA will only contain status code failures
    // caused by a pending connection timeout).
    Service::ConnectFailure failure_from_status = ExamineStatusCodes();

    // Determine disconnect failure reason.
    Service::ConnectFailure failure;
    if (SuspectCredentials(affected_service, &failure)) {
      // If we've reached here, |SuspectCredentials| has already set
      // |failure| to the appropriate value.
    } else {
      SLOG(this, 2) << "Supplicant disconnect reason: "
                    << IEEE_80211::ReasonToString(
                           supplicant_disconnect_reason_);
      // Disconnected for some other reason.
      // Map IEEE error codes to shill error codes.
      switch (supplicant_disconnect_reason_) {
        case IEEE_80211::kReasonCodeInactivity:
        case IEEE_80211::kReasonCodeSenderHasLeft: {
          std::string signal_msg = "Disconnect signal: ";
          signal_msg += std::to_string(disconnect_signal_dbm_);
          if (SignalOutOfRange(disconnect_signal_dbm_)) {
            LOG(INFO) << signal_msg;
            failure = Service::kFailureOutOfRange;
          } else {
            SLOG(2) << signal_msg;
            failure = Service::kFailureDisconnect;
          }
        } break;
        case IEEE_80211::kReasonCodeNonAuthenticated:
        case IEEE_80211::kReasonCodeReassociationNotAuthenticated:
        case IEEE_80211::kReasonCodePreviousAuthenticationInvalid:
          failure = Service::kFailureNotAuthenticated;
          break;
        case IEEE_80211::kReasonCodeNonAssociated:
          failure = Service::kFailureNotAssociated;
          break;
        case IEEE_80211::kReasonCodeTooManySTAs:
          failure = Service::kFailureTooManySTAs;
          break;
        case IEEE_80211::kReasonCode8021XAuth:
          failure = Service::kFailureEAPAuthentication;
          break;
        default:
          // If we don't have a failure type to set given the disconnect reason,
          // see if assoc/auth status codes can lead to an informative failure
          // reason. Will be kFailureUnknown if that isn't the case.
          failure = failure_from_status;
          break;
      }
    }
    if (failure == Service::kFailureEAPAuthentication &&
        pending_eap_failure_ != Service::kFailureNone) {
      failure = pending_eap_failure_;
    } else if (failure == Service::kFailureUnknown &&
               SignalOutOfRange(disconnect_signal_dbm_)) {
      // We have assumed we have disconnected since the current endpoint no
      // longer shows up in the scan. If wpa_supplicant did not give us a
      // reason code, then it will be |kFailureUnknown|. A check here can
      // verify the difference between a true unknown failure and an out of
      // range failure.
      failure = Service::kFailureOutOfRange;
    }
    if (!affected_service->ShouldIgnoreFailure()) {
      affected_service->SetFailure(failure);
    }
    if (is_attempt_failure) {
      // We attempted to connect to a service but the attempt failed. Report
      // a failure to connect (as opposed to a disconnection from a service we
      // were successfully connected to).
      affected_service->EmitConnectionAttemptResultEvent(failure);
      LOG(ERROR) << "Failed to connect due to reason: "
                 << Service::ConnectFailureToString(failure);
    } else {
      LOG(ERROR) << "Disconnected due to reason: "
                 << Service::ConnectFailureToString(failure);
    }
  }

  // Set service state back to idle, so this service can be used for
  // future connections.
  affected_service->SetState(Service::kStateIdle);
}

bool WiFi::SignalOutOfRange(const int16_t& disconnect_signal) {
  return disconnect_signal <= disconnect_threshold_dbm_ &&
         disconnect_signal != kDefaultDisconnectDbm;
}

Service::ConnectFailure WiFi::ExamineStatusCodes() const {
  SLOG(4) << "Supplicant authentication status: " << supplicant_auth_status_;
  SLOG(4) << "Supplicant association status: " << supplicant_assoc_status_;
  bool is_auth_error =
      supplicant_auth_status_ != IEEE_80211::kStatusCodeSuccessful;
  bool is_assoc_error =
      supplicant_assoc_status_ != IEEE_80211::kStatusCodeSuccessful;
  DCHECK(!(is_auth_error && is_assoc_error));
  if (!is_auth_error && !is_assoc_error) {
    return Service::kFailureUnknown;
  }

  int32_t status = supplicant_auth_status_;
  std::string error_name = "Authentication";
  std::string metric_name = Metrics::kMetricWiFiAuthFailureType;
  Service::ConnectFailure proposed_failure = Service::kFailureNotAuthenticated;
  if (is_assoc_error) {
    status = supplicant_assoc_status_;
    error_name = "Association";
    metric_name = Metrics::kMetricWiFiAssocFailureType;
    proposed_failure = Service::kFailureNotAssociated;
  }

  LOG(INFO) << "WiFi Device " << link_name() << ": " << error_name << " error "
            << status << " ("
            << IEEE_80211::StatusToString(
                   static_cast<IEEE_80211::WiFiStatusCode>(status))
            << ")";
  metrics()->SendEnumToUMA(metric_name, status, IEEE_80211::kStatusCodeMax);

  if (status == IEEE_80211::kStatusCodeMaxSta) {
    proposed_failure = Service::kFailureTooManySTAs;
  }
  return proposed_failure;
}

// We use the term "Roam" loosely. In particular, we include the case
// where we "Roam" to a BSS from the disconnected state.
void WiFi::HandleRoam(const RpcIdentifier& new_bss,
                      const RpcIdentifier& old_bss) {
  EndpointMap::iterator endpoint_it = endpoint_by_rpcid_.find(new_bss);
  if (endpoint_it == endpoint_by_rpcid_.end()) {
    LOG(WARNING) << "WiFi " << link_name() << " connected to unknown BSS "
                 << new_bss.value();
    return;
  }

  const WiFiEndpointConstRefPtr endpoint(endpoint_it->second);
  WiFiServiceRefPtr service = provider_->FindServiceForEndpoint(endpoint);
  if (!service) {
    LOG(WARNING) << "WiFi " << link_name()
                 << " could not find Service for Endpoint "
                 << endpoint->bssid_string() << " (service will be unchanged)";
    return;
  }

  metrics()->NotifyAp80211kSupport(
      endpoint->krv_support().neighbor_list_supported);
  metrics()->NotifyAp80211rSupport(endpoint->krv_support().ota_ft_supported,
                                   endpoint->krv_support().otds_ft_supported);
  metrics()->NotifyAp80211vDMSSupport(endpoint->krv_support().dms_supported);
  metrics()->NotifyAp80211vBSSMaxIdlePeriodSupport(
      endpoint->krv_support().bss_max_idle_period_supported);
  metrics()->NotifyAp80211vBSSTransitionSupport(
      endpoint->krv_support().bss_transition_supported);
  metrics()->NotifyCiscoAdaptiveFTSupport(
      endpoint->krv_support().adaptive_ft_supported);
  metrics()->NotifyHS20Support(endpoint->hs20_information().supported,
                               endpoint->hs20_information().version);
  metrics()->NotifyMBOSupport(endpoint->mbo_support());
  metrics()->NotifyStreamClassificationSupport(
      endpoint->qos_support().scs_supported,
      endpoint->qos_support().mscs_supported);
  metrics()->NotifyAlternateEDCASupport(
      endpoint->qos_support().alternate_edca_supported);

  SLOG(this, 2) << "WiFi " << link_name() << " roamed to Endpoint "
                << endpoint->bssid_string() << " "
                << LogSSID(endpoint->ssid_string());

  service->NotifyCurrentEndpoint(endpoint);

  if (pending_service_.get() && service.get() != pending_service_.get()) {
    // The Service we've roamed on to is not the one we asked for.
    // We assume that this is transient, and that wpa_supplicant
    // is trying / will try to connect to |pending_service_|.
    //
    // If it succeeds, we'll end up back here, but with |service|
    // pointing at the same service as |pending_service_|.
    //
    // If it fails, we'll process things in HandleDisconnect.
    //
    // So we leave |pending_service_| untouched.
    SLOG(this, 2) << "WiFi " << link_name() << " new current Endpoint "
                  << endpoint->bssid_string()
                  << " is not part of pending service "
                  << pending_service_->log_name();

    // Quick check: if we didn't roam onto |pending_service_|, we
    // should still be on |current_service_|.
    if (service.get() != current_service_.get()) {
      LOG(WARNING) << "WiFi " << link_name() << " new current Endpoint "
                   << endpoint->bssid_string()
                   << " is neither part of pending service "
                   << pending_service_->log_name()
                   << " nor part of current service "
                   << (current_service_ ? current_service_->log_name()
                                        : "(nullptr)");
      // wpa_supplicant has no knowledge of the pending_service_ at this point.
      // Disconnect the pending_service_, so that it can be connectable again.
      // Otherwise, we'd have to wait for the pending timeout to trigger the
      // disconnect. This will speed up the connection attempt process for
      // the pending_service_.
      DisconnectFrom(pending_service_.get());
    }
    return;
  }

  if (pending_service_) {
    // We assume service.get() == pending_service_.get() here, because
    // of the return in the previous if clause.
    //
    // Boring case: we've connected to the service we asked
    // for. Simply update |current_service_| and |pending_service_|.
    current_service_ = service;
    SetPhyState(WiFiState::PhyState::kConnected, wifi_state_->GetScanMethod(),
                __func__);
    SetPendingService(nullptr);
    return;
  }

  // |pending_service_| was nullptr, so we weren't attempting to connect
  // to a new Service. Quick check that we're still on |current_service_|.
  if (service.get() != current_service_.get()) {
    LOG(WARNING) << "WiFi " << link_name() << " new current Endpoint "
                 << endpoint->bssid_string()
                 << (current_service_.get()
                         ? base::StringPrintf(
                               " is not part of current service %s",
                               current_service_->log_name().c_str())
                         : " with no current service");
    // We didn't expect to be here, but let's cope as well as we
    // can. Update |current_service_| to keep it in sync with
    // supplicant.
    current_service_ = service;

    // If this service isn't already marked as actively connecting (likely,
    // since this service is a bit of a surprise) set the service as
    // associating.
    if (!current_service_->IsConnecting()) {
      current_service_->SetState(Service::kStateAssociating);
    }

    return;
  }

  // At this point, we know that |pending_service_| was nullptr, and that
  // we're still on |current_service_|.  We should track this roaming
  // event so we can refresh our IPConfig if it succeeds.
  if (!is_roaming_in_progress_) {
    // We're roaming, so report an expected disconnection event (from the old
    // BSSID) and a new connection attempt event (to the new BSSID).
    if (old_bss.value() != WPASupplicant::kCurrentBSSNull &&
        old_bss.value() != new_bss.value()) {
      // During a roam, wpa_supplicant sends us multiple CurrentBSS property
      // changes, and some are a "fake" transition between identical BSSIDs.
      // Only emit the "disconnect"/"connection attempts" events if it's a
      // "real" roam.
      service->EmitDisconnectionEvent(
          Metrics::kWiFiDisconnectionTypeExpectedRoaming,
          IEEE_80211::kReasonCodeReserved0);
      service->EmitConnectionAttemptEvent();
    }
  }
  is_roaming_in_progress_ = true;

  return;
}

RpcIdentifier WiFi::FindNetworkRpcidForService(const WiFiService* service,
                                               Error* error) {
  ReverseServiceMap::const_iterator rpcid_it = rpcid_by_service_.find(service);
  if (rpcid_it == rpcid_by_service_.end()) {
    const auto error_message = base::StringPrintf(
        "WiFi %s cannot find supplicant network rpcid for service %s",
        link_name().c_str(), service->log_name().c_str());
    // There are contexts where this is not an error, such as when a service
    // is clearing whatever cached credentials may not exist.
    SLOG(this, 2) << error_message;
    if (error) {
      error->Populate(Error::kNotFound, error_message);
    }
    return RpcIdentifier("");
  }

  return rpcid_it->second;
}

bool WiFi::DisableNetworkForService(const WiFiService* service, Error* error) {
  RpcIdentifier rpcid = FindNetworkRpcidForService(service, error);
  if (rpcid.value().empty()) {
    // Error is already populated.
    return false;
  }

  if (!DisableNetwork(rpcid)) {
    const auto error_message = base::StringPrintf(
        "WiFi %s cannot disable network for service %s: "
        "DBus operation failed for rpcid %s.",
        link_name().c_str(), service->log_name().c_str(),
        rpcid.value().c_str());
    Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                          error_message);

    // Make sure that such errored networks are removed, so problems do not
    // propagate to future connection attempts.
    RemoveNetwork(rpcid);
    rpcid_by_service_.erase(service);

    return false;
  }

  return true;
}

bool WiFi::RemoveNetworkForService(const WiFiService* service, Error* error) {
  RpcIdentifier rpcid = FindNetworkRpcidForService(service, error);
  if (rpcid.value().empty()) {
    // Error is already populated.
    return false;
  }

  // Erase the rpcid from our tables regardless of failure below, since even
  // if in failure, we never want to use this network again.
  rpcid_by_service_.erase(service);

  // TODO(quiche): Reconsider giving up immediately. Maybe give
  // wpa_supplicant some time to retry, first.
  if (!RemoveNetwork(rpcid)) {
    const auto error_message = base::StringPrintf(
        "WiFi %s cannot remove network for service %s: "
        "DBus operation failed for rpcid %s.",
        link_name().c_str(), service->log_name().c_str(),
        rpcid.value().c_str());
    Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                          error_message);
    return false;
  }

  return true;
}

void WiFi::PendingScanResultsHandler() {
  CHECK(pending_scan_results_);
  SLOG(this, 2) << __func__ << " with " << pending_scan_results_->results.size()
                << " results and is_complete set to "
                << pending_scan_results_->is_complete;
  for (const auto& result : pending_scan_results_->results) {
    if (result.is_removal) {
      BSSRemovedTask(result.path);
    } else {
      BSSAddedTask(result.path, result.properties);
    }
  }
  if (pending_scan_results_->is_complete) {
    ScanDoneTask();
  }
  pending_scan_results_.reset();
}

void WiFi::ParseFeatureFlags(const Nl80211Message& nl80211_message) {
  // Verify NL80211_CMD_NEW_WIPHY.
  if (nl80211_message.command() != NewWiphyMessage::kCommand) {
    LOG(ERROR) << "Received unexpected command: " << nl80211_message.command();
    return;
  }

  // Look for scheduled scan support.
  AttributeListConstRefPtr cmds;
  if (nl80211_message.const_attributes()->ConstGetNestedAttributeList(
          NL80211_ATTR_SUPPORTED_COMMANDS, &cmds)) {
    AttributeIdIterator cmds_iter(*cmds);
    for (; !cmds_iter.AtEnd(); cmds_iter.Advance()) {
      uint32_t cmd;
      if (!cmds->GetU32AttributeValue(cmds_iter.GetId(), &cmd)) {
        LOG(ERROR) << "Failed to get supported cmd " << cmds_iter.GetId();
        return;
      }
      if (cmd == NL80211_CMD_START_SCHED_SCAN)
        sched_scan_supported_ = true;
    }
  }

  uint32_t flag;
  if (nl80211_message.const_attributes()->GetU32AttributeValue(
          NL80211_ATTR_FEATURE_FLAGS, &flag)) {
    // There are two flags for MAC randomization: one for regular scans and one
    // for scheduled scans. Only look for the latter if scheduled scans are
    // supported.
    //
    // This flag being set properly currently relies on the assumption that
    // sched_scan_supported_ is set sometime before this codepath is called.
    // A potential TODO to not rely on this assumption is to accumulate all
    // split messages, log the DONE reply, and perform our determinations at the
    // end (aka set this flag). More discussion can be found on
    // crrev.com/c/3028791.

    random_mac_supported_ =
        (flag & NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR) &&
        (!sched_scan_supported_ ||
         (flag & NL80211_FEATURE_SCHED_SCAN_RANDOM_MAC_ADDR));
    if (random_mac_supported_) {
      SLOG(this, 7) << __func__ << ": "
                    << "Supports random MAC: " << random_mac_supported_;
    }
  }
}

void WiFi::ParseCipherSuites(const Nl80211Message& nl80211_message) {
  // Verify NL80211_CMD_NEW_WIPHY.
  if (nl80211_message.command() != NewWiphyMessage::kCommand) {
    LOG(ERROR) << "Received unexpected command: " << nl80211_message.command();
    return;
  }

  ByteString cipher_suites_raw;
  if (!nl80211_message.const_attributes()->GetRawAttributeValue(
          NL80211_ATTR_CIPHER_SUITES, &cipher_suites_raw)) {
    return;
  }

  int num_bytes = cipher_suites_raw.GetLength();
  const uint8_t* cipher_suites = cipher_suites_raw.GetConstData();

  // NL80211_ATTR_CIPHER_SUITES is a set of U32 values, each of which represent
  // a supported cipher suite. Each of these U32 values is represented as 4
  // consecutive bytes in the raw data, which we parse here.
  supported_cipher_suites_.clear();
  for (int i = 0; i + 3 < num_bytes; i += 4) {
    uint32_t cipher_suite = ((uint32_t)cipher_suites[i + 3]) << 24 |
                            ((uint32_t)cipher_suites[i + 2]) << 16 |
                            ((uint32_t)cipher_suites[i + 1]) << 8 |
                            ((uint32_t)cipher_suites[i]);
    supported_cipher_suites_.insert(cipher_suite);
  }
}

void WiFi::HandleNetlinkBroadcast(const NetlinkMessage& netlink_message) {
  // We only handle nl80211 commands.
  if (netlink_message.message_type() != Nl80211Message::GetMessageType()) {
    SLOG(this, 7) << __func__ << ": "
                  << "Not a NL80211 Message";
    return;
  }
  const Nl80211Message& nl80211_msg =
      *reinterpret_cast<const Nl80211Message*>(&netlink_message);

  // Pass nl80211 message to appropriate handler function.
  if (nl80211_msg.command() == TriggerScanMessage::kCommand) {
    OnScanStarted(nl80211_msg);
  } else if (nl80211_msg.command() == WiphyRegChangeMessage::kCommand ||
             nl80211_msg.command() == RegChangeMessage::kCommand) {
    OnRegChange(nl80211_msg);
  } else if (nl80211_msg.command() == NotifyCqmMessage::kCommand) {
    if (wifi_cqm_) {
      wifi_cqm_->OnCQMNotify(nl80211_msg);
    }
  }
}

void WiFi::OnScanStarted(const Nl80211Message& scan_trigger_msg) {
  if (scan_trigger_msg.command() != TriggerScanMessage::kCommand) {
    SLOG(this, 7) << __func__ << ": "
                  << "Not a NL80211_CMD_TRIGGER_SCAN message";
    return;
  }
  uint32_t phy_index;
  if (!scan_trigger_msg.const_attributes()->GetU32AttributeValue(
          NL80211_ATTR_WIPHY, &phy_index)) {
    LOG(ERROR) << "NL80211_CMD_TRIGGER_SCAN had no NL80211_ATTR_WIPHY";
    return;
  }
  if (phy_index != phy_index_) {
    SLOG(this, 7) << __func__ << ": "
                  << "Scan trigger not meant for this interface";
    return;
  }
  bool is_active_scan = false;
  AttributeListConstRefPtr ssids;
  if (scan_trigger_msg.const_attributes()->ConstGetNestedAttributeList(
          NL80211_ATTR_SCAN_SSIDS, &ssids)) {
    AttributeIdIterator ssid_iter(*ssids);
    // If any SSIDs (even the empty wild card) are reported, an active scan was
    // launched. Otherwise, a passive scan was launched.
    is_active_scan = !ssid_iter.AtEnd();
  }
  if (wake_on_wifi_) {
    wake_on_wifi_->OnScanStarted(is_active_scan);
  }
}

void WiFi::OnGetReg(const Nl80211Message& nl80211_message) {
  SLOG(2) << __func__;
  if (nl80211_message.command() != GetRegMessage::kCommand) {
    LOG(ERROR) << __func__
               << ": unexpected command: " << nl80211_message.command_string();
    return;
  }

  uint8_t region;
  if (!nl80211_message.const_attributes()->GetU8AttributeValue(
          NL80211_ATTR_DFS_REGION, &region)) {
    SLOG(this, 1) << "Regulatory message has no DFS region, using: "
                  << NL80211_DFS_UNSET;
    region = NL80211_DFS_UNSET;
  } else {
    SLOG(this, 1) << "DFS region: " << region;
  }

  manager()->power_manager()->ChangeRegDomain(
      static_cast<nl80211_dfs_regions>(region));
}

void WiFi::OnRegChange(const Nl80211Message& nl80211_message) {
  if (nl80211_message.command() != WiphyRegChangeMessage::kCommand &&
      nl80211_message.command() != RegChangeMessage::kCommand) {
    LOG(ERROR) << __func__
               << ": unexpected command: " << nl80211_message.command_string();
    return;
  }

  uint32_t initiator;
  if (!nl80211_message.const_attributes()->GetU32AttributeValue(
          NL80211_ATTR_REG_INITIATOR, &initiator)) {
    LOG(ERROR) << "No NL80211_ATTR_REG_INITIATOR in command "
               << nl80211_message.command_string();
    return;
  }

  uint8_t reg_type;
  if (!nl80211_message.const_attributes()->GetU8AttributeValue(
          NL80211_ATTR_REG_TYPE, &reg_type)) {
    LOG(ERROR) << "Regulatory change message had no NL80211_ATTR_REG_TYPE";
    return;
  }

  std::string country_code;
  switch (reg_type) {
    case NL80211_REGDOM_TYPE_WORLD:
      country_code = kWorldRegDomain;
      break;
    case NL80211_REGDOM_TYPE_CUSTOM_WORLD:
      country_code = kCustomWorldRegDomain;
      break;
    case NL80211_REGDOM_TYPE_INTERSECTION:
      country_code = kIntersectionRegDomain;
      break;
    case NL80211_REGDOM_TYPE_COUNTRY:
      if (!nl80211_message.const_attributes()->GetStringAttributeValue(
              NL80211_ATTR_REG_ALPHA2, &country_code)) {
        LOG(ERROR)
            << "Regulatory change message had no NL80211_ATTR_REG_ALPHA2";
        return;
      }
      break;
    default:
      LOG(ERROR) << "Invalid value of REG_TYPE attribute: " << reg_type;
      return;
  }

  provider_->RegionChanged(country_code);

  // Ignore regulatory domain CHANGE events initiated by user.
  if (initiator == NL80211_REGDOM_SET_BY_USER) {
    SLOG(2) << "Ignoring regulatory domain change initiated by user.";
    return;
  }

  HandleCountryChange(country_code);

  // CHANGE events don't have all the useful attributes (e.g.,
  // NL80211_ATTR_DFS_REGION); request the full info now.
  GetRegulatory();
}

void WiFi::HandleCountryChange(const std::string& country_code) {
  // Variable to keep track of current regulatory domain to reduce noise in
  // reported "change" events.
  static int current_reg_dom_val = -1;

  // Get Regulatory Domain value from received country code.
  int reg_dom_val = Metrics::GetRegulatoryDomainValue(country_code);
  if (reg_dom_val == Metrics::RegulatoryDomain::kCountryCodeInvalid) {
    LOG(WARNING) << "Unsupported NL80211_ATTR_REG_ALPHA2 attribute: "
                 << country_code;
  } else {
    SLOG(2) << base::StringPrintf(
        "Regulatory domain change message with alpha2 %s (metric val: %d)",
        country_code.c_str(), reg_dom_val);
  }

  // Only send to UMA when regulatory domain changes to reduce noise in metrics.
  if (reg_dom_val != current_reg_dom_val) {
    current_reg_dom_val = reg_dom_val;
    metrics()->SendEnumToUMA(Metrics::kMetricRegulatoryDomain, reg_dom_val,
                             Metrics::RegulatoryDomain::kRegDomMaxValue);
  }
}

void WiFi::BSSAddedTask(const RpcIdentifier& path,
                        const KeyValueStore& properties) {
  // Note: we assume that BSSIDs are unique across endpoints. This
  // means that if an AP reuses the same BSSID for multiple SSIDs, we
  // lose.
  WiFiEndpointRefPtr endpoint(
      new WiFiEndpoint(control_interface(), this, path, properties, metrics()));
  SLOG(this, 5) << "Found endpoint. "
                << "RPC path: " << path.value() << ", "
                << LogSSID(endpoint->ssid_string()) << ", "
                << "bssid: " << endpoint->bssid_string() << ", "
                << "signal: " << endpoint->signal_strength() << ", "
                << "security: " << endpoint->security_mode() << ", "
                << "frequency: " << endpoint->frequency();

  if (endpoint->ssid_string().empty()) {
    // Don't bother trying to find or create a Service for an Endpoint
    // without an SSID. We wouldn't be able to connect to it anyway.
    return;
  }

  if (endpoint->ssid()[0] == 0) {
    // Assume that an SSID starting with nullptr is bogus/misconfigured,
    // and filter it out.
    return;
  }

  if (endpoint->network_mode().empty()) {
    // Unsupported modes (e.g., ad-hoc) should be ignored.
    return;
  }

  bool service_has_matched = provider_->OnEndpointAdded(endpoint);
  // Adding a single endpoint can change the bgscan parameters for no more than
  // one active Service. Try pending_service_ only if current_service_ doesn't
  // change.
  if ((!current_service_ || !ReconfigureBgscan(current_service_.get())) &&
      pending_service_) {
    ReconfigureBgscan(pending_service_.get());
  }

  // Do this last, to maintain the invariant that any Endpoint we
  // know about has a corresponding Service.
  //
  // TODO(quiche): Write test to verify correct behavior in the case
  // where we get multiple BSSAdded events for a single endpoint.
  // (Old Endpoint's refcount should fall to zero, and old Endpoint
  // should be destroyed.)
  endpoint_by_rpcid_[path] = endpoint;
  endpoint->Start();

  // Keep track of Passpoint compatible endpoints to trigger an interworking
  // selection later if needed.
  if (endpoint->hs20_information().supported) {
    hs20_bss_count_++;
  }
  need_interworking_select_ =
      need_interworking_select_ ||
      (!service_has_matched && endpoint->hs20_information().supported);
}

void WiFi::BSSRemovedTask(const RpcIdentifier& path) {
  EndpointMap::iterator i = endpoint_by_rpcid_.find(path);
  if (i == endpoint_by_rpcid_.end()) {
    SLOG(this, 1) << "WiFi " << link_name() << " could not find BSS "
                  << path.value() << " to remove.";
    return;
  }

  WiFiEndpointRefPtr endpoint = i->second;
  CHECK(endpoint);
  endpoint_by_rpcid_.erase(i);

  if (endpoint->hs20_information().supported) {
    CHECK_NE(hs20_bss_count_, 0u);
    hs20_bss_count_--;
  }

  WiFiServiceRefPtr service = provider_->OnEndpointRemoved(endpoint);
  if (!service) {
    // Removing a single endpoint can change the bgscan parameters for no more
    // than one active Service. Try pending_service_ only if current_service_
    // doesn't change.
    if ((!current_service_ || !ReconfigureBgscan(current_service_.get())) &&
        pending_service_) {
      ReconfigureBgscan(pending_service_.get());
    }
    return;
  }
  Error unused_error;
  RemoveNetworkForService(service.get(), &unused_error);

  bool disconnect_service = !service->HasBSSIDConnectableEndpoints() &&
                            (service->IsConnecting() || service->IsConnected());

  if (disconnect_service) {
    LOG(INFO) << "Disconnecting from: " << service->log_name()
              << ": BSSRemoved";
    DisconnectFrom(service.get());
  }
}

void WiFi::CertificationTask(const KeyValueStore& properties) {
  // Events may come immediately after Stop().
  if (!enabled()) {
    return;
  }

  if (!current_service_) {
    LOG(ERROR) << "WiFi " << link_name() << " " << __func__
               << " with no current service.";
    return;
  }

  std::string subject;
  uint32_t depth;
  if (WPASupplicant::ExtractRemoteCertification(properties, &subject, &depth)) {
    current_service_->AddEAPCertification(subject, depth);
  }
}

void WiFi::EAPEventTask(const std::string& status,
                        const std::string& parameter) {
  // Events may come immediately after Stop().
  if (!enabled()) {
    return;
  }

  if (!current_service_) {
    LOG(ERROR) << "WiFi " << link_name() << " " << __func__
               << " with no current service.";
    return;
  }
  Service::ConnectFailure failure = Service::kFailureNone;
  eap_state_handler_->ParseStatus(status, parameter, &failure);
  if (failure == Service::kFailurePinMissing) {
    // wpa_supplicant can sometimes forget the PIN on disconnect from the AP.
    const std::string& pin = current_service_->eap()->pin();
    Error unused_error;
    RpcIdentifier rpcid =
        FindNetworkRpcidForService(current_service_.get(), &unused_error);
    if (!pin.empty() && !rpcid.value().empty()) {
      // We have a PIN configured, so we can provide it back to wpa_supplicant.
      LOG(INFO) << "Re-supplying PIN parameter to wpa_supplicant.";
      supplicant_interface_proxy_->NetworkReply(
          rpcid, WPASupplicant::kEAPRequestedParameterPin, pin);
      failure = Service::kFailureNone;
    }
  }
  if (failure != Service::kFailureNone) {
    // Avoid a reporting failure twice by resetting EAP state handler early.
    eap_state_handler_->Reset();
    pending_eap_failure_ = failure;
  }
}

void WiFi::PropertiesChangedTask(const KeyValueStore& properties) {
  // TODO(quiche): Handle changes in other properties (e.g. signal
  // strength).

  // Note that order matters here. In particular, we want to process
  // changes in the current BSS before changes in state. This is so
  // that we update the state of the correct Endpoint/Service.
  // Also note that events may occur (briefly) after Stop(), so we need to make
  // explicit decisions here on what to do when !enabled().
  if (enabled() && properties.Contains<RpcIdentifier>(
                       WPASupplicant::kInterfacePropertyCurrentBSS)) {
    CurrentBSSChanged(properties.Get<RpcIdentifier>(
        WPASupplicant::kInterfacePropertyCurrentBSS));
  }

  if (properties.Contains<std::string>(
          WPASupplicant::kInterfacePropertyState)) {
    StateChanged(
        properties.Get<std::string>(WPASupplicant::kInterfacePropertyState));

    // These properties should only be updated when there is a state change.
    if (properties.Contains<std::string>(
            WPASupplicant::kInterfacePropertyCurrentAuthMode)) {
      CurrentAuthModeChanged(properties.Get<std::string>(
          WPASupplicant::kInterfacePropertyCurrentAuthMode));
    }

    std::string suffix = GetSuffixFromAuthMode(supplicant_auth_mode_);
    if (!suffix.empty()) {
      if (properties.Contains<int32_t>(
              WPASupplicant::kInterfacePropertyRoamTime)) {
        // Network.Shill.WiFi.RoamTime.{PSK,FTPSK,EAP,FTEAP}
        metrics()->SendToUMA(
            base::StringPrintf("%s.%s", Metrics::kMetricWifiRoamTimePrefix,
                               suffix.c_str()),
            properties.Get<int32_t>(WPASupplicant::kInterfacePropertyRoamTime),
            Metrics::kMetricWifiRoamTimeMillisecondsMin,
            Metrics::kMetricWifiRoamTimeMillisecondsMax,
            Metrics::kMetricWifiRoamTimeNumBuckets);
      }

      if (properties.Contains<bool>(
              WPASupplicant::kInterfacePropertyRoamComplete)) {
        // Network.Shill.WiFi.RoamComplete.{PSK,FTPSK,EAP,FTEAP}
        metrics()->SendEnumToUMA(
            base::StringPrintf("%s.%s", Metrics::kMetricWifiRoamCompletePrefix,
                               suffix.c_str()),
            properties.Get<bool>(WPASupplicant::kInterfacePropertyRoamComplete)
                ? Metrics::kWiFiRoamSuccess
                : Metrics::kWiFiRoamFailure,
            Metrics::kWiFiRoamCompleteMax);
      }

      if (properties.Contains<int32_t>(
              WPASupplicant::kInterfacePropertySessionLength)) {
        // Network.Shill.WiFi.SessionLength.{PSK,FTPSK,EAP,FTEAP}
        metrics()->SendToUMA(
            base::StringPrintf("%s.%s", Metrics::kMetricWifiSessionLengthPrefix,
                               suffix.c_str()),
            properties.Get<int32_t>(
                WPASupplicant::kInterfacePropertySessionLength),
            Metrics::kMetricWifiSessionLengthMillisecondsMin,
            Metrics::kMetricWifiSessionLengthMillisecondsMax,
            Metrics::kMetricWifiSessionLengthNumBuckets);
      }
    }
  }

  if (properties.Contains<int32_t>(
          WPASupplicant::kInterfacePropertyAssocStatusCode)) {
    AssocStatusChanged(properties.Get<int32_t>(
        WPASupplicant::kInterfacePropertyAssocStatusCode));
  }

  if (properties.Contains<int32_t>(
          WPASupplicant::kInterfacePropertyAuthStatusCode)) {
    AuthStatusChanged(properties.Get<int32_t>(
        WPASupplicant::kInterfacePropertyAuthStatusCode));
  }

  if (properties.Contains<int32_t>(
          WPASupplicant::kInterfacePropertyDisconnectReason)) {
    DisconnectReasonChanged(properties.Get<int32_t>(
        WPASupplicant::kInterfacePropertyDisconnectReason));
  }

  // Handle signal quality change information (from a CQM event).
  if (properties.Contains<KeyValueStore>(
          WPASupplicant::kSignalChangeProperty)) {
    SignalChanged(
        properties.Get<KeyValueStore>(WPASupplicant::kSignalChangeProperty));
  }
}

void WiFi::PskMismatchTask() {
  WiFiService* affected_service =
      current_service_.get() ? current_service_.get() : pending_service_.get();
  if (!affected_service) {
    SLOG(this, 2) << "WiFi " << link_name() << " " << __func__
                  << " with no service";
    return;
  }
  affected_service->AddSuspectedCredentialFailure();
}

void WiFi::SignalChanged(const KeyValueStore& properties) {
  station_stats_ = WiFiLinkStatistics::StationStatsFromSupplicantKV(properties);

  HandleUpdatedLinkStatistics();
}

std::string WiFi::GetSuffixFromAuthMode(const std::string& auth_mode) const {
  if (auth_mode == WPASupplicant::kAuthModeWPAPSK ||
      auth_mode == WPASupplicant::kAuthModeWPA2PSK ||
      auth_mode == WPASupplicant::kAuthModeBothPSK) {
    return Metrics::kMetricWifiPSKSuffix;
  } else if (auth_mode == WPASupplicant::kAuthModeFTPSK) {
    return Metrics::kMetricWifiFTPSKSuffix;
  } else if (auth_mode == WPASupplicant::kAuthModeFTEAP) {
    return Metrics::kMetricWifiFTEAPSuffix;
  } else if (base::StartsWith(auth_mode, WPASupplicant::kAuthModeEAPPrefix,
                              base::CompareCase::SENSITIVE)) {
    return Metrics::kMetricWifiEAPSuffix;
  }
  return "";
}

void WiFi::ScanDoneTask() {
  SLOG(this, 2) << __func__ << " need_bss_flush_ " << need_bss_flush_;
  // Unsets this flag if it was set in InitiateScanInDarkResume since that scan
  // has completed.
  manager()->set_suppress_autoconnect(false);
  if (wake_on_wifi_) {
    wake_on_wifi_->OnScanCompleted();
  }
  // Post |UpdateScanStateAfterScanDone| so it runs after any pending scan
  // results have been processed.  This allows connections on new BSSes to be
  // started before we decide whether the scan was fruitful.
  dispatcher()->PostTask(
      FROM_HERE, base::BindOnce(&WiFi::UpdateScanStateAfterScanDone,
                                weak_ptr_factory_while_started_.GetWeakPtr()));
  if (wake_on_wifi_ && (provider_->NumAutoConnectableServices() < 1) &&
      IsIdle()) {
    // Ensure we are also idle in case we are in the midst of connecting to
    // the only service that was available for auto-connect on the previous
    // scan (which will cause it to show up as unavailable for auto-connect
    // when we query the WiFiProvider this time).
    wake_on_wifi_->OnNoAutoConnectableServicesAfterScan(
        provider_->GetSsidsConfiguredForAutoConnect(),
        base::BindOnce(&WiFi::RemoveSupplicantNetworks,
                       weak_ptr_factory_while_started_.GetWeakPtr()),
        base::BindOnce(&WiFi::TriggerPassiveScan,
                       weak_ptr_factory_while_started_.GetWeakPtr()));
  }
  if (need_bss_flush_) {
    CHECK(supplicant_interface_proxy_);
    // Compute |max_age| relative to |resumed_at_|, to account for the
    // time taken to scan.
    struct timeval now;
    uint32_t max_age;
    time_->GetTimeMonotonic(&now);
    max_age = kMaxBSSResumeAgeSeconds + (now.tv_sec - resumed_at_.tv_sec);
    supplicant_interface_proxy_->FlushBSS(max_age);
    need_bss_flush_ = false;
  }
  StartScanTimer();

  if (interworking_select_enabled_ && need_interworking_select_ &&
      hs20_bss_count_ != 0 && provider_->has_passpoint_credentials()) {
    LOG(INFO) << __func__ << " start interworking selection";
    // Interworking match is started only if a compatible access point is
    // around and there's credentials to match because such selection
    // takes time.
    supplicant_interface_proxy_->InterworkingSelect();
    last_interworking_select_timestamp_ = base::Time::Now();
  }
  need_interworking_select_ = false;
}

void WiFi::ScanFailedTask() {
  SLOG(this, 2) << __func__;
  SetPhyState(WiFiState::PhyState::kIdle, WiFiState::ScanMethod::kNone,
              __func__);
}

void WiFi::UpdateScanStateAfterScanDone() {
  manager()->OnDeviceGeolocationInfoUpdated(this);
  if (wifi_state_->GetPhyState() == WiFiState::PhyState::kBackgroundScanning) {
    // Going directly to kScanIdle (instead of to kScanFoundNothing) inhibits
    // some UMA reporting in SetPhyState.  That's desired -- we don't want
    // to report background scan results to UMA since the drivers may play
    // background scans over a longer period in order to not interfere with
    // traffic.
    SetPhyState(WiFiState::PhyState::kIdle, WiFiState::ScanMethod::kNone,
                __func__);
  } else if (wifi_state_->GetPhyState() != WiFiState::PhyState::kIdle &&
             IsIdle()) {
    SetPhyState(WiFiState::PhyState::kFoundNothing,
                wifi_state_->GetScanMethod(), __func__);
  }
}

void WiFi::GetAndUseInterfaceCapabilities() {
  KeyValueStore caps;

  if (!supplicant_interface_proxy_->GetCapabilities(&caps))
    LOG(ERROR) << "Failed to obtain interface capabilities";

  ConfigureScanSSIDLimit(caps);
}

void WiFi::ConfigureScanSSIDLimit(const KeyValueStore& caps) {
  if (caps.Contains<int>(WPASupplicant::kInterfaceCapabilityMaxScanSSID)) {
    int value = caps.Get<int>(WPASupplicant::kInterfaceCapabilityMaxScanSSID);
    SLOG(this, 2) << "Obtained MaxScanSSID capability: " << value;
    max_ssids_per_scan_ =
        std::min(static_cast<int>(WPASupplicant::kMaxMaxSSIDsPerScan),
                 std::max(0, value));
    if (max_ssids_per_scan_ != value)
      SLOG(this, 2) << "MaxScanSSID trimmed to: " << max_ssids_per_scan_;
  } else {
    LOG(WARNING) << "Missing MaxScanSSID capability, using default value: "
                 << WPASupplicant::kDefaultMaxSSIDsPerScan;
    max_ssids_per_scan_ = WPASupplicant::kDefaultMaxSSIDsPerScan;
  }

  if (max_ssids_per_scan_ <= 1)
    LOG(WARNING) << "MaxScanSSID <= 1, scans will alternate between single "
                 << "hidden SSID and broadcast scan.";
}

void WiFi::ScanTask() {
  SLOG(this, 2) << "WiFi " << link_name() << " scan requested.";
  if (!enabled()) {
    SLOG(this, 2) << "Ignoring scan request while device is not enabled.";
    SetPhyState(WiFiState::PhyState::kIdle, WiFiState::ScanMethod::kNone,
                __func__);  // Probably redundant.
    return;
  }
  if (!supplicant_present_ || !supplicant_interface_proxy_.get()) {
    SLOG(this, 2) << "Ignoring scan request while supplicant is not present.";
    SetPhyState(WiFiState::PhyState::kIdle, WiFiState::ScanMethod::kNone,
                __func__);
    return;
  }
  if ((pending_service_.get() && pending_service_->IsConnecting()) ||
      (current_service_.get() && current_service_->IsConnecting())) {
    SLOG(this, 2) << "Ignoring scan request while connecting to an AP.";
    return;
  }
  KeyValueStore scan_args;
  scan_args.Set<std::string>(WPASupplicant::kPropertyScanType,
                             WPASupplicant::kScanTypeActive);

  ByteArrays hidden_ssids = provider_->GetHiddenSSIDList();
  if (!hidden_ssids.empty()) {
    // Determine how many hidden ssids to pass in, based on max_ssids_per_scan_
    if (max_ssids_per_scan_ > 1) {
      // The empty '' "broadcast SSID" counts toward the max scan limit, so the
      // capability needs to be >= 2 to have at least 1 hidden SSID.
      if (hidden_ssids.size() >= static_cast<size_t>(max_ssids_per_scan_)) {
        // TODO(b/172220260): Devise a better method for time-sharing with SSIDs
        // that do not fit in
        hidden_ssids.erase(hidden_ssids.begin() + max_ssids_per_scan_ - 1,
                           hidden_ssids.end());
      }
      // Add Broadcast SSID, signified by an empty ByteArray.  If we specify
      // SSIDs to wpa_supplicant, we need to explicitly specify the default
      // behavior of doing a broadcast probe.
      hidden_ssids.push_back(ByteArray());

    } else if (max_ssids_per_scan_ == 1) {
      // Handle case where driver can only accept one scan_ssid at a time
      AlternateSingleScans(&hidden_ssids);
    } else {  // if max_ssids_per_scan_ < 1
      hidden_ssids.resize(0);
    }

    if (!hidden_ssids.empty()) {
      scan_args.Set<ByteArrays>(WPASupplicant::kPropertyScanSSIDs,
                                hidden_ssids);
    }
  }
  scan_args.Set<bool>(WPASupplicant::kPropertyScanAllowRoam,
                      manager()->scan_allow_roam());

  if (!supplicant_interface_proxy_->Scan(scan_args)) {
    // A scan may fail if, for example, the wpa_supplicant vanishing
    // notification is posted after this task has already started running.
    LOG(WARNING) << "Scan failed";
    return;
  }

  // Only set the scan state/method if we are starting a full scan from
  // scratch.
  if (wifi_state_->GetPhyState() != WiFiState::PhyState::kScanning) {
    SetPhyState(IsIdle() ? WiFiState::PhyState::kScanning
                         : WiFiState::PhyState::kBackgroundScanning,
                WiFiState::ScanMethod::kFull, __func__);
  }
}

void WiFi::AlternateSingleScans(ByteArrays* hidden_ssids) {
  // Ensure at least one hidden SSID is probed.
  if (broadcast_probe_was_skipped_) {
    SLOG(this, 2) << "Doing broadcast probe instead of directed probe.";
    hidden_ssids->resize(0);
  } else {
    SLOG(this, 2) << "Doing directed probe instead of broadcast probe.";
    hidden_ssids->resize(1);
  }
  broadcast_probe_was_skipped_ = !broadcast_probe_was_skipped_;
}

std::string WiFi::GetServiceLeaseName(const WiFiService& service) {
  return service.GetStorageIdentifier();
}

const WiFiEndpointConstRefPtr WiFi::GetCurrentEndpoint() const {
  EndpointMap::const_iterator endpoint_it =
      endpoint_by_rpcid_.find(supplicant_bss_);
  if (endpoint_it == endpoint_by_rpcid_.end()) {
    return nullptr;
  }

  return endpoint_it->second.get();
}

void WiFi::DestroyServiceLease(const WiFiService& service) {
  GetPrimaryNetwork()->DestroyDHCPLease(GetServiceLeaseName(service));
}

void WiFi::StateChanged(const std::string& new_state) {
  const std::string old_state = supplicant_state_;
  supplicant_state_ = new_state;
  LOG(INFO) << "WiFi " << link_name() << " " << __func__ << " " << old_state
            << " -> " << new_state;

  if (old_state == WPASupplicant::kInterfaceStateDisconnected &&
      new_state != WPASupplicant::kInterfaceStateDisconnected) {
    // The state has been changed from disconnect to something else, clearing
    // out disconnect reason to avoid confusion about future disconnects.
    SLOG(this, 2) << "WiFi clearing DisconnectReason for " << link_name();
    supplicant_disconnect_reason_ = IEEE_80211::kReasonCodeInvalid;
  }

  // Identify the service to which the state change applies. If
  // |pending_service_| is non-NULL, then the state change applies to
  // |pending_service_|. Otherwise, it applies to |current_service_|.
  //
  // This policy is driven by the fact that the |pending_service_|
  // doesn't become the |current_service_| until wpa_supplicant
  // reports a CurrentBSS change to the |pending_service_|. And the
  // CurrentBSS change won't be reported until the |pending_service_|
  // reaches the WPASupplicant::kInterfaceStateCompleted state.
  WiFiService* affected_service =
      pending_service_.get() ? pending_service_.get() : current_service_.get();
  if (!affected_service) {
    SLOG(this, 2) << "WiFi " << link_name() << " " << __func__
                  << " with no service";
    return;
  }

  if (new_state == WPASupplicant::kInterfaceStateCompleted) {
    if (old_state != WPASupplicant::kInterfaceStateCompleted &&
        !IsStateTransitionConnectionMaintenance(*affected_service)) {
      // Do not report connection attempts when the transition to
      // |kInterfaceStateCompleted| was caused by a "maintenance" event
      // (e.g. rekeying) from a fully connected state rather than a genuine
      // attempt to connect from a "disconnected" state.
      // When rekeying happens shill does not always get notified for every
      // state transition, it sometimes only gets 1 state transition that
      // appears to be between |kInterfaceStateCompleted| and
      // |kInterfaceStateCompleted|. We handle that case as a rekeying event.
      affected_service->EmitConnectionAttemptResultEvent(Service::kFailureNone);
    }
    if (affected_service->IsConnected()) {
      StopReconnectTimer();
      if (is_roaming_in_progress_) {
        // This means wpa_supplicant completed a roam without an intervening
        // disconnect. We should renew our DHCP lease just in case the new
        // AP is on a different subnet than where we started.
        // TODO(matthewmwang): Handle the IPv6 roam case.
        is_roaming_in_progress_ = false;
        if (GetPrimaryNetwork()->TimeToNextDHCPLeaseRenewal() != std::nullopt) {
          LOG(INFO) << link_name() << " renewing L3 configuration after roam.";
          RetrieveLinkStatistics(WiFiLinkStatistics::Trigger::kDHCPRenewOnRoam);
          GetPrimaryNetwork()->RenewDHCPLease();
          affected_service->SetRoamState(Service::kRoamStateConfiguring);
        }
      } else if (affected_service->is_rekey_in_progress()) {
        affected_service->SetIsRekeyInProgress(false);
        LOG(INFO) << link_name()
                  << " EAP re-key complete. No need to renew L3 configuration.";
      }
    } else if (has_already_completed_) {
      LOG(INFO) << link_name() << " L3 configuration already started.";
    } else {
      auto dhcp_opts = manager()->CreateDefaultDHCPOption();
      dhcp_opts.lease_name = GetServiceLeaseName(*affected_service);
      Network::StartOptions opts = {
          .dhcp = dhcp_opts,
          .accept_ra = true,
          .ignore_link_monitoring = affected_service->link_monitor_disabled(),
          .probing_configuration =
              manager()->GetPortalDetectorProbingConfiguration(),
      };
      GetPrimaryNetwork()->Start(opts);
      LOG(INFO) << link_name() << " is up; started L3 configuration.";
      RetrieveLinkStatistics(
          WiFiLinkStatistics::Trigger::kIPConfigurationStart);
      affected_service->SetState(Service::kStateConfiguring);
      if (affected_service->IsSecurityMatch(kSecurityWep)) {
        // With the overwhelming majority of WEP networks, we cannot assume
        // our credentials are correct just because we have successfully
        // connected.  It is more useful to track received data as the L3
        // configuration proceeds to see if we can decrypt anything.
        receive_byte_count_at_connect_ = GetReceiveByteCount();
      } else {
        affected_service->ResetSuspectedCredentialFailures();
      }
    }
    has_already_completed_ = true;
  } else if (IsWPAStateConnectionInProgress(new_state)) {
    if (new_state == WPASupplicant::kInterfaceStateAssociating) {
      // Ensure auth status is kept up-to-date
      supplicant_auth_status_ = IEEE_80211::kStatusCodeSuccessful;
    } else if (new_state == WPASupplicant::kInterfaceStateAssociated) {
      // Supplicant does not indicate successful association in assoc status
      // messages, but we know at this point that 802.11 association succeeded
      supplicant_assoc_status_ = IEEE_80211::kStatusCodeSuccessful;
    }

    if (is_roaming_in_progress_) {
      // Instead of transitioning into the associating state and potentially
      // reordering the service list, set the roam state to keep track of the
      // actual state.
      affected_service->SetRoamState(Service::kRoamStateAssociating);
    } else if (!affected_service->is_rekey_in_progress()) {
      // Ignore transitions into these states when roaming is in progress, to
      // avoid bothering the user when roaming, or re-keying.
      if (old_state == WPASupplicant::kInterfaceStateCompleted) {
        // Shill gets EAP events when a re-key happens in an 802.1X network, but
        // nothing when it happens in a PSK network. Unless roaming is in
        // progress, we assume supplicant state transitions from completed to an
        // auth/assoc state are a result of a re-key.
        affected_service->SetIsRekeyInProgress(true);
        metrics()->NotifyRekeyStart();
      } else {
        affected_service->SetState(Service::kStateAssociating);
      }
    }
    // TODO(quiche): On backwards transitions, we should probably set
    // a timeout for getting back into the completed state. At present,
    // we depend on wpa_supplicant eventually reporting that CurrentBSS
    // has changed. But there may be cases where that signal is not sent.
    // (crbug.com/206208)
  } else if (new_state == WPASupplicant::kInterfaceStateDisconnected &&
             affected_service == current_service_ &&
             affected_service->IsConnected()) {
    // This means that wpa_supplicant failed in a re-connect attempt, but
    // may still be reconnecting.  Give wpa_supplicant a limited amount of
    // time to transition out this condition by either connecting or changing
    // CurrentBSS.
    StartReconnectTimer();
  } else {
    // Other transitions do not affect Service state.
    //
    // Note in particular that we ignore a State change into
    // kInterfaceStateDisconnected, in favor of observing the corresponding
    // change in CurrentBSS.
  }
}

bool WiFi::SuspectCredentials(WiFiServiceRefPtr service,
                              Service::ConnectFailure* failure) const {
  if (service->IsSecurityMatch(kSecurityClassPsk)) {
    if (supplicant_state_ == WPASupplicant::kInterfaceState4WayHandshake &&
        service->CheckSuspectedCredentialFailure()) {
      if (failure) {
        *failure = Service::kFailureBadPassphrase;
        metrics()->NotifyWiFiBadPassphrase(service->has_ever_connected(),
                                           service->is_in_user_connect());
      }
      return true;
    }
  } else if (service->IsSecurityMatch(kSecurityClass8021x)) {
    if (eap_state_handler_->is_eap_in_progress() &&
        service->AddAndCheckSuspectedCredentialFailure()) {
      if (failure) {
        *failure = Service::kFailureEAPAuthentication;
      }
      return true;
    }
  }

  return false;
}

// static
bool WiFi::SanitizeSSID(std::string* ssid) {
  CHECK(ssid);

  size_t ssid_len = ssid->length();
  size_t i;
  bool changed = false;

  for (i = 0; i < ssid_len; ++i) {
    if (!IsPrintableAsciiChar((*ssid)[i])) {
      (*ssid)[i] = '?';
      changed = true;
    }
  }

  return changed;
}

// static
std::string WiFi::LogSSID(const std::string& ssid) {
  std::string out;
  for (const auto& chr : ssid) {
    // Replace '[' and ']' (in addition to non-printable characters) so that
    // it's easy to match the right substring through a non-greedy regex.
    if (chr == '[' || chr == ']' || !IsPrintableAsciiChar(chr)) {
      base::StringAppendF(&out, "\\x%02x", chr);
    } else {
      out += chr;
    }
  }
  return base::StringPrintf("[SSID=%s]", out.c_str());
}

void WiFi::OnUnreliableLink() {
  SLOG(this, 2) << "Device " << link_name() << ": Link is unreliable.";
  selected_service()->set_unreliable(true);
  reliable_link_callback_.Cancel();
  metrics()->SendToUMA(Metrics::kMetricUnreliableLinkSignalStrength,
                       selected_service()->strength());
}

void WiFi::OnReliableLink() {
  SLOG(this, 2) << "Device " << link_name() << ": Link is reliable.";
  selected_service()->set_unreliable(false);
}

void WiFi::OnLinkMonitorFailure(IPAddress::Family family) {
  SLOG(this, 2) << "Device " << link_name()
                << ": Link Monitor indicates failure.";

  // Determine the reliability of the link.
  time_t now;
  time_->GetSecondsBoottime(&now);
  if (last_link_monitor_failed_time_ != 0 &&
      now - last_link_monitor_failed_time_ <
          kLinkUnreliableThreshold.InSeconds()) {
    OnUnreliableLink();
  }
  last_link_monitor_failed_time_ = now;

  // If we have never found the gateway, let's be conservative and not
  // do anything, in case this network topology does not have a gateway.
  if ((family == IPAddress::kFamilyIPv4 &&
       !GetPrimaryNetwork()->ipv4_gateway_found()) ||
      (family == IPAddress::kFamilyIPv6 &&
       !GetPrimaryNetwork()->ipv6_gateway_found())) {
    LOG(INFO) << "In " << __func__ << "(): "
              << "Skipping reassociate since gateway was never found.";
    return;
  }

  if (!supplicant_present_) {
    LOG(ERROR) << "In " << __func__ << "(): "
               << "wpa_supplicant is not present.  Cannot reassociate.";
    return;
  }

  if (!current_service_) {
    LOG(INFO) << "No current service, skipping reassociate attempt.";
    return;
  }

  // Skip reassociate attempt if service is not reliable, meaning multiple link
  // failures in short period of time.
  if (current_service_->unreliable()) {
    LOG(INFO) << "Current service is unreliable, skipping reassociate attempt.";
    metrics()->NotifyWiFiConnectionUnreliable();
    return;
  }

  // This will force a transition out of connected, if we are actually
  // connected.
  if (!supplicant_interface_proxy_->Reattach()) {
    LOG(ERROR) << "In " << __func__ << "(): failed to call Reattach().";
    return;
  }

  // If we don't eventually get a transition back into a connected state,
  // there is something wrong.
  StartReconnectTimer();
  LOG(INFO) << "In " << __func__ << "(): Called Reattach().";
}

void WiFi::DisassociateFromService(const WiFiServiceRefPtr& service) {
  SLOG(this, 2) << "In " << __func__ << " for service: " << service->log_name();
  DisconnectFromIfActive(service.get());
  if (service == selected_service()) {
    DropConnection();
  }
  Error unused_error;
  RemoveNetworkForService(service.get(), &unused_error);
}

void WiFi::UpdateGeolocationObjects(
    std::vector<GeolocationInfo>* geolocation_infos) const {
  int old_size = geolocation_infos->size();
  // Move all the geolocation objects from geolocation_infos to
  // geolocation_infos_copy. After this move, geolocation_infos is empty, and
  // all the geolocation objects are in geolocation_infos_copy
  std::vector<GeolocationInfo> geolocation_infos_copy =
      std::move(*geolocation_infos);
  // Update the geolocation cache using the current WiFi scan results
  for (const auto& endpoint_entry : endpoint_by_rpcid_) {
    GeolocationInfo geoinfo;
    const WiFiEndpointRefPtr& endpoint = endpoint_entry.second;
    geoinfo[kGeoMacAddressProperty] = endpoint->bssid_string();
    geoinfo[kGeoSignalStrengthProperty] =
        base::StringPrintf("%d", endpoint->signal_strength());
    geoinfo[kGeoChannelProperty] = base::StringPrintf(
        "%d", Metrics::WiFiFrequencyToChannel(endpoint->frequency()));
    AddLastSeenTime(&geoinfo, endpoint->last_seen());
    SLOG(4) << "Cached: " << GeolocationInfoToString(geoinfo);
    geolocation_infos->emplace_back(geoinfo);
  }
  int carry_num = 0, evict_num = 0, update_num = 0;
  // If a BSS is not in the latest scan result, we put it back to the
  // geolocation cache if it is not expired yet
  for (auto& geoinfo : geolocation_infos_copy) {
    // Evict a cached endpoint if its age is older than
    // kWiFiGeolocationInfoExpiration
    if (IsGeolocationInfoOlderThan(geoinfo, kWiFiGeolocationInfoExpiration)) {
      evict_num++;
      continue;
    }
    std::vector<GeolocationInfo>::iterator it;
    for (it = geolocation_infos->begin();
         it != geolocation_infos->end() &&
         (*it)[kGeoMacAddressProperty] != geoinfo[kGeoMacAddressProperty];
         it++) {
    }
    if (it == geolocation_infos->end()) {
      SLOG(4) << "Carried over: " << GeolocationInfoToString(geoinfo);
      // The cached endpoint is not in the WiFi scan result and has not expired
      // yet, put it back to the cache
      geolocation_infos->emplace_back(geoinfo);
      carry_num++;
    } else {
      // The cached endpoint has been updated with the WiFi scan result
      update_num++;
    }
  }
  LOG(INFO) << "Geolocation cache input size: " << old_size
            << ", output size: " << geolocation_infos->size()
            << ", carried over: " << carry_num << ", updated: " << update_num
            << ", evicted: " << evict_num;
  base::Time oldest_timestamp, newest_timestamp;
  GeolocationInfoAgeRange(*geolocation_infos, &oldest_timestamp,
                          &newest_timestamp);
  if (!oldest_timestamp.is_inf() && !newest_timestamp.is_inf()) {
    LOG(INFO) << "The oldest endpoint was seen at " << oldest_timestamp
              << ", the newest endpoint was seen at " << newest_timestamp;
  }
}

void WiFi::HelpRegisterDerivedInt32(PropertyStore* store,
                                    base::StringPiece name,
                                    int32_t (WiFi::*get)(Error* error),
                                    bool (WiFi::*set)(const int32_t& value,
                                                      Error* error)) {
  store->RegisterDerivedInt32(
      name, Int32Accessor(new CustomAccessor<WiFi, int32_t>(this, get, set)));
}

void WiFi::HelpRegisterDerivedUint16(PropertyStore* store,
                                     base::StringPiece name,
                                     uint16_t (WiFi::*get)(Error* error),
                                     bool (WiFi::*set)(const uint16_t& value,
                                                       Error* error)) {
  store->RegisterDerivedUint16(
      name, Uint16Accessor(new CustomAccessor<WiFi, uint16_t>(this, get, set)));
}

void WiFi::HelpRegisterDerivedBool(PropertyStore* store,
                                   base::StringPiece name,
                                   bool (WiFi::*get)(Error* error),
                                   bool (WiFi::*set)(const bool& value,
                                                     Error* error)) {
  store->RegisterDerivedBool(
      name, BoolAccessor(new CustomAccessor<WiFi, bool>(this, get, set)));
}

void WiFi::HelpRegisterConstDerivedBool(PropertyStore* store,
                                        base::StringPiece name,
                                        bool (WiFi::*get)(Error* error)) {
  store->RegisterDerivedBool(
      name, BoolAccessor(new CustomAccessor<WiFi, bool>(this, get, nullptr)));
}

void WiFi::HelpRegisterConstDerivedUint16s(PropertyStore* store,
                                           base::StringPiece name,
                                           Uint16s (WiFi::*get)(Error* error)) {
  store->RegisterDerivedUint16s(
      name,
      Uint16sAccessor(new CustomAccessor<WiFi, Uint16s>(this, get, nullptr)));
}

void WiFi::OnBeforeSuspend(ResultCallback callback) {
  if (!enabled()) {
    std::move(callback).Run(Error(Error::kSuccess));
    return;
  }
  LOG(INFO) << __func__ << ": "
            << (IsConnectedToCurrentService() ? "connected" : "not connected");
  StopScanTimer();
  supplicant_process_proxy()->ExpectDisconnect();
  if (!wake_on_wifi_) {
    std::move(callback).Run(Error(Error::kSuccess));
    return;
  }
  wake_on_wifi_->OnBeforeSuspend(
      IsConnectedToCurrentService(),
      provider_->GetSsidsConfiguredForAutoConnect(), std::move(callback),
      base::BindOnce(&Device::ForceIPConfigUpdate,
                     weak_ptr_factory_while_started_.GetWeakPtr()),
      base::BindOnce(&WiFi::RemoveSupplicantNetworks,
                     weak_ptr_factory_while_started_.GetWeakPtr()),
      GetPrimaryNetwork()->TimeToNextDHCPLeaseRenewal());
}

void WiFi::OnDarkResume(ResultCallback callback) {
  if (!enabled()) {
    std::move(callback).Run(Error(Error::kSuccess));
    return;
  }
  LOG(INFO) << __func__ << ": "
            << (IsConnectedToCurrentService() ? "connected" : "not connected");
  StopScanTimer();
  if (!wake_on_wifi_) {
    std::move(callback).Run(Error(Error::kSuccess));
    return;
  }
  wake_on_wifi_->OnDarkResume(
      IsConnectedToCurrentService(),
      provider_->GetSsidsConfiguredForAutoConnect(), std::move(callback),
      base::BindOnce(&Device::ForceIPConfigUpdate,
                     weak_ptr_factory_while_started_.GetWeakPtr()),
      base::BindOnce(&WiFi::InitiateScanInDarkResume,
                     weak_ptr_factory_while_started_.GetWeakPtr()),
      base::BindRepeating(&WiFi::RemoveSupplicantNetworks,
                          weak_ptr_factory_while_started_.GetWeakPtr()));
}

void WiFi::OnAfterResume() {
  LOG(INFO) << __func__ << ": "
            << (IsConnectedToCurrentService() ? "connected" : "not connected")
            << ", " << (enabled() ? "enabled" : "disabled");
  Device::OnAfterResume();  // May refresh ipconfig_
  // We let the Device class do its thing, but we did nothing in
  // OnBeforeSuspend(), so why undo anything now?
  if (!enabled()) {
    return;
  }
  dispatcher()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&WiFi::ReportConnectedToServiceAfterWake,
                     weak_ptr_factory_while_started_.GetWeakPtr()),
      kPostWakeConnectivityReportDelay);
  if (wake_on_wifi_) {
    wake_on_wifi_->OnAfterResume();
  }

  // We want to flush the BSS cache, but we don't want to conflict
  // with an active connection attempt. So record the need to flush,
  // and take care of flushing when the next scan completes.
  //
  // Note that supplicant will automatically expire old cache
  // entries (after, e.g., a BSS is not found in two consecutive
  // scans). However, our explicit flush accelerates re-association
  // in cases where a BSS disappeared while we were asleep. (See,
  // e.g. WiFiRoaming.005SuspendRoam.)
  time_->GetTimeMonotonic(&resumed_at_);
  need_bss_flush_ = true;

  if (!IsConnectedToCurrentService()) {
    InitiateScan();
  }

  // Since we stopped the scan timer before suspending, start it again here.
  StartScanTimer();

  // Resume from sleep, could be in different location now.
  // Ignore previous link monitor failures.
  if (selected_service()) {
    selected_service()->set_unreliable(false);
    reliable_link_callback_.Cancel();
  }
  last_link_monitor_failed_time_ = 0;
}

void WiFi::AbortScan() {
  SetPhyState(WiFiState::PhyState::kIdle, WiFiState::ScanMethod::kNone,
              __func__);
}

void WiFi::InitiateScan() {
  LOG(INFO) << __func__;
  // Abort any current scan (at the shill-level; let any request that's
  // already gone out finish) since we don't know when it started.
  AbortScan();

  if (IsIdle()) {
    // Not scanning/connecting/connected, so let's get things rolling.
    Scan(nullptr, __func__);
    RestartFastScanAttempts();
  } else {
    SLOG(this, 1) << __func__
                  << " skipping scan, already connecting or connected.";
  }
}

void WiFi::InitiateScanInDarkResume(const FreqSet& freqs) {
  LOG(INFO) << __func__;
  AbortScan();
  if (!IsIdle()) {
    SLOG(this, 1) << __func__
                  << " skipping scan, already connecting or connected.";
    return;
  }

  CHECK(supplicant_interface_proxy_);
  // Force complete flush of BSS cache since we want WPA supplicant and shill to
  // have an accurate view of what endpoints are available in dark resume. This
  // prevents either from performing incorrect actions that can prolong dark
  // resume (e.g. attempting to auto-connect to a WiFi service whose endpoint
  // disappeared before the dark resume).
  if (!supplicant_interface_proxy_->FlushBSS(0)) {
    LOG(WARNING) << __func__ << ": Failed to flush wpa_supplicant BSS cache";
  }
  // Suppress any autoconnect attempts until this scan is done and endpoints
  // are updated.
  manager()->set_suppress_autoconnect(true);

  TriggerPassiveScan(freqs);
}

void WiFi::TriggerPassiveScan(const FreqSet& freqs) {
  LOG(INFO) << __func__;
  TriggerScanMessage trigger_scan;
  trigger_scan.attributes()->SetU32AttributeValue(NL80211_ATTR_IFINDEX,
                                                  interface_index());
  if (!freqs.empty()) {
    SLOG(this, 2) << __func__ << ": "
                  << "Scanning on specific channels";
    trigger_scan.attributes()->CreateNl80211Attribute(
        NL80211_ATTR_SCAN_FREQUENCIES, NetlinkMessage::MessageContext());

    AttributeListRefPtr frequency_list;
    if (!trigger_scan.attributes()->GetNestedAttributeList(
            NL80211_ATTR_SCAN_FREQUENCIES, &frequency_list) ||
        !frequency_list) {
      LOG(ERROR) << __func__ << ": "
                 << "Couldn't get NL80211_ATTR_SCAN_FREQUENCIES";
    }
    trigger_scan.attributes()->SetNestedAttributeHasAValue(
        NL80211_ATTR_SCAN_FREQUENCIES);

    std::string attribute_name;
    int i = 0;
    for (uint32_t freq : freqs) {
      SLOG(this, 7) << __func__ << ": "
                    << "Frequency-" << i << ": " << freq;
      attribute_name = base::StringPrintf("Frequency-%d", i);
      frequency_list->CreateU32Attribute(i, attribute_name.c_str());
      frequency_list->SetU32AttributeValue(i, freq);
      ++i;
    }
  }

  netlink_manager_->SendNl80211Message(
      &trigger_scan,
      base::BindRepeating(&WiFi::OnTriggerPassiveScanResponse,
                          weak_ptr_factory_while_started_.GetWeakPtr()),
      base::BindRepeating(&NetlinkManager::OnAckDoNothing),
      base::BindRepeating(&NetlinkManager::OnNetlinkMessageError));
}

void WiFi::OnConnected() {
  Device::OnConnected();
  RetrieveLinkStatistics(WiFiLinkStatistics::Trigger::kConnected);
  if (current_service_ && current_service_->IsSecurityMatch(kSecurityWep)) {
    // With a WEP network, we are now reasonably certain the credentials are
    // correct, whereas with other network types we were able to determine
    // this earlier when the association process succeeded.
    current_service_->ResetSuspectedCredentialFailures();
  }
  RequestStationInfo(WiFiLinkStatistics::Trigger::kBackground);

  if (selected_service()->unreliable()) {
    // Post a delayed task to reset link back to reliable if no link failure is
    // detected in the next 5 minutes.
    reliable_link_callback_.Reset(
        base::BindOnce(&WiFi::OnReliableLink, base::Unretained(this)));
    dispatcher()->PostDelayedTask(FROM_HERE, reliable_link_callback_.callback(),
                                  kLinkUnreliableResetTimeout);
  }
}

void WiFi::OnSelectedServiceChanged(const ServiceRefPtr& old_service) {
  // Reset link status for the previously selected service.
  if (old_service) {
    old_service->set_unreliable(false);
  }
  reliable_link_callback_.Cancel();
  last_link_monitor_failed_time_ = 0;
}

void WiFi::OnIPConfigFailure() {
  if (!current_service_) {
    LOG(ERROR) << "WiFi " << link_name() << " " << __func__
               << " with no current service.";
    return;
  }
  if (current_service_->IsSecurityMatch(kSecurityWep) &&
      GetReceiveByteCount() == receive_byte_count_at_connect_ &&
      current_service_->AddAndCheckSuspectedCredentialFailure()) {
    // If we've connected to a WEP network and haven't successfully
    // decrypted any bytes at all during the configuration process,
    // it is fair to suspect that our credentials to this network
    // may not be correct.
    Error error;
    current_service_->DisconnectWithFailure(Service::kFailureBadPassphrase,
                                            &error, __func__);
    return;
  }

  Device::OnIPConfigFailure();
}

void WiFi::RestartFastScanAttempts() {
  if (!enabled()) {
    SLOG(this, 2) << "Skpping fast scan attempts while not enabled.";
    return;
  }
  fast_scans_remaining_ = kNumFastScanAttempts;
  StartScanTimer();
}

void WiFi::StartScanTimer() {
  SLOG(this, 2) << __func__;
  if (scan_interval_seconds_ == 0) {
    StopScanTimer();
    return;
  }
  scan_timer_callback_.Reset(base::BindOnce(
      &WiFi::ScanTimerHandler, weak_ptr_factory_while_started_.GetWeakPtr()));
  // Repeat the first few scans after disconnect relatively quickly so we
  // have reasonable trust that no APs we are looking for are present.
  base::TimeDelta wait_time = fast_scans_remaining_ > 0
                                  ? kFastScanInterval
                                  : base::Seconds(scan_interval_seconds_);
  dispatcher()->PostDelayedTask(FROM_HERE, scan_timer_callback_.callback(),
                                wait_time);
  SLOG(this, 5) << "Next scan scheduled for " << wait_time.InMilliseconds()
                << "ms";
}

void WiFi::StopScanTimer() {
  SLOG(this, 2) << __func__;
  scan_timer_callback_.Cancel();
}

void WiFi::ScanTimerHandler() {
  SLOG(this, 2) << "WiFi Device " << link_name() << ": " << __func__;
  if (manager()->IsSuspending()) {
    SLOG(this, 5) << "Not scanning: still in suspend";
    return;
  }
  if (wifi_state_->GetPhyState() == WiFiState::PhyState::kIdle && IsIdle()) {
    Scan(nullptr, __func__);
    if (fast_scans_remaining_ > 0) {
      --fast_scans_remaining_;
    }
  } else {
    if (wifi_state_->GetPhyState() != WiFiState::PhyState::kIdle) {
      SLOG(this, 5) << "Skipping scan: phy state is "
                    << wifi_state_->GetPhyStateString()
                    << " ensured scan state is "
                    << wifi_state_->GetEnsuredScanStateString();
    }
    if (current_service_) {
      SLOG(this, 5) << "Skipping scan: current_service_ is service "
                    << current_service_->log_name();
    }
    if (pending_service_) {
      SLOG(this, 5) << "Skipping scan: pending_service_ is service"
                    << pending_service_->log_name();
    }
  }
  StartScanTimer();
}

void WiFi::StartPendingTimer() {
  pending_timeout_callback_.Reset(
      base::BindOnce(&WiFi::PendingTimeoutHandler,
                     weak_ptr_factory_while_started_.GetWeakPtr()));
  dispatcher()->PostDelayedTask(FROM_HERE, pending_timeout_callback_.callback(),
                                kPendingTimeout);
}

void WiFi::StopPendingTimer() {
  SLOG(this, 2) << "WiFi Device " << link_name() << ": " << __func__;
  pending_timeout_callback_.Cancel();
}

void WiFi::SetPendingService(const WiFiServiceRefPtr& service) {
  SLOG(this, 2) << "WiFi " << link_name() << " setting pending service to "
                << (service ? service->log_name() : "<none>");
  if (service) {
    SetPhyState(WiFiState::PhyState::kConnecting, wifi_state_->GetScanMethod(),
                __func__);
    service->SetState(Service::kStateAssociating);
    StartPendingTimer();
  } else {
    // SetPendingService(nullptr) is called in the following cases:
    //  a) |ConnectTo|->|DisconnectFrom|.  Connecting to a service, disconnect
    //     the old service (scan_state_ == kScanTransitionToConnecting).  No
    //     state transition is needed here.
    //  b) |HandleRoam|.  Connected to a service, it's no longer pending
    //     (scan_state_ == kScanIdle).  No state transition is needed here.
    //  c) |DisconnectFrom| and |HandleDisconnect|. Disconnected/disconnecting
    //     from a service not during a scan (scan_state_ == kScanIdle).  No
    //     state transition is needed here.
    //  d) |DisconnectFrom| and |HandleDisconnect|. Disconnected/disconnecting
    //     from a service during a scan (scan_state_ == kScanScanning or
    //     kScanConnecting).  This is an odd case -- let's discard any
    //     statistics we're gathering by transitioning directly into kScanIdle.
    if (wifi_state_->GetPhyState() == WiFiState::PhyState::kScanning ||
        wifi_state_->GetPhyState() ==
            WiFiState::PhyState::kBackgroundScanning ||
        wifi_state_->GetPhyState() == WiFiState::PhyState::kConnecting) {
      SetPhyState(WiFiState::PhyState::kIdle, WiFiState::ScanMethod::kNone,
                  __func__);
    }
    if (pending_service_) {
      StopPendingTimer();
    }
  }
  pending_service_ = service;
}

void WiFi::PendingTimeoutHandler() {
  Error unused_error;
  LOG(INFO) << "WiFi Device " << link_name() << ": " << __func__;
  CHECK(pending_service_);
  SetPhyState(WiFiState::PhyState::kFoundNothing, wifi_state_->GetScanMethod(),
              __func__);

  // These variables are just to check if the failure has been determined and
  // reported via SetFailure() - see below.
  auto service = pending_service_;
  auto service_prev_err = service->previous_error_number();

  // Failure cause is determined later in ServiceDisconnected().
  pending_service_->Disconnect(&unused_error, __func__);

  // A hidden service may have no endpoints, since wpa_supplicant
  // failed to attain a CurrentBSS.  If so, the service has no
  // reference to |this| device and cannot call WiFi::DisconnectFrom()
  // to reset pending_service_.  In this case, we must perform the
  // disconnect here ourselves.
  if (pending_service_) {
    CHECK(!pending_service_->HasEndpoints());
    LOG(INFO) << "Hidden service was not found.";
    DisconnectFrom(pending_service_.get());
  }

  // Check if the SetFailure() has been called.
  if (service_prev_err == service->previous_error_number()) {
    LOG(WARNING) << "Expected SetFailure() to be called, but it wasn't.";
    Service::ConnectFailure failure = ExamineStatusCodes();
    if (failure == Service::kFailureUnknown &&
        SignalOutOfRange(service->SignalLevel())) {
      failure = Service::kFailureOutOfRange;
    }
    service->SetFailure(failure);
    service->SetState(Service::kStateIdle);
  }
}

void WiFi::StartReconnectTimer() {
  if (!reconnect_timeout_callback_.IsCancelled()) {
    LOG(INFO) << "WiFi Device " << link_name() << ": " << __func__
              << ": reconnect timer already running.";
    return;
  }
  LOG(INFO) << "WiFi Device " << link_name() << ": " << __func__;
  reconnect_timeout_callback_.Reset(
      base::BindOnce(&WiFi::ReconnectTimeoutHandler,
                     weak_ptr_factory_while_started_.GetWeakPtr()));
  dispatcher()->PostDelayedTask(
      FROM_HERE, reconnect_timeout_callback_.callback(), kReconnectTimeout);
}

void WiFi::StopReconnectTimer() {
  SLOG(this, 2) << "WiFi Device " << link_name() << ": " << __func__;
  reconnect_timeout_callback_.Cancel();
}

void WiFi::ReconnectTimeoutHandler() {
  LOG(INFO) << "WiFi Device " << link_name() << ": " << __func__;
  reconnect_timeout_callback_.Cancel();
  CHECK(current_service_);
  current_service_->SetFailure(Service::kFailureConnect);
  DisconnectFrom(current_service_.get());
}

void WiFi::OnSupplicantPresence(bool present) {
  LOG(INFO) << "WPA supplicant presence changed: " << present;

  if (present) {
    if (supplicant_present_) {
      // Restart the WiFi device if it's started already. This will reset the
      // state and connect the device to the new WPA supplicant instance.
      if (enabled()) {
        Restart();
      }
      return;
    }
    supplicant_present_ = true;
    if (enabled()) {
      ConnectToSupplicant();
    }
    return;
  }

  if (!supplicant_present_) {
    return;
  }
  supplicant_present_ = false;
  // Restart the WiFi device if it's started already. This will effectively
  // suspend the device until the WPA supplicant reappears.
  if (enabled()) {
    Restart();
  }
}

void WiFi::OnWiFiDebugScopeChanged(bool enabled) {
  LOG(INFO) << "WiFi debug scope changed; enable is now " << enabled;
  if (!supplicant_present_) {
    SLOG(this, 2) << "Supplicant process proxy not connected.";
    return;
  }
  std::string current_level;
  if (!supplicant_process_proxy()->GetDebugLevel(&current_level)) {
    LOG(ERROR) << __func__ << ": Failed to get wpa_supplicant debug level.";
    return;
  }

  if (current_level != WPASupplicant::kDebugLevelInfo &&
      current_level != WPASupplicant::kDebugLevelDebug) {
    SLOG(this, 2) << "WiFi debug level is currently " << current_level
                  << "; assuming that it is being controlled elsewhere.";
    return;
  }
  std::string new_level = enabled ? WPASupplicant::kDebugLevelDebug
                                  : WPASupplicant::kDebugLevelInfo;

  if (new_level == current_level) {
    SLOG(this, 2) << "WiFi debug level is already the desired level "
                  << current_level;
    return;
  }

  if (!supplicant_process_proxy()->SetDebugLevel(new_level)) {
    LOG(ERROR) << __func__ << ": Failed to set wpa_supplicant debug level.";
  }
}

void WiFi::SetConnectionDebugging(bool enabled) {
  if (is_debugging_connection_ == enabled) {
    return;
  }
  OnWiFiDebugScopeChanged(enabled || ScopeLogger::GetInstance()->IsScopeEnabled(
                                         ScopeLogger::kWiFi));
  is_debugging_connection_ = enabled;
}

void WiFi::SetSupplicantInterfaceProxy(
    std::unique_ptr<SupplicantInterfaceProxyInterface> proxy) {
  if (proxy) {
    supplicant_interface_proxy_ = std::move(proxy);
  } else {
    supplicant_interface_proxy_.reset();
  }
}

void WiFi::ConnectToSupplicant() {
  LOG(INFO) << link_name() << ": " << (enabled() ? "enabled" : "disabled")
            << " supplicant: " << (supplicant_present_ ? "present" : "absent")
            << " proxy: "
            << (supplicant_interface_proxy_.get() ? "non-null" : "null");
  if (!supplicant_present_) {
    return;
  }
  OnWiFiDebugScopeChanged(
      ScopeLogger::GetInstance()->IsScopeEnabled(ScopeLogger::kWiFi));

  RpcIdentifier previous_supplicant_interface_path(supplicant_interface_path_);

  KeyValueStore create_interface_args;
  create_interface_args.Set<std::string>(WPASupplicant::kInterfacePropertyName,
                                         link_name());
  create_interface_args.Set<std::string>(
      WPASupplicant::kInterfacePropertyDriver, WPASupplicant::kDriverNL80211);
  create_interface_args.Set<std::string>(
      WPASupplicant::kInterfacePropertyConfigFile,
      WPASupplicant::kSupplicantConfPath);
  supplicant_connect_attempts_++;

  if (!supplicant_process_proxy()->CreateInterface(
          create_interface_args, &supplicant_interface_path_)) {
    // Interface might've already been created, attempt to retrieve it.
    if (!supplicant_process_proxy()->GetInterface(
            link_name(), &supplicant_interface_path_)) {
      LOG(WARNING) << __func__
                   << ": Failed to create interface with supplicant, attempt "
                   << supplicant_connect_attempts_;

      // Interface could not be created at the moment. This could be a
      // transient error in trying to bring the interface UP, or it could be a
      // persistent device failure. We continue to rety a few times until
      // either we succeed or the device disappears or is disabled, in the hope
      // that the device will recover.
      if (supplicant_connect_attempts_ >= kMaxRetryCreateInterfaceAttempts) {
        LOG(ERROR) << "Failed to create interface with supplicant after "
                   << supplicant_connect_attempts_ << " attempts. Giving up.";
        SetEnabled(false);
        // kMetricWifiSupplicantAttempts.max means we aborted.
        metrics()->SendToUMA(Metrics::kMetricWifiSupplicantAttempts,
                             Metrics::kMetricWifiSupplicantAttempts.max);
      } else {
        dispatcher()->PostDelayedTask(
            FROM_HERE,
            base::BindOnce(&WiFi::ConnectToSupplicant,
                           weak_ptr_factory_.GetWeakPtr()),
            kRetryCreateInterfaceInterval);
      }
      return;
    }
  }

  LOG(INFO) << "connected to supplicant on attempt "
            << supplicant_connect_attempts_;
  metrics()->SendToUMA(Metrics::kMetricWifiSupplicantAttempts,
                       supplicant_connect_attempts_);

  // Only (re)create the interface proxy if its D-Bus path changed, or if we
  // haven't created one yet. This lets us watch interface properties
  // immediately after Stop() (e.g., for metrics collection) and also allows
  // tests to skip recreation (by retaining the same interface path).
  if (!supplicant_interface_proxy_ ||
      previous_supplicant_interface_path != supplicant_interface_path_) {
    SLOG(this, 2) << base::StringPrintf(
        "Updating interface path from \"%s\" to \"%s\"",
        previous_supplicant_interface_path.value().c_str(),
        supplicant_interface_path_.value().c_str());
    SetSupplicantInterfaceProxy(
        control_interface()->CreateSupplicantInterfaceProxy(
            this, supplicant_interface_path_));
  } else {
    SLOG(this, 2) << "Reusing existing interface at "
                  << supplicant_interface_path_.value();
  }

  GetAndUseInterfaceCapabilities();

  RTNLHandler::GetInstance()->SetInterfaceFlags(interface_index(), IFF_UP,
                                                IFF_UP);
  // TODO(quiche) Set ApScan=1 and BSSExpireAge=190, like flimflam does?

  // Clear out any networks that might previously have been configured
  // for this interface.
  supplicant_interface_proxy_->RemoveAllNetworks();

  // Flush interface's BSS cache, so that we get BSSAdded signals for
  // all BSSes (not just new ones since the last scan).
  supplicant_interface_proxy_->FlushBSS(0);

  // TODO(pstew): Disable fast_reauth until supplicant can properly deal
  // with RADIUS servers that respond strangely to such requests.
  // crbug.com/208561
  if (!supplicant_interface_proxy_->SetFastReauth(false)) {
    LOG(ERROR) << "Failed to disable fast_reauth. "
               << "May be running an older version of wpa_supplicant.";
  }

  // Helps with passing WiFiRoaming.001SSIDSwitchBack.
  if (!supplicant_interface_proxy_->SetScanInterval(kRescanIntervalSeconds)) {
    LOG(ERROR) << "Failed to set scan_interval. "
               << "May be running an older version of wpa_supplicant.";
  }

  if (random_mac_enabled_ &&
      !supplicant_interface_proxy_->EnableMacAddressRandomization(
          kRandomMacMask, sched_scan_supported_)) {
    LOG(ERROR) << "Failed to enable MAC address randomization. "
               << "May be running an older version of wpa_supplicant.";
  }

  // Remove all the credentials set in supplicant.
  if (!supplicant_interface_proxy_->RemoveAllCreds()) {
    LOG(ERROR) << "Failed to clear credentials from wpa_supplicant";
  }

  // Push our set of passpoint credentials.
  std::vector<PasspointCredentialsRefPtr> credentials =
      provider_->GetCredentials();
  for (const auto& c : credentials) {
    AddCred(c);
  }

  Scan(nullptr, __func__);
  StartScanTimer();
}

void WiFi::Restart() {
  LOG(INFO) << link_name() << " restarting.";
  WiFiRefPtr me = this;  // Make sure we don't get destructed.
  // Go through the manager rather than starting and stopping the device
  // directly so that the device can be configured with the profile.
  manager()->DeregisterDevice(me);
  manager()->RegisterDevice(me);
}

void WiFi::GetPhyInfo() {
  GetWiphyMessage get_wiphy;
  get_wiphy.AddFlag(NLM_F_DUMP);
  get_wiphy.attributes()->SetU32AttributeValue(NL80211_ATTR_IFINDEX,
                                               interface_index());
  get_wiphy.attributes()->SetFlagAttributeValue(NL80211_ATTR_SPLIT_WIPHY_DUMP,
                                                true);
  netlink_manager_->SendNl80211Message(
      &get_wiphy,
      base::BindRepeating(&WiFi::OnNewWiphy,
                          weak_ptr_factory_while_started_.GetWeakPtr()),
      base::BindRepeating(&NetlinkManager::OnAckDoNothing),
      base::BindRepeating(&WiFi::OnGetPhyInfoAuxMessage,
                          weak_ptr_factory_while_started_.GetWeakPtr()));
}

void WiFi::OnNewWiphy(const Nl80211Message& nl80211_message) {
  // Verify NL80211_CMD_NEW_WIPHY.
  if (nl80211_message.command() != NewWiphyMessage::kCommand) {
    LOG(ERROR) << "Received unexpected command:" << nl80211_message.command();
    return;
  }
  uint32_t phy_index;
  if (!nl80211_message.const_attributes()->GetU32AttributeValue(
          NL80211_ATTR_WIPHY, &phy_index)) {
    LOG(ERROR) << "NL80211_CMD_NEW_WIPHY had no NL80211_ATTR_WIPHY";
    return;
  }

  if (phy_index_ != phy_index) {
    LOG(WARNING) << "Incorrect phy index in NL80211_CMD_NEW_WIPHY. Got index "
                 << phy_index << " but device has index: " << phy_index_;
    // If the message has a different |phy_index|, update |phy_index_| to its
    // value, deregister this device from its current phy, and continue parsing
    // the message.
    // TODO(b/248292473): Check for this warning in feedback reports.
    provider_->DeregisterDeviceFromPhy(this, phy_index_);
    phy_index_ = phy_index;
  }

  provider_->OnNewWiphy(nl80211_message);
  // TODO(b/248054832): Move this registration into WiFiProvider.
  provider_->RegisterDeviceToPhy(this, phy_index_);

  if (wake_on_wifi_) {
    // TODO(b/247124602): These can be combined into a single function.
    wake_on_wifi_->ParseWakeOnWiFiCapabilities(nl80211_message);
    wake_on_wifi_->OnWiphyIndexReceived(phy_index_);
  }

  GetRegulatory();

  // This checks NL80211_ATTR_FEATURE_FLAGS.
  ParseFeatureFlags(nl80211_message);

  // This checks NL80211_ATTR_CIPHER_SUITES and pupulates
  // supported_cipher_suites_.
  ParseCipherSuites(nl80211_message);
}

void WiFi::OnGetPhyInfoAuxMessage(NetlinkManager::AuxiliaryMessageType type,
                                  const NetlinkMessage* raw_message) {
  if (type != NetlinkManager::kDone) {
    NetlinkManager::OnNetlinkMessageError(type, raw_message);
    return;
  }
  provider_->PhyDumpComplete(phy_index_);
}

void WiFi::GetRegulatory() {
  GetRegMessage reg_msg;
  reg_msg.attributes()->SetU32AttributeValue(NL80211_ATTR_WIPHY, phy_index_);
  netlink_manager_->SendNl80211Message(
      &reg_msg,
      base::BindRepeating(&WiFi::OnGetReg,
                          weak_ptr_factory_while_started_.GetWeakPtr()),
      base::BindRepeating(&NetlinkManager::OnAckDoNothing),
      base::BindRepeating(&NetlinkManager::OnNetlinkMessageError));
}

void WiFi::OnTriggerPassiveScanResponse(const Nl80211Message& netlink_message) {
  LOG(WARNING) << "Didn't expect _this_netlink message ("
               << netlink_message.command() << " here:";
  netlink_message.Print(0, 0);
  return;
}

SupplicantProcessProxyInterface* WiFi::supplicant_process_proxy() const {
  return manager()->supplicant_manager()->proxy();
}

KeyValueStore WiFi::GetLinkStatistics(Error* /*error*/) {
  return WiFiLinkStatistics::StationStatsToWiFiDeviceKV(station_stats_);
}

bool WiFi::GetScanPending(Error* /* error */) {
  WiFiState::PhyState state = wifi_state_->GetPhyState();
  return state == WiFiState::PhyState::kScanning ||
         state == WiFiState::PhyState::kBackgroundScanning;
}

bool WiFi::GetWakeOnWiFiSupported(Error* /* error */) {
  return wake_on_wifi_ != nullptr;
}

void WiFi::SetPhyState(WiFiState::PhyState new_state,
                       WiFiState::ScanMethod new_method,
                       const char* reason) {
  if (new_state == WiFiState::PhyState::kIdle)
    new_method = WiFiState::ScanMethod::kNone;
  if (new_state == WiFiState::PhyState::kConnected) {
    // The scan method shouldn't be changed by the connection process, so
    // we'll put a CHECK, here, to verify.  NOTE: this assumption is also
    // enforced by the parameters to the call to |ReportScanResultToUma|.
    CHECK(new_method == wifi_state_->GetScanMethod());
  }

  int log_level = 6;
  bool state_or_method_changed = true;
  bool is_terminal_state = false;
  if (new_state == wifi_state_->GetPhyState() &&
      new_method == wifi_state_->GetScanMethod()) {
    log_level = 7;
    state_or_method_changed = false;
  } else if (new_state == WiFiState::PhyState::kConnected ||
             new_state == WiFiState::PhyState::kFoundNothing) {
    // These 'terminal' states are slightly more interesting than the
    // intermediate states.
    // NOTE: Since background scan goes directly to kScanIdle (skipping over
    // the states required to set |is_terminal_state|), ReportScanResultToUma,
    // below, doesn't get called.  That's intentional.
    log_level = 5;
    is_terminal_state = true;
  }

  if (wifi_state_->GetEnsuredScanState() ==
      WiFiState::EnsuredScanState::kIdle) {
    SLOG(this, log_level) << (reason ? reason : "<unknown>") << " - "
                          << link_name() << ": Scan state: "
                          << WiFiState::LegacyStateString(
                                 wifi_state_->GetPhyState(),
                                 wifi_state_->GetScanMethod())
                          << " -> "
                          << wifi_state_->LegacyStateString(new_state,
                                                            new_method);
  } else {
    LOG(INFO) << (reason ? reason : "<unknown>") << " - " << link_name()
              << ": Scan state: "
              << WiFiState::LegacyStateString(wifi_state_->GetPhyState(),
                                              wifi_state_->GetScanMethod())
              << " -> " << wifi_state_->LegacyStateString(new_state, new_method)
              << " ensured scan: " << wifi_state_->GetEnsuredScanStateString();
  }

  // Actually change the state.
  WiFiState::PhyState old_state = wifi_state_->GetPhyState();
  WiFiState::ScanMethod old_method = wifi_state_->GetScanMethod();
  bool old_scan_pending = GetScanPending(nullptr);
  wifi_state_->SetPhyState(new_state, new_method);
  bool new_scan_pending = GetScanPending(nullptr);

  // Always handle ensured scans on idle transitions.
  if (new_state == WiFiState::PhyState::kIdle) {
    HandleEnsuredScan(old_state);
  }

  // Avoid reporting metrics if nothing changed.
  if (!state_or_method_changed)
    return;

  if (old_scan_pending != new_scan_pending) {
    adaptor()->EmitBoolChanged(kScanningProperty, new_scan_pending);
  }
  switch (new_state) {
    case WiFiState::PhyState::kIdle:
      metrics()->ResetScanTimer(interface_index());
      metrics()->ResetConnectTimer(interface_index());
      break;
    case WiFiState::PhyState::kScanning:  // FALLTHROUGH
    case WiFiState::PhyState::kBackgroundScanning:
      if (new_state != old_state) {
        metrics()->NotifyDeviceScanStarted(interface_index());
      }
      break;
    case WiFiState::PhyState::kConnecting:
      metrics()->NotifyDeviceScanFinished(interface_index());
      metrics()->NotifyDeviceConnectStarted(interface_index());
      break;
    case WiFiState::PhyState::kConnected:
      metrics()->NotifyDeviceConnectFinished(interface_index());
      break;
    case WiFiState::PhyState::kFoundNothing:
      // Note that finishing a scan that hasn't started (if, for example, we
      // get here when we fail to complete a connection) does nothing.
      metrics()->NotifyDeviceScanFinished(interface_index());
      metrics()->ResetConnectTimer(interface_index());
      break;
    case WiFiState::PhyState::kTransitionToConnecting:  // FALLTHROUGH
    default:
      break;
  }
  if (is_terminal_state) {
    ReportScanResultToUma(new_state, old_method);
    // Now that we've logged a terminal state, let's call ourselves to
    // transition to the idle state.
    SetPhyState(WiFiState::PhyState::kIdle, WiFiState::ScanMethod::kNone,
                reason);
  }
}

void WiFi::HandleEnsuredScan(WiFiState::PhyState old_phy_state) {
  if (wifi_state_->GetEnsuredScanState() ==
      WiFiState::EnsuredScanState::kIdle) {
    return;
  }
  // If the device was disabled or the supplicant disappeared between the
  // call to ensure the scan and this call, attempt to connect to a best service
  // on another device.
  if (!enabled() || !supplicant_present_) {
    wifi_state_->SetEnsuredScanState(WiFiState::EnsuredScanState::kIdle);
    return;
  }
  switch (wifi_state_->GetEnsuredScanState()) {
    case WiFiState::EnsuredScanState::kWaiting:
      wifi_state_->SetEnsuredScanState(WiFiState::EnsuredScanState::kScanning);
      // This starts a scan in the event loop, allowing SetPhyState
      // to complete before proceeding.
      Scan(nullptr, "Previous scan complete. Starting ensured scan.");
      break;
    case WiFiState::EnsuredScanState::kScanning:
      // If the last state was a scanning-related state, the scan actually
      // executed.  Otherwise there was a race condition for the radio, and
      // a new scan should be started.
      switch (old_phy_state) {
        case WiFiState::PhyState::kScanning:
        case WiFiState::PhyState::kBackgroundScanning:
        case WiFiState::PhyState::kFoundNothing:
          wifi_state_->SetEnsuredScanState(WiFiState::EnsuredScanState::kIdle);
          manager()->ConnectToBestWiFiService();
          break;
        case WiFiState::PhyState::kTransitionToConnecting:
        case WiFiState::PhyState::kConnecting:
        case WiFiState::PhyState::kConnected:
        case WiFiState::PhyState::kIdle:
          // This starts a scan in the event loop, allowing SetPhyState
          // to complete before proceeding.
          Scan(nullptr, "Ensured scan didn't occur. Requesting another scan.");
          break;
      }
      break;
    case WiFiState::EnsuredScanState::kIdle:
      break;
  }
}

void WiFi::ReportScanResultToUma(WiFiState::PhyState state,
                                 WiFiState::ScanMethod method) {
  Metrics::WiFiScanResult result = Metrics::kScanResultMax;
  if (state == WiFiState::PhyState::kConnected) {
    switch (method) {
      case WiFiState::ScanMethod::kFull:
        result = Metrics::kScanResultFullScanConnected;
        break;
      default:
        // OK: Connect resulting from something other than scan.
        break;
    }
  } else if (state == WiFiState::PhyState::kFoundNothing) {
    switch (method) {
      case WiFiState::ScanMethod::kFull:
        result = Metrics::kScanResultFullScanFoundNothing;
        break;
      default:
        // OK: Connect failed, not scan related.
        break;
    }
  }

  if (result != Metrics::kScanResultMax) {
    metrics()->ReportDeviceScanResultToUma(result);
  }
}

void WiFi::EmitStationInfoRequestEvent(WiFiLinkStatistics::Trigger trigger) {
  if (!current_service_.get()) {
    SLOG(this, 2) << __func__ << ": WiFi " << link_name()
                  << " tried to emit STA info trigger event"
                  << " without being connected.";
    return;
  }
  current_service_->EmitLinkQualityTriggerEvent(
      WiFiLinkStatistics::ConvertLinkStatsTriggerEvent(trigger));
}

void WiFi::RequestStationInfo(WiFiLinkStatistics::Trigger trigger) {
  // It only makes sense to request station info if a link is active.
  if (supplicant_state_ != WPASupplicant::kInterfaceStateCompleted) {
    LOG(ERROR) << "Not collecting station info because we are not connected.";
    return;
  }

  EndpointMap::iterator endpoint_it = endpoint_by_rpcid_.find(supplicant_bss_);
  if (endpoint_it == endpoint_by_rpcid_.end()) {
    LOG(ERROR) << "Can't get endpoint for current supplicant BSS "
               << supplicant_bss_.value();
    return;
  }

  // shill requests the station info every |kRequestStationInfoPeriod| seconds,
  // which is 20s at the time of writing, in particular to update the signal
  // strength. We don't necessarily want to add the statistics to structured
  // events that often, so we only emit the event once we've passed multiple
  // |kRequestStationInfoPeriod| periods.
  // Note: link statistics requests triggered by non-periodic events (e.g CQM,
  // some IP-level events, etc.) will interfere with the way we track the
  // |kReportStationInfoSample| interval since they will cancel pending calls
  // to background stats reports, but that's not a problem, we only care about
  // the approximate interval between structured events, it does not have to be
  // exact.
  if (trigger == WiFiLinkStatistics::Trigger::kBackground) {
    if (station_info_reqs_ % kReportStationInfoSample == 0) {
      EmitStationInfoRequestEvent(WiFiLinkStatistics::Trigger::kBackground);
      pending_nl80211_stats_requests_.push_back(
          WiFiLinkStatistics::Trigger::kBackground);
    }
    station_info_reqs_++;
  } else if (trigger != WiFiLinkStatistics::Trigger::kUnknown) {
    EmitStationInfoRequestEvent(trigger);
    pending_nl80211_stats_requests_.push_back(trigger);
  }

  // TODO(b/260915172): we sometimes call RequestStationInfo() multiple times,
  // sending redundant requests to wpa_supplicant. We could instead only query
  // supplicant if there isn't a request already in flight.
  KeyValueStore properties;
  if (supplicant_interface_proxy_->SignalPoll(&properties)) {
    // Only process a signal change if information was received.
    SignalChanged(properties);
  }

  request_station_info_callback_.Reset(base::BindOnce(
      &WiFi::RequestStationInfo, weak_ptr_factory_while_started_.GetWeakPtr(),
      WiFiLinkStatistics::Trigger::kBackground));
  dispatcher()->PostDelayedTask(FROM_HERE,
                                request_station_info_callback_.callback(),
                                kRequestStationInfoPeriod);
}

void WiFi::AddBTStateToLinkQualityReport(
    Metrics::WiFiLinkQualityReport& report) const {
#if !defined(DISABLE_FLOSS)
  BluetoothManagerInterface* bt_manager = manager()->bluetooth_manager();
  if (!bt_manager) {
    LOG(ERROR) << link_name() << ": BT manager is not ready";
    return;
  }

  bool floss = false;
  bool bt_enabled = false;
  int32_t hci = BluetoothManagerInterface::kInvalidHCI;
  std::vector<BluetoothManagerInterface::BTAdapterWithEnabled> bt_adapters;
  if (!bt_manager->GetAvailableAdapters(&floss, &bt_adapters)) {
    LOG(ERROR) << link_name() << ": Failed to query available BT adapters";
    return;
  }
  report.bt_stack = floss ? Metrics::kBTStackFloss : Metrics::kBTStackBlueZ;

  for (auto adapter : bt_adapters) {
    if (adapter.enabled) {
      bt_enabled = true;
      if (hci == BluetoothManagerInterface::kInvalidHCI) {
        // If this is the first adapter that is enabled, store its HCI and query
        // that adapter directly. That saves a D-Bus roundtrip to find out which
        // adapter is the default one.
        hci = adapter.hci_interface;
      } else {
        // At least 2 adapters are enabled. Reset the HCI and query the BT stack
        // to know which adapter is the default one. Only then will we be able
        // to query the state of that particular adapter.
        hci = BluetoothManagerInterface::kInvalidHCI;
        break;
      }
    }
  }
  report.bt_enabled = bt_enabled;

  if (!(floss && bt_enabled)) {
    // Querying the state of BT adapters is only possible if both:
    // - the device is using Floss
    // - BT is enabled
    return;
  }
  if (hci == BluetoothManagerInterface::kInvalidHCI) {
    // More than 1 adapter is enabled, find out the HCI of the default one and
    // then query that adapter directly.
    if (!bt_manager->GetDefaultAdapter(&hci)) {
      LOG(ERROR) << link_name() << ": Failed to query default BT adapter";
      return;
    }
  }
  SLOG(this, 3) << __func__ << ": WiFi " << link_name()
                << ": Default BT adapter HCI " << hci;
  BluetoothManagerInterface::BTProfileConnectionState profile_state;
  if (bt_manager->GetProfileConnectionState(
          hci, BluetoothManagerInterface::BTProfile::kHFP, &profile_state)) {
    report.bt_hfp =
        WiFiMetricsUtils::ConvertBTProfileConnectionState(profile_state);
  }
  if (bt_manager->GetProfileConnectionState(
          hci, BluetoothManagerInterface::BTProfile::kA2DPSink,
          &profile_state)) {
    report.bt_a2dp =
        WiFiMetricsUtils::ConvertBTProfileConnectionState(profile_state);
  }
  bool discovering;
  if (bt_manager->IsDiscovering(hci, &discovering)) {
    report.bt_active_scanning = discovering;
  }
#else   // DISABLE_FLOSS
  (void)report;
#endif  // DISABLE_FLOSS
}

void WiFi::EmitStationInfoReceivedEvent(
    const WiFiLinkStatistics::StationStats& stats) {
  if (!current_service_.get()) {
    SLOG(this, 2) << __func__ << ": WiFi " << link_name()
                  << " tried to emit STA info event"
                  << " without being connected.";
    return;
  }
  Metrics::WiFiLinkQualityReport report =
      WiFiLinkStatistics::ConvertLinkStatsReport(stats);
  AddBTStateToLinkQualityReport(report);
  current_service_->EmitLinkQualityReportEvent(report);
}

void WiFi::HandleUpdatedLinkStatistics() {
  // Update the endpoint's signal
  EndpointMap::iterator endpoint_it = endpoint_by_rpcid_.find(supplicant_bss_);
  if (endpoint_it == endpoint_by_rpcid_.end()) {
    LOG(ERROR) << "Can't get endpoint for current supplicant BSS."
               << supplicant_bss_.value();
    return;
  }
  WiFiEndpointRefPtr endpoint(endpoint_it->second);
  // Update the signal strength.  Prefer the average signal strength, then the
  // average beacon strength, then the signal strength from the last packet.
  if (station_stats_.signal_avg != WiFiLinkStatistics::kDefaultSignalValue) {
    endpoint->UpdateSignalStrength(
        static_cast<signed char>(station_stats_.signal_avg));
  } else if (station_stats_.beacon_signal_avg !=
             WiFiLinkStatistics::kDefaultSignalValue) {
    endpoint->UpdateSignalStrength(
        static_cast<signed char>(station_stats_.beacon_signal_avg));
  } else {
    endpoint->UpdateSignalStrength(
        static_cast<signed char>(station_stats_.signal));
  }

  // Update telemetry and Service link speed properties.
  if (station_stats_.tx.bitrate != UINT_MAX) {
    metrics()->SendToUMA(Metrics::kMetricWifiTxBitrate,
                         station_stats_.tx.bitrate / 10);
    if (current_service_) {
      // Convert the unit of link speed from 100Kbps to Kbps.
      current_service_->SetUplinkSpeedKbps(station_stats_.tx.bitrate * 100);
    }
  }
  if (station_stats_.rx.bitrate != UINT_MAX && current_service_) {
    current_service_->SetDownlinkSpeedKbps(station_stats_.rx.bitrate * 100);
  }
  if (!pending_nl80211_stats_requests_.empty()) {
    // Only emit 1 telemetry event with link statistics, even if we had multiple
    // trigger events (e.g. CQM and DHCP in quick succession).
    EmitStationInfoReceivedEvent(station_stats_);
    for (auto req : pending_nl80211_stats_requests_) {
      wifi_link_statistics_->UpdateNl80211LinkStatistics(req, station_stats_);
    }
    pending_nl80211_stats_requests_.clear();
  }
}

void WiFi::ResetStationInfoRequests() {
  pending_nl80211_stats_requests_.clear();
  station_info_reqs_ = 0;
  station_stats_ = {};
}

void WiFi::StopRequestingStationInfo() {
  SLOG(this, 2) << "WiFi Device " << link_name() << ": " << __func__;
  request_station_info_callback_.Cancel();
  ResetStationInfoRequests();
}

void WiFi::RemoveSupplicantNetworks() {
  for (const auto& map_entry : rpcid_by_service_) {
    RemoveNetwork(map_entry.second);
  }
  rpcid_by_service_.clear();
}

void WiFi::OnGetDHCPLease(int net_interface_index) {
  DCHECK(net_interface_index == interface_index());
  RetrieveLinkStatistics(WiFiLinkStatistics::Trigger::kDHCPSuccess);
}

void WiFi::OnGetDHCPFailure(int net_interface_index) {
  DCHECK(net_interface_index == interface_index());
  RetrieveLinkStatistics(WiFiLinkStatistics::Trigger::kDHCPFailure);
}

void WiFi::OnGetSLAACAddress(int net_interface_index) {
  DCHECK(net_interface_index == interface_index());
  RetrieveLinkStatistics(WiFiLinkStatistics::Trigger::kSlaacFinished);
}

void WiFi::OnNetworkValidationStart(int net_interface_index) {
  DCHECK(net_interface_index == interface_index());
  RetrieveLinkStatistics(WiFiLinkStatistics::Trigger::kNetworkValidationStart);
}

void WiFi::OnNetworkValidationSuccess() {
  RetrieveLinkStatistics(
      WiFiLinkStatistics::Trigger::kNetworkValidationSuccess);
}

void WiFi::OnNetworkValidationFailure() {
  RetrieveLinkStatistics(
      WiFiLinkStatistics::Trigger::kNetworkValidationFailure);
}

void WiFi::OnIPv4ConfiguredWithDHCPLease(int net_interface_index) {
  DCHECK(net_interface_index == interface_index());
  if (!wake_on_wifi_) {
    return;
  }
  SLOG(this, 2) << __func__ << ": "
                << "IPv4 DHCP lease obtained";
  wake_on_wifi_->OnConnectedAndReachable(
      GetPrimaryNetwork()->TimeToNextDHCPLeaseRenewal());
}

void WiFi::OnIPv6ConfiguredWithSLAACAddress(int net_interface_index) {
  DCHECK(net_interface_index == interface_index());
  if (!IsConnectedToCurrentService()) {
    return;
  }
  if (!wake_on_wifi_) {
    return;
  }
  SLOG(this, 2) << __func__ << ": "
                << "IPv6 configuration obtained through SLAAC";
  wake_on_wifi_->OnConnectedAndReachable(std::nullopt);
}

void WiFi::RetrieveLinkStatistics(WiFiLinkStatistics::Trigger event) {
  current_rtnl_network_event_ = event;
  RTNLHandler::GetInstance()->RequestDump(RTNLHandler::kRequestLink);
  RequestStationInfo(event);
}

bool WiFi::IsConnectedToCurrentService() {
  return (current_service_ && current_service_->IsConnected());
}

void WiFi::ReportConnectedToServiceAfterWake() {
  int seconds_in_suspend = (manager()->GetSuspendDurationUsecs() / 1000000);
  if (wake_on_wifi_) {
    wake_on_wifi_->ReportConnectedToServiceAfterWake(
        IsConnectedToCurrentService(), seconds_in_suspend);
  }
}

bool WiFi::RequestRoam(const std::string& addr, Error* error) {
  if (!supplicant_interface_proxy_->Roam(addr)) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kOperationFailed,
        base::StringPrintf("%s: requested roam to %s failed",
                           link_name().c_str(), addr.c_str()));
    return false;
  }
  return true;
}

// TODO(b/184395063): determine this at runtime.
bool WiFi::SupportsWPA3() const {
#if !defined(DISABLE_WPA3_SAE)
  return true;
#else
  return false;
#endif
}

void WiFi::GetDeviceHardwareIds(int* vendor,
                                int* product,
                                int* subsystem) const {
  if (manager() && manager()->device_info()) {
    manager()->device_info()->GetWiFiHardwareIds(interface_index(), vendor,
                                                 product, subsystem);
  }
}

void WiFi::OnNeighborReachabilityEvent(
    int net_interface_index,
    const IPAddress& ip_address,
    patchpanel::Client::NeighborRole role,
    patchpanel::Client::NeighborStatus status) {
  using Role = patchpanel::Client::NeighborRole;
  using Status = patchpanel::Client::NeighborStatus;

  DCHECK(net_interface_index == interface_index());

  // Checks if the signal is for the gateway of the current connection.
  if (role != Role::kGateway && role != Role::kGatewayAndDnsServer) {
    return;
  }

  switch (status) {
    case Status::kReachable:
      return;
    case Status::kFailed:
      OnLinkMonitorFailure(ip_address.family());
      return;
    default:
      // Already filtered in Network::OnNeighborReachabilityEvent().
      NOTREACHED();
  }
}

uint64_t WiFi::GetReceiveByteCount() {
  uint64_t rx_byte_count = 0, tx_byte_count = 0;
  manager()->device_info()->GetByteCounts(interface_index(), &rx_byte_count,
                                          &tx_byte_count);
  return rx_byte_count;
}

void WiFi::OnReceivedRtnlLinkStatistics(const old_rtnl_link_stats64& stats) {
  wifi_link_statistics_->UpdateRtnlLinkStatistics(current_rtnl_network_event_,
                                                  stats);
  // Reset current_rtnl_network_event_ to prevent unnecessary WiFiLinkStatistics
  // update/print
  current_rtnl_network_event_ = WiFiLinkStatistics::Trigger::kUnknown;
}

bool WiFi::SupportsWEP() const {
  return (base::Contains(supported_cipher_suites_, kWEP40CipherCode) &&
          base::Contains(supported_cipher_suites_, kWEP104CipherCode));
}

const WiFiPhy* WiFi::GetWiFiPhy() const {
  return provider_->GetPhyAtIndex(phy_index_);
}

bool WiFi::SetBSSIDAllowlist(const WiFiService* service,
                             const Strings& bssid_allowlist,
                             Error* error) {
  RpcIdentifier network_rpcid = FindNetworkRpcidForService(service, error);
  if (network_rpcid.value().empty()) {
    // Error is already populated.
    return false;
  }

  KeyValueStore kv;
  kv.Set<std::string>(WPASupplicant::kNetworkPropertyBSSIDAccept,
                      base::JoinString(bssid_allowlist, " "));
  std::unique_ptr<SupplicantNetworkProxyInterface> supplicant_network_proxy =
      control_interface()->CreateSupplicantNetworkProxy(network_rpcid);
  if (!supplicant_network_proxy->SetProperties(kv)) {
    const auto error_message = base::StringPrintf(
        "WiFi %s cannot set BSSID allowlist for service %s: "
        "DBus operation failed for rpcid %s.",
        link_name().c_str(), service->log_name().c_str(),
        network_rpcid.value().c_str());
    Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                          error_message);
    return false;
  }

  return true;
}

}  // namespace shill
