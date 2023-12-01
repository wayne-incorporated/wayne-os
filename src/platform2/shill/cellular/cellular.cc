// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/cellular.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <linux/if.h>  // NOLINT - Needs definitions from netinet/in.h

#include <memory>
#include <optional>
#include <set>
#include <tuple>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/containers/contains.h>
#include <base/containers/cxx20_erase.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/notreached.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_split.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <chromeos/dbus/service_constants.h>
#include <ModemManager/ModemManager.h>

#include "dbus/shill/dbus-constants.h"
#include "shill/adaptor_interfaces.h"
#include "shill/cellular/apn_list.h"
#include "shill/cellular/carrier_entitlement.h"
#include "shill/cellular/cellular_bearer.h"
#include "shill/cellular/cellular_capability_3gpp.h"
#include "shill/cellular/cellular_consts.h"
#include "shill/cellular/cellular_error.h"
#include "shill/cellular/cellular_helpers.h"
#include "shill/cellular/cellular_service.h"
#include "shill/cellular/cellular_service_provider.h"
#include "shill/cellular/mobile_operator_info.h"
#include "shill/cellular/modem_info.h"
#include "shill/control_interface.h"
#include "shill/data_types.h"
#include "shill/dbus/dbus_properties_proxy.h"
#include "shill/device.h"
#include "shill/device_info.h"
#include "shill/error.h"
#include "shill/event_dispatcher.h"
#include "shill/external_task.h"
#include "shill/ipconfig.h"
#include "shill/logging.h"
#include "shill/manager.h"
#include "shill/net/ip_address.h"
#include "shill/net/netlink_sock_diag.h"
#include "shill/net/process_manager.h"
#include "shill/net/rtnl_handler.h"
#include "shill/net/rtnl_listener.h"
#include "shill/net/rtnl_message.h"
#include "shill/net/sockets.h"
#include "shill/ppp_daemon.h"
#include "shill/profile.h"
#include "shill/service.h"
#include "shill/store/property_accessor.h"
#include "shill/store/store_interface.h"
#include "shill/technology.h"
#include "shill/tethering_manager.h"
#include "shill/virtual_device.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kCellular;
}  // namespace Logging

namespace {

// Maximum time to wait for Modem registration before canceling a pending
// connect attempt.
constexpr base::TimeDelta kPendingConnectCancel = base::Minutes(1);

// Prefix used by entitlement check logging messages when the entitlement
// check is not successful. This prefix is used by the anomaly detector to
// identify these events.
constexpr char kEntitlementCheckAnomalyDetectorPrefix[] =
    "Entitlement check failed: ";

bool IsEnabledModemState(Cellular::ModemState state) {
  switch (state) {
    case Cellular::kModemStateFailed:
    case Cellular::kModemStateUnknown:
    case Cellular::kModemStateDisabled:
    case Cellular::kModemStateInitializing:
    case Cellular::kModemStateLocked:
    case Cellular::kModemStateDisabling:
    case Cellular::kModemStateEnabling:
      return false;
    case Cellular::kModemStateEnabled:
    case Cellular::kModemStateSearching:
    case Cellular::kModemStateRegistered:
    case Cellular::kModemStateDisconnecting:
    case Cellular::kModemStateConnecting:
    case Cellular::kModemStateConnected:
      return true;
  }
  return false;
}

Metrics::DetailedCellularConnectionResult::IPConfigMethod
BearerIPConfigMethodToMetrics(CellularBearer::IPConfigMethod method) {
  using BearerType = CellularBearer::IPConfigMethod;
  using MetricsType = Metrics::DetailedCellularConnectionResult::IPConfigMethod;
  switch (method) {
    case BearerType::kUnknown:
      return MetricsType::kUnknown;
    case BearerType::kPPP:
      return MetricsType::kPPP;
    case BearerType::kStatic:
      return MetricsType::kStatic;
    case BearerType::kDHCP:
      return MetricsType::kDHCP;
  }
}

std::string GetFriendlyModelId(const std::string& model_id) {
  if (model_id.find("L850") != std::string::npos) {
    return "L850";
  }
  if (model_id.find("FM101") != std::string::npos) {
    return "FM101";
  }
  if (model_id.find("7c Compute") != std::string::npos) {
    return "SC7180";
  }
  if (model_id.find("4D75") != std::string::npos) {
    return "FM350";
  }
  if (model_id.find("NL668") != std::string::npos) {
    return "NL668";
  }
  return model_id;
}

// Returns if specified modem manager error can be classified as
// subscription related error. This API should be enhanced if
// better signals become available to detect subscription error.
bool IsSubscriptionError(std::string mm_error) {
  return mm_error == MM_MOBILE_EQUIPMENT_ERROR_DBUS_PREFIX
         ".ServiceOptionNotSubscribed";
}

Metrics::DetailedCellularConnectionResult::ConnectionAttemptType
ConnectionAttemptTypeToMetrics(CellularServiceRefPtr service) {
  using MetricsType =
      Metrics::DetailedCellularConnectionResult::ConnectionAttemptType;
  if (!service)
    return MetricsType::kUnknown;
  if (service->is_in_user_connect())
    return MetricsType::kUserConnect;
  return MetricsType::kAutoConnect;
}

}  // namespace

// static
const char Cellular::kAllowRoaming[] = "AllowRoaming";
const char Cellular::kPolicyAllowRoaming[] = "PolicyAllowRoaming";
const char Cellular::kUseAttachApn[] = "UseAttachAPN";
const char Cellular::kQ6V5ModemManufacturerName[] = "QUALCOMM INCORPORATED";
const char Cellular::kQ6V5DriverName[] = "qcom-q6v5-mss";
const char Cellular::kQ6V5SysfsBasePath[] = "/sys/class/remoteproc";
const char Cellular::kQ6V5RemoteprocPattern[] = "remoteproc*";
const char Cellular::kTetheringTestDatabasePath[] =
    "/usr/share/shill/tethering_experimental.pbf";

// static
std::string Cellular::GetStateString(State state) {
  switch (state) {
    case State::kDisabled:
      return "Disabled";
    case State::kEnabled:
      return "Enabled";
    case State::kModemStarting:
      return "ModemStarting";
    case State::kModemStarted:
      return "ModemStarted";
    case State::kModemStopping:
      return "ModemStopping";
    case State::kRegistered:
      return "Registered";
    case State::kConnected:
      return "Connected";
    case State::kLinked:
      return "Linked";
    default:
      NOTREACHED();
  }
  return base::StringPrintf("CellularStateUnknown-%d", state);
}

// static
std::string Cellular::GetModemStateString(ModemState modem_state) {
  switch (modem_state) {
    case kModemStateFailed:
      return "ModemStateFailed";
    case kModemStateUnknown:
      return "ModemStateUnknown";
    case kModemStateInitializing:
      return "ModemStateInitializing";
    case kModemStateLocked:
      return "ModemStateLocked";
    case kModemStateDisabled:
      return "ModemStateDisabled";
    case kModemStateDisabling:
      return "ModemStateDisabling";
    case kModemStateEnabling:
      return "ModemStateEnabling";
    case kModemStateEnabled:
      return "ModemStateEnabled";
    case kModemStateSearching:
      return "ModemStateSearching";
    case kModemStateRegistered:
      return "ModemStateRegistered";
    case kModemStateDisconnecting:
      return "ModemStateDisconnecting";
    case kModemStateConnecting:
      return "ModemStateConnecting";
    case kModemStateConnected:
      return "ModemStateConnected";
    default:
      NOTREACHED();
  }
  return base::StringPrintf("ModemStateUnknown-%d", modem_state);
}

// static
void Cellular::ValidateApnTryList(std::deque<Stringmap>& apn_try_list) {
  // Entries in the APN try list must have the APN property
  apn_try_list.erase(
      std::remove_if(
          apn_try_list.begin(), apn_try_list.end(),
          [](const auto& item) { return !base::Contains(item, kApnProperty); }),
      apn_try_list.end());
}

// static
Stringmap Cellular::BuildFallbackEmptyApn(ApnList::ApnType apn_type) {
  Stringmap apn;
  apn[kApnProperty] = "";
  apn[kApnTypesProperty] = ApnList::GetApnTypeString(apn_type);
  apn[kApnIpTypeProperty] = kApnIpTypeV4V6;
  apn[kApnSourceProperty] = cellular::kApnSourceFallback;
  return apn;
}

Cellular::Cellular(Manager* manager,
                   const std::string& link_name,
                   const std::string& address,
                   int interface_index,
                   const std::string& service,
                   const RpcIdentifier& path)
    : Device(
          manager, link_name, address, interface_index, Technology::kCellular),
      mobile_operator_info_(
          new MobileOperatorInfo(manager->dispatcher(), "cellular")),
      dbus_service_(service),
      dbus_path_(path),
      dbus_path_str_(path.value()),
      process_manager_(ProcessManager::GetInstance()) {
  RegisterProperties();
  // TODO(b/267804414): This database is merged with service_providers.pbf, and
  // overrides a few carriers in it. This is used for fishfooding on carriers
  // that require multiple PDNs.
  if (manager->tethering_manager() && manager->tethering_manager()->allowed() &&
      !base::PathExists(
          base::FilePath(MobileOperatorInfo::kExclusiveOverrideDatabasePath))) {
    mobile_operator_info_->AddDatabasePath(
        base::FilePath(kTetheringTestDatabasePath));
  }

  mobile_operator_info_->Init();

  socket_destroyer_ = NetlinkSockDiag::Create(std::make_unique<Sockets>());
  if (!socket_destroyer_) {
    LOG(WARNING) << LoggingTag() << ": Socket destroyer failed to initialize; "
                 << "IPv6 will be unavailable.";
  }

  // Create an initial Capability.
  CreateCapability();

  carrier_entitlement_ = std::make_unique<CarrierEntitlement>(
      dispatcher(), metrics(),
      base::BindRepeating(&Cellular::OnEntitlementCheckUpdated,
                          weak_ptr_factory_.GetWeakPtr()));
  SLOG(1) << LoggingTag() << ": Cellular()";
}

Cellular::~Cellular() {
  LOG(INFO) << LoggingTag() << ": ~Cellular()";
  if (capability_)
    DestroyCapability();
}

std::string Cellular::GetLegacyEquipmentIdentifier() const {
  // 3GPP devices are uniquely identified by IMEI, which has 15 decimal digits.
  if (!imei_.empty())
    return imei_;

  // 3GPP2 devices are uniquely identified by MEID, which has 14 hexadecimal
  // digits.
  if (!meid_.empty())
    return meid_;

  // An equipment ID may be reported by ModemManager, which is typically the
  // serial number of a legacy AT modem, and is either the IMEI, MEID, or ESN
  // of a MBIM/QMI modem. This is used as a fallback in case neither IMEI nor
  // MEID could be retrieved through ModemManager (e.g. when there is no SIM
  // inserted, ModemManager doesn't expose modem 3GPP interface where the IMEI
  // is reported).
  if (!equipment_id_.empty())
    return equipment_id_;

  // If none of IMEI, MEID, and equipment ID is available, fall back to MAC
  // address.
  return mac_address();
}

std::string Cellular::GetStorageIdentifier() const {
  // Cellular is not guaranteed to have a valid MAC address, and other unique
  // identifiers may not be initially available. Use the link name to
  // differentiate between internal devices and external devices.
  return "device_" + link_name();
}

bool Cellular::Load(const StoreInterface* storage) {
  std::string id = GetStorageIdentifier();
  SLOG(2) << LoggingTag() << ": " << __func__ << ": Device ID: " << id;
  if (!storage->ContainsGroup(id)) {
    id = "device_" + GetLegacyEquipmentIdentifier();
    if (!storage->ContainsGroup(id)) {
      LOG(WARNING) << LoggingTag() << ": " << __func__
                   << ": Device is not available in the persistent store";
      return false;
    }
    legacy_storage_id_ = id;
  }
  storage->GetBool(id, kAllowRoaming, &allow_roaming_);
  storage->GetBool(id, kPolicyAllowRoaming, &policy_allow_roaming_);
  LOG(INFO) << LoggingTag() << ": " << __func__ << ": " << kAllowRoaming << ":"
            << allow_roaming_ << " " << kPolicyAllowRoaming << ":"
            << policy_allow_roaming_;
  return Device::Load(storage);
}

bool Cellular::Save(StoreInterface* storage) {
  const std::string id = GetStorageIdentifier();
  storage->SetBool(id, kAllowRoaming, allow_roaming_);
  storage->SetBool(id, kPolicyAllowRoaming, policy_allow_roaming_);
  bool result = Device::Save(storage);
  SLOG(2) << LoggingTag() << ": " << __func__ << ": Device ID: " << id;
  LOG(INFO) << LoggingTag() << ": " << __func__ << ": " << result;
  // TODO(b/181843251): Remove when number of users on M92 are negligible.
  if (result && !legacy_storage_id_.empty() &&
      storage->ContainsGroup(legacy_storage_id_)) {
    SLOG(2) << LoggingTag() << ": " << __func__
            << ": Deleting legacy storage id: " << legacy_storage_id_;
    storage->DeleteGroup(legacy_storage_id_);
    legacy_storage_id_.clear();
  }
  return result;
}

std::string Cellular::GetTechnologyFamily(Error* error) {
  return capability_ ? capability_->GetTypeString() : "";
}

std::string Cellular::GetDeviceId(Error* error) {
  return device_id_ ? device_id_->AsString() : "";
}

bool Cellular::GetMultiplexSupport() {
  // The device allows multiplexing support when more than one multiplexed
  // bearers can be setup at a given time.
  return (max_multiplexed_bearers_ > 1);
}

bool Cellular::ShouldBringNetworkInterfaceDownAfterDisabled() const {
  if (!device_id_)
    return false;

  // The cdc-mbim kernel driver stop draining the receive buffer after the
  // network interface is brought down. However, some MBIM modem (see
  // b:71505232) may misbehave if the host stops draining the receiver buffer
  // before issuing a MBIM command to disconnect the modem from network. To
  // work around the issue, shill needs to defer bringing down the network
  // interface until after the modem is disabled.
  //
  // TODO(benchan): Investigate if we need to apply the workaround for other
  // MBIM modems or revert this change once the issue is addressed by the modem
  // firmware on Fibocom L850-GL.
  static constexpr DeviceId kAffectedDeviceIds[] = {
      {DeviceId::BusType::kUsb, 0x2cb7, 0x0007},  // Fibocom L850-GL
  };
  for (const auto& affected_device_id : kAffectedDeviceIds) {
    if (device_id_->Match(affected_device_id))
      return true;
  }

  return false;
}

void Cellular::SetState(State state) {
  if (state == state_)
    return;
  LOG(INFO) << LoggingTag() << ": " << __func__ << ": "
            << GetStateString(state_) << " -> " << GetStateString(state);
  state_ = state;
  UpdateScanning();
}

void Cellular::SetModemState(ModemState modem_state) {
  if (modem_state == modem_state_)
    return;
  LOG(INFO) << LoggingTag() << ": " << __func__ << ": "
            << GetModemStateString(modem_state_) << " -> "
            << GetModemStateString(modem_state);
  modem_state_ = modem_state;
  UpdateScanning();
}

void Cellular::HelpRegisterDerivedBool(base::StringPiece name,
                                       bool (Cellular::*get)(Error* error),
                                       bool (Cellular::*set)(const bool& value,
                                                             Error* error)) {
  mutable_store()->RegisterDerivedBool(
      name, BoolAccessor(new CustomAccessor<Cellular, bool>(this, get, set)));
}

void Cellular::HelpRegisterConstDerivedString(
    base::StringPiece name, std::string (Cellular::*get)(Error*)) {
  mutable_store()->RegisterDerivedString(
      name, StringAccessor(
                new CustomAccessor<Cellular, std::string>(this, get, nullptr)));
}

void Cellular::Start(EnabledStateChangedCallback callback) {
  LOG(INFO) << LoggingTag() << ": " << __func__ << ": "
            << GetStateString(state_);

  if (!capability_) {
    // Report success, even though a connection will not succeed until a Modem
    // is instantiated and |cabability_| is created. Setting |state_|
    // to kEnabled here will cause CreateCapability to call StartModem.
    SetState(State::kEnabled);
    LOG(WARNING) << LoggingTag() << ": " << __func__
                 << ": Skipping Start (no capability).";
    std::move(callback).Run(Error(Error::kSuccess));
    return;
  }

  StartModem(std::move(callback));
}

void Cellular::Stop(EnabledStateChangedCallback callback) {
  LOG(INFO) << LoggingTag() << ": " << __func__ << ": "
            << GetStateString(state_);
  DCHECK(!stop_step_.has_value()) << "Already stopping. Unexpected Stop call.";
  stop_step_ = StopSteps::kStopModem;
  StopStep(std::move(callback), Error());
}

void Cellular::StopStep(EnabledStateChangedCallback callback,
                        const Error& error_result) {
  SLOG(1) << LoggingTag() << ": " << __func__ << ": " << GetStateString(state_);
  DCHECK(stop_step_.has_value());
  switch (stop_step_.value()) {
    case StopSteps::kStopModem:
      if (capability_) {
        LOG(INFO) << LoggingTag() << ": " << __func__ << ": Calling StopModem.";
        SetState(State::kModemStopping);
        capability_->StopModem(base::BindOnce(&Cellular::StopModemCallback,
                                              weak_ptr_factory_.GetWeakPtr(),
                                              std::move(callback)));
        return;
      }
      stop_step_ = StopSteps::kModemStopped;
      [[fallthrough]];

    case StopSteps::kModemStopped:
      SetState(State::kDisabled);

      // Sockets should be destroyed here to ensure that we make new connections
      // when we next enable Cellular. Since the carrier may assign us a new IP
      // on reconnect and some carriers don't like it when packets are sent from
      // this device using the old IP, we need to make sure that we prevent
      // further packets from going out.
      DestroySockets();

      // Destroy any cellular services regardless of any errors that occur
      // during the stop process since we do not know the state of the modem at
      // this point.
      DestroyAllServices();

      // In case no termination action was executed (and
      // TerminationActionComplete was not invoked) in response to a suspend
      // request, any registered termination action needs to be removed
      // explicitly.
      manager()->RemoveTerminationAction(link_name());

      UpdateScanning();

      if (error_result.type() == Error::kWrongState) {
        // ModemManager.Modem will not respond to Stop when in a failed state.
        // Allow the callback to succeed so that Shill identifies and persists
        // Cellular as disabled. TODO(b/184974739): StopModem should probably
        // succeed when in a failed state.
        LOG(WARNING) << LoggingTag()
                     << ": StopModem returned an error: " << error_result;
        std::move(callback).Run(Error());
      } else {
        if (error_result.IsFailure())
          LOG(ERROR) << LoggingTag()
                     << ": StopModem returned an error: " << error_result;
        std::move(callback).Run(error_result);
      }
      stop_step_.reset();
      return;
  }
}

void Cellular::StartModem(EnabledStateChangedCallback callback) {
  DCHECK(capability_);
  LOG(INFO) << LoggingTag() << ": " << __func__;
  SetState(State::kModemStarting);
  capability_->StartModem(base::BindOnce(&Cellular::StartModemCallback,
                                         weak_ptr_factory_.GetWeakPtr(),
                                         std::move(callback)));
}

void Cellular::StartModemCallback(EnabledStateChangedCallback callback,
                                  const Error& error) {
  LOG(INFO) << LoggingTag() << ": " << __func__
            << ": state=" << GetStateString(state_);

  if (!error.IsSuccess()) {
    SetState(State::kEnabled);
    if (error.type() == Error::kWrongState) {
      // If the enable operation failed with Error::kWrongState, the modem is
      // in an unexpected state. This usually indicates a missing or locked
      // SIM. Invoke |callback| with no error so that the enable completes.
      // If the ModemState property later changes to 'disabled', StartModem
      // will be called again.
      LOG(WARNING) << LoggingTag() << ": StartModem failed: " << error;
      std::move(callback).Run(Error(Error::kSuccess));
    } else {
      LOG(ERROR) << LoggingTag() << ": StartModem failed: " << error;
      std::move(callback).Run(error);
    }
    return;
  }

  SetState(State::kModemStarted);

  // Registration state updates may have been ignored while the
  // modem was not yet marked enabled.
  HandleNewRegistrationState();

  metrics()->NotifyDeviceEnableFinished(interface_index());

  std::move(callback).Run(Error(Error::kSuccess));
}

void Cellular::StopModemCallback(EnabledStateChangedCallback callback,
                                 const Error& error_result) {
  LOG(INFO) << LoggingTag() << ": " << __func__ << ": "
            << GetStateString(state_) << " Error: " << error_result;
  stop_step_ = StopSteps::kModemStopped;
  StopStep(std::move(callback), error_result);
}

void Cellular::DestroySockets() {
  if (!socket_destroyer_)
    return;

  auto primary_network = GetPrimaryNetwork();
  for (const auto& address : primary_network->GetAddresses()) {
    SLOG(2) << LoggingTag() << ": Destroy all sockets of address:" << address;
    rtnl_handler()->RemoveInterfaceAddress(primary_network->interface_index(),
                                           address);
    if (!socket_destroyer_->DestroySockets(IPPROTO_TCP, address))
      SLOG(2) << LoggingTag() << ": no tcp sockets found for " << address;
    // Chrome sometimes binds to UDP sockets, so lets destroy them.
    if (!socket_destroyer_->DestroySockets(IPPROTO_UDP, address))
      SLOG(2) << LoggingTag() << ": no udp sockets found for " << address;
  }
  SLOG(2) << LoggingTag() << ": " << __func__ << " complete.";
}

void Cellular::CompleteActivation(Error* error) {
  if (capability_)
    capability_->CompleteActivation(error);
}

bool Cellular::IsUnderlyingDeviceEnabled() const {
  return IsEnabledModemState(modem_state_);
}

void Cellular::Scan(Error* error, const std::string& /*reason*/) {
  SLOG(2) << LoggingTag() << ": Scanning started";
  CHECK(error);
  if (proposed_scan_in_progress_) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInProgress,
                          "Already scanning");
    return;
  }

  if (!capability_)
    return;

  capability_->Scan(
      base::BindOnce(&Cellular::OnScanStarted, weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&Cellular::OnScanReply, weak_ptr_factory_.GetWeakPtr()));
}

void Cellular::RegisterOnNetwork(const std::string& network_id,
                                 ResultCallback callback) {
  if (!capability_) {
    std::move(callback).Run(Error(Error::Type::kOperationFailed));
    return;
  }
  capability_->RegisterOnNetwork(network_id, std::move(callback));
}

void Cellular::RequirePin(const std::string& pin,
                          bool require,
                          ResultCallback callback) {
  SLOG(2) << LoggingTag() << ": " << __func__ << ": " << require;
  if (!capability_) {
    std::move(callback).Run(Error(Error::Type::kOperationFailed));
    return;
  }
  capability_->RequirePin(pin, require, std::move(callback));
}

void Cellular::EnterPin(const std::string& pin, ResultCallback callback) {
  SLOG(2) << LoggingTag() << ": " << __func__;
  if (!capability_) {
    std::move(callback).Run(Error(Error::Type::kOperationFailed));
    return;
  }
  capability_->EnterPin(pin, std::move(callback));
}

void Cellular::UnblockPin(const std::string& unblock_code,
                          const std::string& pin,
                          ResultCallback callback) {
  SLOG(2) << LoggingTag() << ": " << __func__;
  if (!capability_) {
    std::move(callback).Run(Error(Error::Type::kOperationFailed));
    return;
  }
  capability_->UnblockPin(unblock_code, pin, std::move(callback));
}

void Cellular::ChangePin(const std::string& old_pin,
                         const std::string& new_pin,
                         ResultCallback callback) {
  SLOG(2) << LoggingTag() << ": " << __func__;
  if (!capability_) {
    std::move(callback).Run(Error(Error::Type::kOperationFailed));
    return;
  }
  capability_->ChangePin(old_pin, new_pin, std::move(callback));
}

void Cellular::Reset(ResultCallback callback) {
  SLOG(2) << LoggingTag() << ": " << __func__;

  // Qualcomm q6v5 modems on trogdor do not support reset using qmi messages.
  // As per QC the only way to reset the modem is to use the sysfs interface.
  if (IsQ6V5Modem()) {
    if (!ResetQ6V5Modem()) {
      std::move(callback).Run(Error(Error::Type::kOperationFailed));
    } else {
      std::move(callback).Run(Error(Error::Type::kSuccess));
    }
    return;
  }

  if (!capability_) {
    std::move(callback).Run(Error(Error::Type::kOperationFailed));
    return;
  }
  capability_->Reset(std::move(callback));
}

void Cellular::DropConnection() {
  if (ppp_device_) {
    // For PPP dongles, IP configuration is handled on the |ppp_device_|,
    // rather than the netdev plumbed into |this|.
    ppp_device_->DropConnection();
  } else {
    SetPrimaryMultiplexedInterface("");
    Device::DropConnection();
  }
}

void Cellular::SetServiceState(Service::ConnectState state) {
  if (ppp_device_) {
    ppp_device_->SetServiceState(state);
  } else if (selected_service()) {
    Device::SetServiceState(state);
  } else if (service_) {
    service_->SetState(state);
  } else {
    LOG(WARNING) << LoggingTag() << ": State change with no Service.";
  }
}

void Cellular::SetServiceFailure(Service::ConnectFailure failure_state) {
  LOG(WARNING) << LoggingTag() << ": " << __func__ << ": "
               << Service::ConnectFailureToString(failure_state);
  if (ppp_device_) {
    ppp_device_->SetServiceFailure(failure_state);
  } else if (selected_service()) {
    Device::SetServiceFailure(failure_state);
  } else if (service_) {
    service_->SetFailure(failure_state);
  } else {
    LOG(WARNING) << LoggingTag() << ": State change with no Service.";
  }
}

void Cellular::SetServiceFailureSilent(Service::ConnectFailure failure_state) {
  SLOG(2) << LoggingTag() << ": " << __func__ << ": "
          << Service::ConnectFailureToString(failure_state);
  if (ppp_device_) {
    ppp_device_->SetServiceFailureSilent(failure_state);
  } else if (selected_service()) {
    Device::SetServiceFailureSilent(failure_state);
  } else if (service_) {
    service_->SetFailureSilent(failure_state);
  } else {
    LOG(WARNING) << LoggingTag() << ": State change with no Service.";
  }
}

void Cellular::OnConnected() {
  if (StateIsConnected()) {
    SLOG(1) << LoggingTag() << ": " << __func__ << ": Already connected";
    return;
  }
  SLOG(1) << LoggingTag() << ": " << __func__;
  SetState(State::kConnected);
  if (!service_) {
    LOG(INFO) << LoggingTag() << ": Disconnecting due to no cellular service.";
    Disconnect(nullptr, "no cellular service");
  } else if (service_->IsRoamingRuleViolated()) {
    // TODO(pholla): This logic is probably unreachable since we have two gate
    // keepers that prevent this scenario.
    // a) Cellular::Connect prevents connects if roaming rules are violated.
    // b) CellularCapability3gpp::FillConnectPropertyMap will not allow MM to
    //    connect to roaming networks.
    LOG(INFO) << LoggingTag() << ": Disconnecting due to roaming.";
    Disconnect(nullptr, "roaming disallowed");
  } else {
    EstablishLink();
  }
}

void Cellular::OnBeforeSuspend(ResultCallback callback) {
  LOG(INFO) << LoggingTag() << ": " << __func__;
  Error error;
  StopPPP();
  if (capability_)
    capability_->SetModemToLowPowerModeOnModemStop(true);
  SetEnabledNonPersistent(false, std::move(callback));
}

void Cellular::OnAfterResume() {
  SLOG(2) << LoggingTag() << ": " << __func__;
  if (enabled_persistent()) {
    LOG(INFO) << LoggingTag() << ": Restarting modem after resume.";
    // TODO(b/216847428): replace this with a real toggle
    SetEnabledUnchecked(true, base::BindOnce(LogRestartModemResult));
  }

  // TODO(quiche): Consider if this should be conditional. If, e.g.,
  // the device was still disabling when we suspended, will trying to
  // renew DHCP here cause problems?
  Device::OnAfterResume();
}

void Cellular::UpdateGeolocationObjects(
    std::vector<GeolocationInfo>* geolocation_infos) const {
  const std::string& mcc = location_info_.mcc;
  const std::string& mnc = location_info_.mnc;
  const std::string& lac = location_info_.lac;
  const std::string& cid = location_info_.ci;

  GeolocationInfo geolocation_info;

  if (!(mcc.empty() || mnc.empty() || lac.empty() || cid.empty())) {
    geolocation_info[kGeoMobileCountryCodeProperty] = mcc;
    geolocation_info[kGeoMobileNetworkCodeProperty] = mnc;
    geolocation_info[kGeoLocationAreaCodeProperty] = lac;
    geolocation_info[kGeoCellIdProperty] = cid;
    // kGeoTimingAdvanceProperty currently unused in geolocation API
  }
  // Else we have either an incomplete location, no location yet,
  // or some unsupported location type, so don't return something incorrect.
  geolocation_infos->clear();
  geolocation_infos->push_back(geolocation_info);
}

void Cellular::ConfigureAttachApn() {
  SLOG(1) << LoggingTag() << ": " << __func__;
  if (!enabled() && !enabled_pending()) {
    LOG(WARNING) << LoggingTag() << ": " << __func__
                 << ": Modem not enabled, skip attach APN configuration.";
    return;
  }

  capability_->ConfigureAttachApn();
}

// TODO(b/267804414): Reattach is only used by |TetheringAllowedUpdated|,
// which is a temporary function for tethering fishfooding.
void Cellular::ReAttach() {
  SLOG(1) << LoggingTag() << ": " << __func__;
  if (!enabled() && !enabled_pending()) {
    LOG(WARNING) << LoggingTag() << ": " << __func__
                 << ": Modem not enabled, skipped re-attach.";
    return;
  }

  capability_->SetModemToLowPowerModeOnModemStop(false);
  Error error;
  SetEnabledNonPersistent(false,
                          base::BindOnce(&Cellular::ReAttachOnDetachComplete,
                                         weak_ptr_factory_.GetWeakPtr()));
}

void Cellular::ReAttachOnDetachComplete(const Error& error) {
  SLOG(2) << LoggingTag() << ": " << __func__;
  // Reset the flag to its default value.
  capability_->SetModemToLowPowerModeOnModemStop(true);
  if (error.IsSuccess()) {
    LOG(INFO) << LoggingTag() << ": Restarting modem for re-attach.";
    SetEnabledNonPersistent(true, base::BindOnce(LogRestartModemResult));
  } else {
    LOG(WARNING) << LoggingTag() << ": Detaching the modem failed: " << error;
  }
}

void Cellular::CancelPendingConnect() {
  ConnectToPendingFailed(Service::kFailureDisconnect);
}

void Cellular::OnScanStarted() {
  proposed_scan_in_progress_ = true;
  UpdateScanning();
}

void Cellular::OnScanReply(const Stringmaps& found_networks,
                           const Error& error) {
  SLOG(2) << LoggingTag() << ": Scanning completed";
  proposed_scan_in_progress_ = false;
  UpdateScanning();

  // TODO(jglasgow): fix error handling.
  // At present, there is no way of notifying user of this asynchronous error.
  if (error.IsFailure()) {
    error.Log();
    if (!found_networks_.empty())
      SetFoundNetworks(Stringmaps());
    return;
  }

  SetFoundNetworks(found_networks);
}

// Called from an asyc D-Bus function
// Relies on location handler to fetch relevant value from map
void Cellular::GetLocationCallback(const std::string& gpp_lac_ci_string,
                                   const Error& error) {
  // Expects string of form "MCC,MNC,LAC,CI"
  SLOG(2) << LoggingTag() << ": " << __func__ << ": " << gpp_lac_ci_string;
  std::vector<std::string> location_vec = SplitString(
      gpp_lac_ci_string, ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  if (location_vec.size() < 4) {
    LOG(ERROR) << LoggingTag() << ": "
               << "Unable to parse location string " << gpp_lac_ci_string;
    return;
  }
  location_info_.mcc = location_vec[0];
  location_info_.mnc = location_vec[1];
  location_info_.lac = location_vec[2];
  location_info_.ci = location_vec[3];

  // Alert manager that location has been updated.
  manager()->OnDeviceGeolocationInfoUpdated(this);
}

void Cellular::PollLocationTask() {
  SLOG(4) << LoggingTag() << ": " << __func__;

  PollLocation();

  poll_location_task_.Reset(base::BindOnce(&Cellular::PollLocationTask,
                                           weak_ptr_factory_.GetWeakPtr()));
  dispatcher()->PostDelayedTask(FROM_HERE, poll_location_task_.callback(),
                                kPollLocationInterval);
}

void Cellular::PollLocation() {
  if (!capability_)
    return;
  capability_->GetLocation(base::BindOnce(&Cellular::GetLocationCallback,
                                          weak_ptr_factory_.GetWeakPtr()));
}

void Cellular::HandleNewSignalQuality(uint32_t strength) {
  SLOG(2) << LoggingTag() << ": Signal strength: " << strength;
  if (service_) {
    service_->SetStrength(strength);
  }
}

void Cellular::HandleNewRegistrationState() {
  SLOG(2) << LoggingTag() << ": " << __func__
          << ": state = " << GetStateString(state_);

  CHECK(capability_);
  if (!capability_->IsRegistered()) {
    if (!explicit_disconnect_ && StateIsConnected() && service_.get()) {
      // TODO(b/200584652): Remove after January 2024
      if (capability_->GetNetworkTechnologyString() == "")
        LOG(INFO) << LoggingTag() << ": Logging Drop connection on unknown "
                  << "cellular technology";

      metrics()->NotifyCellularDeviceDrop(
          capability_->GetNetworkTechnologyString(), service_->strength());
    }
    if (StateIsRegistered()) {
      // If the state is moving out of Connected/Linked clean up IP/networking.
      OnDisconnected();
      SetState(State::kEnabled);
    }
    StopLocationPolling();
    return;
  }

  switch (state_) {
    case State::kDisabled:
    case State::kModemStarting:
    case State::kModemStopping:
      // Defer updating Services while disabled and during transitions.
      return;
    case State::kEnabled:
      LOG(WARNING) << LoggingTag() << ": Capability is registered but "
                   << "State=Enabled. Setting to Registered. ModemState="
                   << GetModemStateString(modem_state_);
      SetRegistered();
      break;
    case State::kModemStarted:
      SetRegistered();
      break;
    case State::kRegistered:
    case State::kConnected:
    case State::kLinked:
      // Already registered
      break;
  }

  UpdateServices();
}

void Cellular::SetRegistered() {
  DCHECK(!StateIsRegistered());
  SetState(State::kRegistered);
  // Once the modem becomes registered, begin polling location; registered means
  // we've successfully connected
  StartLocationPolling();
}

void Cellular::UpdateServices() {
  SLOG(2) << LoggingTag() << ": " << __func__;
  // When Disabled, ensure all services are destroyed except when ModemState is:
  //  * Locked: The primary SIM is locked and the modem has not started.
  //  * Failed: No valid SIM in the primary slot.
  // In these cases we want to create any services we know about for the UI.
  if (state_ == State::kDisabled && modem_state_ != kModemStateLocked &&
      modem_state_ != kModemStateFailed) {
    DestroyAllServices();
    return;
  }

  // If iccid_ is empty, the primary slot is not set, so do not create a
  // primary service. CreateSecondaryServices() will have been called in
  // SetSimProperties(). Just ensure that the Services are updated.
  if (iccid_.empty()) {
    manager()->cellular_service_provider()->UpdateServices(this);
    return;
  }

  // Ensure that a Service matching the Device SIM Profile exists and has its
  // |connectable_| property set correctly.
  if (!service_ || service_->iccid() != iccid_) {
    CreateServices();
  } else {
    manager()->cellular_service_provider()->UpdateServices(this);
  }

  if (state_ == State::kRegistered && modem_state_ == kModemStateConnected)
    OnConnected();

  service_->SetNetworkTechnology(capability_->GetNetworkTechnologyString());
  service_->SetRoamingState(capability_->GetRoamingStateString());
  manager()->UpdateService(service_);
  ConnectToPending();
}

void Cellular::CreateServices() {
  if (service_for_testing_)
    return;

  if (service_ && service_->iccid() == iccid_) {
    LOG(ERROR) << LoggingTag() << ": " << __func__
               << ": Service already exists for ICCID.";
    return;
  }

  CHECK(capability_);
  DCHECK(manager()->cellular_service_provider());

  // Create or update Cellular Services for the primary SIM.
  service_ =
      manager()->cellular_service_provider()->LoadServicesForDevice(this);
  LOG(INFO) << LoggingTag() << ": " << __func__
            << ": Service=" << service_->log_name();

  // Create or update Cellular Services for secondary SIMs.
  UpdateSecondaryServices();

  capability_->OnServiceCreated();

  // Ensure operator properties are updated.
  OnOperatorChanged();
}

void Cellular::DestroyAllServices() {
  LOG(INFO) << LoggingTag() << ": " << __func__;
  DropConnection();

  if (service_for_testing_)
    return;

  DCHECK(manager()->cellular_service_provider());
  manager()->cellular_service_provider()->RemoveServices();
  service_ = nullptr;
}

void Cellular::UpdateSecondaryServices() {
  for (const SimProperties& sim_properties : sim_slot_properties_) {
    if (sim_properties.iccid.empty() || sim_properties.iccid == iccid_)
      continue;
    manager()->cellular_service_provider()->LoadServicesForSecondarySim(
        sim_properties.eid, sim_properties.iccid, sim_properties.imsi, this);
  }

  // Remove any Services no longer associated with a SIM slot.
  manager()->cellular_service_provider()->RemoveNonDeviceServices(this);
}

void Cellular::OnModemDestroyed() {
  SLOG(1) << LoggingTag() << ": " << __func__;
  StopLocationPolling();
  DestroyCapability();
  // Clear the dbus path.
  SetDbusPath(shill::RpcIdentifier());

  // Under certain conditions, Cellular::StopModem may not be called before
  // the Modem object is destroyed. This happens if the dbus modem exported
  // by the modem-manager daemon disappears soon after the modem is disabled,
  // not giving Shill enough time to complete the disable operation.
  // In that case, the termination action associated with this cellular object
  // may not have been removed.
  manager()->RemoveTerminationAction(link_name());
}

void Cellular::CreateCapability() {
  SLOG(1) << LoggingTag() << ": " << __func__;
  CHECK(!capability_);
  capability_ = std::make_unique<CellularCapability3gpp>(
      this, manager()->control_interface(), manager()->metrics(),
      manager()->modem_info()->pending_activation_store());
  if (initial_properties_.has_value()) {
    SetInitialProperties(*initial_properties_);
    initial_properties_ = std::nullopt;
  }

  mobile_operator_info_->AddObserver(this);

  // If Cellular::Start has not been called, or Cellular::Stop has been called,
  // we still want to create the capability, but not call StartModem.
  if (state_ == State::kModemStopping || state_ == State::kDisabled)
    return;

  StartModem(base::DoNothing());

  // Update device state that might have been pending
  // due to the lack of |capability_| during Cellular::Start().
  UpdateEnabledState();
}

void Cellular::DestroyCapability() {
  SLOG(1) << LoggingTag() << ": " << __func__;

  mobile_operator_info_->RemoveObserver(this);
  // When there is a SIM swap, ModemManager destroys and creates a new modem
  // object. Reset the mobile operator info to avoid stale data.
  mobile_operator_info()->Reset();

  // Make sure we are disconnected.
  StopPPP();
  DisconnectCleanup();

  // |service_| holds a pointer to |this|. We need to disassociate it here so
  // that |this| will be destroyed if the interface is removed.
  if (service_) {
    service_->SetDevice(nullptr);
    service_ = nullptr;
  }

  capability_.reset();

  if (state_ != State::kDisabled)
    SetState(State::kEnabled);
  SetModemState(kModemStateUnknown);
}

bool Cellular::GetConnectable(CellularService* service) const {
  // Check |iccid_| in case sim_slot_properties_ have not been set.
  if (service->iccid() == iccid_)
    return true;
  // If the Service ICCID matches the ICCID in any slot, that Service can be
  // connected to (by changing the active slot if necessary).
  for (const SimProperties& sim_properties : sim_slot_properties_) {
    if (sim_properties.iccid == service->iccid())
      return true;
  }
  return false;
}

void Cellular::NotifyCellularConnectionResult(const Error& error,
                                              const std::string& iccid,
                                              bool is_user_triggered,
                                              ApnList::ApnType apn_type) {
  SLOG(3) << LoggingTag() << ": " << __func__ << ": Result: " << error.type();
  // Don't report successive failures on the same SIM when the `Connect` is
  // triggered by `AutoConnect`, and the failures are the same.
  if (error.type() != Error::kSuccess && !is_user_triggered &&
      last_cellular_connection_results_.count(iccid) > 0 &&
      error.type() == last_cellular_connection_results_[iccid]) {
    SLOG(3) << LoggingTag() << ": "
            << " Skipping repetitive failure metric. Error: "
            << error.message();
    return;
  }
  metrics()->NotifyCellularConnectionResult(error.type(), apn_type);
  last_cellular_connection_results_[iccid] = error.type();
  if (error.IsSuccess()) {
    return;
  }
  // used by anomaly detector for cellular subsystem crashes
  LOG(ERROR) << LoggingTag() << ": " << GetFriendlyModelId(model_id_)
             << " could not connect (trigger="
             << (is_user_triggered ? "dbus" : "auto")
             << ") to mccmnc=" << mobile_operator_info_->mccmnc() << ": "
             << error.message();
}

void Cellular::NotifyDetailedCellularConnectionResult(
    const Error& error,
    ApnList::ApnType apn_type,
    const shill::Stringmap& apn_info) {
  CHECK(service_);
  SLOG(3) << LoggingTag() << ": " << __func__ << ": Result:" << error.type();

  auto ipv4 = CellularBearer::IPConfigMethod::kUnknown;
  auto ipv6 = CellularBearer::IPConfigMethod::kUnknown;
  uint32_t tech_used = MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN;
  uint32_t iccid_len = 0;
  SimType sim_type = kSimTypeUnknown;
  brillo::ErrorPtr detailed_error;
  std::string cellular_error;
  bool use_apn_revamp_ui = false;
  std::string iccid = service_->iccid();

  std::string roaming_state;
  if (service_) {
    roaming_state = service_->roaming_state();
    iccid_len = service_->iccid().length();
    use_apn_revamp_ui = service_->custom_apn_list().has_value();
    // If EID is not empty, report as eSIM else report as pSIM
    if (!service_->eid().empty())
      sim_type = kSimTypeEsim;
    else
      sim_type = kSimTypePsim;
  }

  if (capability_) {
    tech_used = capability_->GetActiveAccessTechnologies();
    CellularBearer* bearer = capability_->GetActiveBearer(apn_type);
    if (bearer) {
      ipv4 = bearer->ipv4_config_method();
      ipv6 = bearer->ipv6_config_method();
    }
  }

  error.ToDetailedError(&detailed_error);
  if (detailed_error != nullptr)
    cellular_error = detailed_error->GetCode();

  SLOG(3) << LoggingTag() << ": Cellular Error:" << cellular_error;

  if (error.IsSuccess()) {
    subscription_error_seen_[iccid] = false;
  }

  Metrics::DetailedCellularConnectionResult result;
  result.error = error.type();
  result.detailed_error = cellular_error;
  result.uuid = mobile_operator_info_->uuid();
  result.apn_info = apn_info;
  result.ipv4_config_method = BearerIPConfigMethodToMetrics(ipv4);
  result.ipv6_config_method = BearerIPConfigMethodToMetrics(ipv6);
  result.home_mccmnc = mobile_operator_info_->mccmnc();
  result.serving_mccmnc = mobile_operator_info_->serving_mccmnc();
  result.roaming_state = roaming_state;
  result.use_apn_revamp_ui = use_apn_revamp_ui;
  result.tech_used = tech_used;
  result.iccid_length = iccid_len;
  result.sim_type = sim_type;
  result.gid1 = mobile_operator_info_->gid1();
  result.connection_attempt_type = ConnectionAttemptTypeToMetrics(service_);
  result.subscription_error_seen = subscription_error_seen_[iccid];
  result.modem_state = modem_state_;
  result.interface_index = interface_index();
  metrics()->NotifyDetailedCellularConnectionResult(result);

  // Update if we reported subscription error for this card so that
  // subsequent errors report subscription_error_seen=true.
  // This is needed because when connection attempt fail with
  // serviceOptionNotSubscribed error which in most cases indicate issues
  // related to user data plan, subsequent connection attempts fails with
  // different error codes, making analysis of metrics difficult.
  if (IsSubscriptionError(cellular_error)) {
    subscription_error_seen_[iccid] = true;
  }
}

void Cellular::Connect(CellularService* service, Error* error) {
  CHECK(service);
  LOG(INFO) << LoggingTag() << ": " << __func__ << ": " << service->log_name();

  const ApnList::ApnType apn_type = ApnList::ApnType::kDefault;
  if (!capability_) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kWrongState,
                          "Connect Failed: Modem not available.");
    NotifyCellularConnectionResult(*error, service->iccid(),
                                   service->is_in_user_connect(), apn_type);
    return;
  }

  if (inhibited_) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kWrongState,
                          "Connect Failed: Inhibited.");
    NotifyCellularConnectionResult(*error, service->iccid(),
                                   service->is_in_user_connect(), apn_type);
    return;
  }

  if (!connect_pending_iccid_.empty() &&
      connect_pending_iccid_ == service->iccid()) {
    Error error_temp = Error(Error::kWrongState, "Connect already pending.");
    LOG(WARNING) << LoggingTag() << ": " << error_temp.message();
    NotifyCellularConnectionResult(error_temp, service->iccid(),
                                   service->is_in_user_connect(), apn_type);
    return;
  }

  if (service->iccid() != iccid_) {
    // If the Service has a different ICCID than the current one, Disconnect
    // from the current Service if connected, switch to the correct SIM slot,
    // and set |connect_pending_iccid_|. The Connect will be retried after the
    // slot change completes (which may take a while).
    if (StateIsConnected())
      Disconnect(nullptr, "switching service");
    if (capability_->SetPrimarySimSlotForIccid(service->iccid())) {
      SetPendingConnect(service->iccid());
    } else {
      Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                            "Connect Failed: ICCID not available.");
      NotifyCellularConnectionResult(*error, service->iccid(),
                                     service->is_in_user_connect(), apn_type);
    }
    return;
  }

  if (scanning_) {
    LOG(INFO) << LoggingTag() << ": "
              << "Cellular is scanning. Pending connect to: "
              << service->log_name();
    SetPendingConnect(service->iccid());
    return;
  }

  if (!StateIsStarted()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                          "Connect Failed: Modem not started.");
    NotifyCellularConnectionResult(*error, service->iccid(),
                                   service->is_in_user_connect(), apn_type);
    return;
  }

  if (StateIsConnected()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kAlreadyConnected,
                          "Already connected; connection request ignored.");
    NotifyCellularConnectionResult(*error, service->iccid(),
                                   service->is_in_user_connect(), apn_type);
    return;
  }

  if (ModemIsEnabledButNotRegistered()) {
    LOG(WARNING) << LoggingTag() << ": " << __func__
                 << ": Waiting for Modem registration.";
    SetPendingConnect(service->iccid());
    return;
  }

  if (state_ != State::kRegistered) {
    LOG(ERROR) << LoggingTag() << ": Connect attempted while state = "
               << GetStateString(state_);
    Error::PopulateAndLog(FROM_HERE, error, Error::kNotRegistered,
                          "Connect Failed: Modem not registered.");
    NotifyCellularConnectionResult(*error, service->iccid(),
                                   service->is_in_user_connect(), apn_type);
    // If using an attach APN, send detailed metrics since |kNotRegistered| is
    // a very common error when using Attach APNs.
    if (service->GetLastAttachApn())
      NotifyDetailedCellularConnectionResult(*error, apn_type,
                                             *service->GetLastAttachApn());
    return;
  }

  if (service->IsRoamingRuleViolated()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kNotOnHomeNetwork,
                          "Connect Failed: Roaming disallowed.");
    NotifyCellularConnectionResult(*error, service->iccid(),
                                   service->is_in_user_connect(), apn_type);
    return;
  }

  // Build default APN list, guaranteed to never be empty.
  std::deque<Stringmap> apn_try_list = BuildDefaultApnTryList();
  CHECK(!apn_try_list.empty());

  OnConnecting();
  capability_->Connect(
      apn_type, apn_try_list,
      base::BindOnce(&Cellular::OnConnectReply, weak_ptr_factory_.GetWeakPtr(),
                     service->iccid(), service->is_in_user_connect()));

  metrics()->NotifyDeviceConnectStarted(interface_index());
}

// Note that there's no ResultCallback argument to this since Connect() isn't
// yet passed one.
void Cellular::OnConnectReply(std::string iccid,
                              bool is_user_triggered,
                              const Error& error) {
  NotifyCellularConnectionResult(error, iccid, is_user_triggered,
                                 ApnList::ApnType::kDefault);
  if (!error.IsSuccess()) {
    LOG(WARNING) << LoggingTag() << ": " << __func__ << ": Failed: " << error;
    if (service_ && service_->iccid() == iccid) {
      if (error.type() == Error::kInvalidApn)
        service_->SetFailure(Service::kFailureInvalidAPN);
      else
        service_->SetFailure(Service::kFailureConnect);
    }
    return;
  }
  metrics()->NotifyDeviceConnectFinished(interface_index());
  OnConnected();
}

void Cellular::OnEnabled() {
  SLOG(1) << LoggingTag() << ": " << __func__;
  manager()->AddTerminationAction(
      link_name(), base::BindOnce(&Cellular::StartTermination,
                                  weak_ptr_factory_.GetWeakPtr()));
  if (!enabled() && !enabled_pending()) {
    LOG(WARNING) << LoggingTag() << ": OnEnabled called while not enabling, "
                 << "setting enabled.";
    SetEnabled(true);
  }
}

void Cellular::OnConnecting() {
  if (service_)
    service_->SetState(Service::kStateAssociating);
}

void Cellular::Disconnect(Error* error, const char* reason) {
  SLOG(1) << LoggingTag() << ": " << __func__ << ": " << reason;
  if (!StateIsConnected()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kNotConnected,
                          "Not connected; request ignored.");
    return;
  }
  if (!capability_) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                          "Modem not available.");
    return;
  }
  StopPPP();
  explicit_disconnect_ = true;
  capability_->DisconnectAll(base::BindOnce(&Cellular::OnDisconnectReply,
                                            weak_ptr_factory_.GetWeakPtr()));
}

void Cellular::OnDisconnectReply(const Error& error) {
  explicit_disconnect_ = false;
  if (!error.IsSuccess()) {
    LOG(WARNING) << LoggingTag() << ": " << __func__ << ": Failed: " << error;
    OnDisconnectFailed();
    return;
  }
  OnDisconnected();
}

void Cellular::OnDisconnected() {
  SLOG(1) << LoggingTag() << ": " << __func__;
  if (!DisconnectCleanup()) {
    LOG(WARNING) << LoggingTag() << ": Disconnect occurred while in state "
                 << GetStateString(state_);
  }
}

void Cellular::OnDisconnectFailed() {
  SLOG(1) << LoggingTag() << ": " << __func__;
  // If the modem is in the disconnecting state, then the disconnect should
  // eventually succeed, so do nothing.
  if (modem_state_ == kModemStateDisconnecting) {
    LOG(INFO) << LoggingTag()
              << ": Ignoring failed disconnect while modem is disconnecting.";
    return;
  }

  // OnDisconnectFailed got called because no bearers to disconnect were found.
  // Which means that we shouldn't really remain in the connected/linked state
  // if we are in one of those.
  if (!DisconnectCleanup()) {
    // otherwise, no-op
    LOG(WARNING) << LoggingTag()
                 << ": Ignoring failed disconnect while in state "
                 << GetStateString(state_);
  }

  // TODO(armansito): In either case, shill ends up thinking that it's
  // disconnected, while for some reason the underlying modem might still
  // actually be connected. In that case the UI would be reflecting an incorrect
  // state and a further connection request would fail. We should perhaps tear
  // down the modem and restart it here.
}

void Cellular::EstablishLink() {
  if (skip_establish_link_for_testing_) {
    return;
  }

  SLOG(2) << LoggingTag() << ": " << __func__;
  CHECK_EQ(State::kConnected, state_);
  CHECK(capability_);

  CellularBearer* bearer =
      capability_->GetActiveBearer(ApnList::ApnType::kDefault);
  if (!bearer) {
    LOG(WARNING) << LoggingTag()
                 << ": Disconnecting due to missing active bearer.";
    Disconnect(nullptr, "missing active bearer");
    return;
  }

  // The APN type is ensured to be one by GetActiveBearer()
  CHECK_EQ(bearer->apn_types().size(), 1UL);
  CHECK_EQ(bearer->apn_types()[0], ApnList::ApnType::kDefault);

  if (bearer->ipv4_config_method() == CellularBearer::IPConfigMethod::kPPP) {
    LOG(INFO) << LoggingTag() << ": Start PPP connection on "
              << bearer->data_interface();
    StartPPP(bearer->data_interface());
    return;
  }

  // ModemManager specifies which is the network interface that has been
  // connected at this point, which may be either the same interface that was
  // used to reference this Cellular device, or a completely different one.
  // At this point, only the physical network interface is expected to be
  // connected; fail otherwise.
  LOG(INFO) << LoggingTag() << ": Establish link on "
            << bearer->data_interface();
  int data_interface_index =
      rtnl_handler()->GetInterfaceIndex(bearer->data_interface());
  if (data_interface_index != interface_index()) {
    Disconnect(nullptr, "Unexpected data interface to connect");
    return;
  }

  // Start the link listener, which will ensure the initial link state for the
  // data interface is notified.
  StartLinkListener();

  // Set state to associating.
  OnConnecting();
}

void Cellular::LinkUp(int data_interface_index) {
  DCHECK(data_interface_index == interface_index());

  if (state_ != State::kConnected) {
    SLOG(3) << LoggingTag() << ": Link is up.";
    return;
  }

  // Connected -> Linked transition launches Network creation
  LOG(INFO) << LoggingTag() << ": Link is up.";
  SetPrimaryMultiplexedInterface(link_name());
  SetState(State::kLinked);

  CHECK(capability_);
  CellularBearer* bearer =
      capability_->GetActiveBearer(ApnList::ApnType::kDefault);
  if (!bearer) {
    LOG(WARNING) << LoggingTag() << ": No bearer found";
    // TODO(b/282250501): Update Cellular interface IP configurations.
    // Add disconnect here.
    return;
  }
  bool ipv6_configured = false;
  bool ipv4_configured = false;
  std::unique_ptr<IPConfig::Properties> static_ipv4_props;
  std::optional<DHCPProvider::Options> dhcp_opts = std::nullopt;
  // Some modems use kMethodStatic and some use kMethodDHCP for IPv6 config
  if (bearer->ipv6_config_method() !=
      CellularBearer::IPConfigMethod::kUnknown) {
    SLOG(2) << LoggingTag()
            << ": Assign static IPv6 configuration from bearer.";
    const auto& ipv6_props = *bearer->ipv6_config_properties();
    // Only apply static config if the address is link local. This is a
    // workaround for b/230336493.
    const auto link_local_mask =
        IPAddress::CreateFromStringAndPrefix("fe80::", 10);
    CHECK(link_local_mask.has_value());
    const auto local = IPAddress::CreateFromString(ipv6_props.address);
    if (!local.has_value()) {
      LOG(ERROR) << "IPv6 address is not valid: " << ipv6_props.address;
    } else if (link_local_mask->CanReachAddress(*local)) {
      GetPrimaryNetwork()->set_ipv6_static_properties(
          std::make_unique<IPConfig::Properties>(ipv6_props));
    }
    ipv6_configured = true;
  }

  if (bearer->ipv4_config_method() == CellularBearer::IPConfigMethod::kStatic) {
    SLOG(2) << LoggingTag()
            << ": Assign static IPv4 configuration from bearer.";
    // Override the MTU with a given limit for a specific serving operator
    // if the network doesn't report something lower.
    static_ipv4_props = std::make_unique<IPConfig::Properties>(
        *bearer->ipv4_config_properties());
    if (mobile_operator_info_ &&
        mobile_operator_info_->mtu() != IPConfig::kUndefinedMTU &&
        (static_ipv4_props->mtu == IPConfig::kUndefinedMTU ||
         mobile_operator_info_->mtu() < static_ipv4_props->mtu)) {
      static_ipv4_props->mtu = mobile_operator_info_->mtu();
    }
    ipv4_configured = true;
  } else if (bearer->ipv4_config_method() ==
             CellularBearer::IPConfigMethod::kDHCP) {
    if (capability_->IsModemL850()) {
      LOG(WARNING) << LoggingTag()
                   << ": DHCP configuration not supported on L850"
                      " (Ignoring kDHCP).";
    } else {
      dhcp_opts = manager()->CreateDefaultDHCPOption();
      dhcp_opts->use_arp_gateway = false;
      dhcp_opts->use_rfc_8925 = false;
      ipv4_configured = true;
    }
  }

  if (!ipv6_configured && !ipv4_configured) {
    LOG(WARNING) << LoggingTag()
                 << ": No supported IP configuration found in bearer";
    // TODO(b/282250501): Update Cellular interface IP configurations.
    // Add disconnect here.
  }
  Network::StartOptions opts = {
      .dhcp = dhcp_opts,
      .accept_ra = true,
      // TODO(b/234300343#comment43): Read probe URL override configuration
      // from shill APN dB.
      .probing_configuration =
          manager()->GetPortalDetectorProbingConfiguration(),
  };
  SelectService(service_);
  SetServiceState(Service::kStateConfiguring);
  GetPrimaryNetwork()->set_link_protocol_ipv4_properties(
      std::move(static_ipv4_props));
  GetPrimaryNetwork()->Start(opts);
}

void Cellular::LinkDown(int data_interface_index) {
  DCHECK(data_interface_index == interface_index());

  if (state_ == State::kLinked) {
    LOG(INFO) << LoggingTag() << ": Link is down, disconnecting.";
    Disconnect(nullptr, "link is down.");
    return;
  }

  if (state_ == State::kConnected) {
    LOG(INFO) << LoggingTag() << ": Link is down, bringing up.";
    rtnl_handler()->SetInterfaceFlags(data_interface_index, IFF_UP, IFF_UP);
    return;
  }

  SLOG(3) << LoggingTag() << ": Link is down.";
}

void Cellular::LinkDeleted(int data_interface_index) {
  DCHECK(data_interface_index == interface_index());
  LOG(INFO) << LoggingTag() << ": Link is deleted.";
  // This is an indication that the cellular device is gone from the system.
  DestroyAllServices();
}

void Cellular::LinkMsgHandler(const RTNLMessage& msg) {
  DCHECK(msg.type() == RTNLMessage::kTypeLink);

  int data_interface_index = msg.interface_index();
  if (data_interface_index != interface_index())
    return;

  if (msg.mode() == RTNLMessage::kModeDelete) {
    LinkDeleted(data_interface_index);
    return;
  }

  if (msg.mode() == RTNLMessage::kModeAdd) {
    if (msg.link_status().flags & IFF_UP) {
      LinkUp(data_interface_index);
    } else {
      LinkDown(data_interface_index);
    }
    return;
  }

  LOG(WARNING) << LoggingTag()
               << ": Unexpected link message mode: " << msg.mode();
}

void Cellular::StopLinkListener() {
  link_listener_.reset(nullptr);
}

void Cellular::StartLinkListener() {
  SLOG(2) << LoggingTag() << ": Started RTNL listener";
  link_listener_.reset(new RTNLListener(
      RTNLHandler::kRequestLink,
      base::BindRepeating(&Cellular::LinkMsgHandler, base::Unretained(this))));
  rtnl_handler()->RequestDump(RTNLHandler::kRequestLink);
}

void Cellular::SetInitialProperties(const InterfaceToProperties& properties) {
  if (!capability_) {
    LOG(WARNING) << LoggingTag() << ": SetInitialProperties with no Capability";
    initial_properties_ = properties;
    return;
  }
  capability_->SetInitialProperties(properties);
}

void Cellular::OnModemStateChanged(ModemState new_state) {
  ModemState old_modem_state = modem_state_;
  if (old_modem_state == new_state) {
    SLOG(3) << LoggingTag()
            << ": The new state matches the old state. Nothing to do.";
    return;
  }

  SLOG(1) << LoggingTag() << ": " << __func__
          << ": State: " << GetStateString(state_)
          << " ModemState: " << GetModemStateString(new_state);
  SetModemState(new_state);
  CHECK(capability_);

  if (old_modem_state >= kModemStateRegistered &&
      modem_state_ < kModemStateRegistered) {
    if (state_ == State::kModemStarting) {
      // Avoid un-registering the modem while the Capability is starting the
      // Modem to prevent unexpected spurious state changes.
      // TODO(stevenjb): Audit logs and remove or tighten this logic.
      LOG(WARNING) << LoggingTag()
                   << ": Modem state change while capability starting, "
                   << " ModemState: " << GetModemStateString(new_state);
    } else {
      capability_->SetUnregistered(modem_state_ == kModemStateSearching);
      HandleNewRegistrationState();
    }
  }

  if (old_modem_state < kModemStateEnabled &&
      modem_state_ >= kModemStateEnabled) {
    // Just became enabled, update enabled state.
    OnEnabled();
  }

  switch (modem_state_) {
    case kModemStateFailed:
    case kModemStateUnknown:
    case kModemStateInitializing:
    case kModemStateLocked:
      break;
    case kModemStateDisabled:
      // When the Modem becomes disabled, Cellular is not necessarily disabled.
      // This may occur after a SIM swap or eSIM profile change. Ensure that
      // the Modem is started.
      if (state_ == State::kEnabled)
        StartModem(base::DoNothing());
      break;
    case kModemStateDisabling:
    case kModemStateEnabling:
      break;
    case kModemStateEnabled:
    case kModemStateSearching:
    case kModemStateRegistered:
      if (old_modem_state == kModemStateConnected ||
          old_modem_state == kModemStateConnecting ||
          old_modem_state == kModemStateDisconnecting) {
        OnDisconnected();
      }
      break;
    case kModemStateDisconnecting:
      break;
    case kModemStateConnecting:
      OnConnecting();
      break;
    case kModemStateConnected:
      // Even if the modem state transitions from Connecting to Connected here
      // we don't report the cellular object as Connected yet; we require the
      // actual connection attempt operation to finish.
      break;
  }
}

bool Cellular::IsActivating() const {
  return capability_ && capability_->IsActivating();
}

bool Cellular::GetPolicyAllowRoaming(Error* /*error*/) {
  return policy_allow_roaming_;
}

bool Cellular::SetPolicyAllowRoaming(const bool& value, Error* error) {
  if (policy_allow_roaming_ == value)
    return false;

  LOG(INFO) << LoggingTag() << ": " << __func__ << ": " << policy_allow_roaming_
            << "->" << value;

  policy_allow_roaming_ = value;
  adaptor()->EmitBoolChanged(kCellularPolicyAllowRoamingProperty, value);
  manager()->UpdateDevice(this);

  if (service_ && service_->IsRoamingRuleViolated()) {
    Disconnect(nullptr, "policy updated: roaming rule violated");
  }

  return true;
}

bool Cellular::SetUseAttachApn(const bool& value, Error* error) {
  LOG(INFO) << __func__;
  // |use_attach_apn_ | is deprecated. its default value should be true.
  if (!value)
    return false;

  return true;
}

bool Cellular::GetInhibited(Error* error) {
  return inhibited_;
}

bool Cellular::SetInhibited(const bool& inhibited, Error* error) {
  if (inhibited == inhibited_) {
    LOG(WARNING) << LoggingTag() << ": " << __func__
                 << ": State already set, ignoring request.";
    return false;
  }
  LOG(INFO) << LoggingTag() << ": " << __func__ << ": " << inhibited;

  // Clear any pending connect when inhibited changes.
  SetPendingConnect(std::string());

  inhibited_ = inhibited;

  // Update and emit Scanning before Inhibited. This allows the UI to wait for
  // Scanning to be false once Inhibit changes to know when an Inhibit operation
  // completes. UpdateScanning will call ConnectToPending if Scanning is false.
  UpdateScanning();
  adaptor()->EmitBoolChanged(kInhibitedProperty, inhibited_);

  return true;
}

KeyValueStore Cellular::GetSimLockStatus(Error* error) {
  if (!capability_) {
    // modemmanager might be inhibited or restarting.
    LOG(WARNING) << LoggingTag() << ": " << __func__
                 << ": Called with null capability.";
    return KeyValueStore();
  }
  return capability_->SimLockStatusToProperty(error);
}

void Cellular::SetSimPresent(bool sim_present) {
  if (sim_present_ == sim_present)
    return;

  sim_present_ = sim_present;
  adaptor()->EmitBoolChanged(kSIMPresentProperty, sim_present_);
}

void Cellular::StartTermination() {
  SLOG(2) << LoggingTag() << ": " << __func__;
  OnBeforeSuspend(base::BindOnce(&Cellular::OnTerminationCompleted,
                                 weak_ptr_factory_.GetWeakPtr()));
}

void Cellular::OnTerminationCompleted(const Error& error) {
  LOG(INFO) << LoggingTag() << ": " << __func__ << ": " << error;
  manager()->TerminationActionComplete(link_name());
  manager()->RemoveTerminationAction(link_name());
}

bool Cellular::DisconnectCleanup() {
  SLOG(2) << LoggingTag() << ": " << __func__;
  DestroySockets();
  if (!StateIsConnected())
    return false;
  StopLinkListener();
  SetState(State::kRegistered);
  SetServiceFailureSilent(Service::kFailureNone);
  SetPrimaryMultiplexedInterface("");
  GetPrimaryNetwork()->Stop();
  ResetCarrierEntitlement();
  return true;
}

void Cellular::ResetCarrierEntitlement() {
  carrier_entitlement_->Reset();
  if (!entitlement_check_callback_.is_null()) {
    std::move(entitlement_check_callback_)
        .Run(TetheringManager::EntitlementStatus::kNotAllowed);
  }
}

// static
void Cellular::LogRestartModemResult(const Error& error) {
  if (error.IsSuccess()) {
    LOG(INFO) << "Modem restart completed.";
  } else {
    LOG(WARNING) << "Attempt to restart modem failed: " << error;
  }
}

bool Cellular::ResetQ6V5Modem() {
  base::FilePath modem_reset_path = GetQ6V5ModemResetPath();
  if (!base::PathExists(modem_reset_path)) {
    PLOG(ERROR) << LoggingTag()
                << ": Unable to find sysfs file to reset modem.";
    return false;
  }

  int fd = HANDLE_EINTR(open(modem_reset_path.value().c_str(),
                             O_WRONLY | O_NONBLOCK | O_CLOEXEC));
  if (fd < 0) {
    PLOG(ERROR) << LoggingTag()
                << ": Failed to open sysfs file to reset modem.";
    return false;
  }

  base::ScopedFD scoped_fd(fd);
  if (!base::WriteFileDescriptor(scoped_fd.get(), "stop")) {
    PLOG(ERROR) << LoggingTag() << ": Failed to stop modem";
    return false;
  }
  usleep(kModemResetTimeout.InMicroseconds());
  if (!base::WriteFileDescriptor(scoped_fd.get(), "start")) {
    PLOG(ERROR) << LoggingTag() << ": Failed to start modem";
    return false;
  }
  return true;
}

base::FilePath Cellular::GetQ6V5ModemResetPath() {
  base::FilePath modem_reset_path, driver_path;

  base::FileEnumerator it(
      base::FilePath(kQ6V5SysfsBasePath), false,
      base::FileEnumerator::FILES | base::FileEnumerator::SHOW_SYM_LINKS,
      kQ6V5RemoteprocPattern);
  for (base::FilePath name = it.Next(); !name.empty(); name = it.Next()) {
    if (base::ReadSymbolicLink(name.Append("device/driver"), &driver_path) &&
        driver_path.BaseName() == base::FilePath(kQ6V5DriverName)) {
      modem_reset_path = name.Append("state");
      break;
    }
  }

  return modem_reset_path;
}

bool Cellular::IsQ6V5Modem() {
  // Check if manufacturer is equal to "QUALCOMM INCORPORATED" and
  // if one of the remoteproc[0-9]/device/driver in sysfs links
  // to "qcom-q6v5-mss".
  return (manufacturer_ == kQ6V5ModemManufacturerName &&
          base::PathExists(GetQ6V5ModemResetPath()));
}

void Cellular::StartPPP(const std::string& serial_device) {
  SLOG(2) << LoggingTag() << ": " << __func__ << ": on " << serial_device;
  // Detach any SelectedService from this device. It will be grafted onto
  // the PPPDevice after PPP is up (in Cellular::Notify).
  //
  // This kills dhcpcd if it is running.
  if (selected_service()) {
    CHECK_EQ(service_.get(), selected_service().get());
    // Save and restore |service_| state, as DropConnection calls
    // SelectService, and SelectService will move selected_service()
    // to State::kIdle.
    Service::ConnectState original_state(service_->state());
    Device::DropConnection();  // Don't redirect to PPPDevice.
    service_->SetState(original_state);
  } else {
    // Network shouldn't be connected without selected_service().
    DCHECK(!GetPrimaryNetwork()->IsConnected());
  }

  PPPDaemon::DeathCallback death_callback(
      base::BindOnce(&Cellular::OnPPPDied, weak_ptr_factory_.GetWeakPtr()));

  PPPDaemon::Options options;
  options.no_detach = true;
  options.no_default_route = true;
  options.use_peer_dns = true;
  options.max_fail = 1;

  is_ppp_authenticating_ = false;

  Error error;
  std::unique_ptr<ExternalTask> new_ppp_task(PPPDaemon::Start(
      control_interface(), process_manager_, weak_ptr_factory_.GetWeakPtr(),
      options, serial_device, std::move(death_callback), &error));
  if (new_ppp_task) {
    SLOG(1) << LoggingTag() << ": Forked pppd process.";
    ppp_task_ = std::move(new_ppp_task);
  }
}

void Cellular::StopPPP() {
  SLOG(2) << LoggingTag() << ": " << __func__;
  if (!ppp_device_)
    return;
  DropConnection();
  ppp_task_.reset();
  ppp_device_ = nullptr;
}

// called by |ppp_task_|
void Cellular::GetLogin(std::string* user, std::string* password) {
  SLOG(2) << LoggingTag() << ": " << __func__;
  if (!service()) {
    LOG(ERROR) << LoggingTag() << ": " << __func__ << ": with no service ";
    return;
  }
  CHECK(user);
  CHECK(password);
  *user = service()->ppp_username();
  *password = service()->ppp_password();
}

// Called by |ppp_task_|.
void Cellular::Notify(const std::string& reason,
                      const std::map<std::string, std::string>& dict) {
  SLOG(2) << LoggingTag() << ": " << __func__ << ": " << reason;

  if (reason == kPPPReasonAuthenticating) {
    OnPPPAuthenticating();
  } else if (reason == kPPPReasonAuthenticated) {
    OnPPPAuthenticated();
  } else if (reason == kPPPReasonConnect) {
    OnPPPConnected(dict);
  } else if (reason == kPPPReasonDisconnect) {
    // Ignore; we get disconnect information when pppd exits.
  } else if (reason == kPPPReasonExit) {
    // Ignore; we get its exit status by the death callback for PPPDaemon.
  } else {
    NOTREACHED();
  }
}

void Cellular::OnPPPAuthenticated() {
  SLOG(2) << LoggingTag() << ": " << __func__;
  is_ppp_authenticating_ = false;
}

void Cellular::OnPPPAuthenticating() {
  SLOG(2) << LoggingTag() << ": " << __func__;
  is_ppp_authenticating_ = true;
}

void Cellular::OnPPPConnected(
    const std::map<std::string, std::string>& params) {
  SLOG(2) << LoggingTag() << ": " << __func__;
  std::string interface_name = PPPDaemon::GetInterfaceName(params);
  DeviceInfo* device_info = manager()->device_info();
  int interface_index = device_info->GetIndex(interface_name);
  if (interface_index < 0) {
    // TODO(quiche): Consider handling the race when the RTNL notification about
    // the new PPP device has not been received yet. crbug.com/246832.
    NOTIMPLEMENTED() << ": No device info for " << interface_name << ".";
    return;
  }

  if (!ppp_device_ || ppp_device_->interface_index() != interface_index) {
    if (ppp_device_) {
      ppp_device_->SelectService(nullptr);  // No longer drives |service_|.
      // Destroy the existing device before creating a new one to avoid the
      // possibility of multiple DBus Objects with the same interface name.
      // See https://crbug.com/1032030 for details.
      ppp_device_ = nullptr;
    }
    ppp_device_ = device_info->CreatePPPDevice(manager(), interface_name,
                                               interface_index);
    device_info->RegisterDevice(ppp_device_);
  }

  CHECK(service_);
  // For PPP, we only SelectService on the |ppp_device_|.
  CHECK(!selected_service());
  ppp_device_->SetEnabled(true);
  ppp_device_->SelectService(service_);

  auto properties = std::make_unique<IPConfig::Properties>(
      PPPDaemon::ParseIPConfiguration(params));
  ppp_device_->UpdateIPConfig(std::move(properties), nullptr);
}

void Cellular::OnPPPDied(pid_t pid, int exit) {
  SLOG(1) << LoggingTag() << ": " << __func__;
  ppp_task_.reset();
  if (is_ppp_authenticating_) {
    SetServiceFailure(Service::kFailurePPPAuth);
  } else {
    SetServiceFailure(PPPDaemon::ExitStatusToFailure(exit));
  }
  Disconnect(nullptr, "unexpected pppd exit");
}

bool Cellular::ModemIsEnabledButNotRegistered() {
  // Normally the Modem becomes Registered immediately after becoming enabled.
  // In cases where we have an attach APN or eSIM this may not be true. See
  // b/204847937 and b/205882451 for more details.
  // TODO(b/186482862): Fix this behavior in ModemManager.
  return (state_ == State::kEnabled || state_ == State::kModemStarting ||
          state_ == State::kModemStarted) &&
         modem_state_ == kModemStateEnabled;
}

void Cellular::SetPendingConnect(const std::string& iccid) {
  if (iccid == connect_pending_iccid_)
    return;

  if (!connect_pending_iccid_.empty()) {
    SLOG(1) << LoggingTag()
            << ": Cancelling pending connect to: " << connect_pending_iccid_;
    ConnectToPendingFailed(Service::kFailureDisconnect);
  }

  connect_pending_callback_.Cancel();
  connect_pending_iccid_ = iccid;

  if (iccid.empty())
    return;

  SLOG(1) << LoggingTag() << ": Set Pending connect: " << iccid;
  // Pending connect requests may fail, e.g. a SIM slot change may fail or
  // registration may fail for an inactive eSIM profile. Set a timeout to
  // cancel the pending connect and inform the UI.
  connect_cancel_callback_.Reset(base::BindOnce(
      &Cellular::ConnectToPendingCancel, weak_ptr_factory_.GetWeakPtr()));
  dispatcher()->PostDelayedTask(FROM_HERE, connect_cancel_callback_.callback(),
                                kPendingConnectCancel);
}

void Cellular::ConnectToPending() {
  if (connect_pending_iccid_.empty() ||
      !connect_pending_callback_.IsCancelled()) {
    return;
  }

  if (inhibited_) {
    SLOG(1) << LoggingTag() << ": " << __func__ << ": Inhibited";
    return;
  }
  if (scanning_) {
    SLOG(1) << LoggingTag() << ": " << __func__ << ": Scanning";
    return;
  }

  if (modem_state_ == kModemStateLocked) {
    LOG(WARNING) << LoggingTag() << ": " << __func__ << ": Modem locked";
    ConnectToPendingFailed(Service::kFailureSimLocked);
    return;
  }

  if (ModemIsEnabledButNotRegistered()) {
    LOG(WARNING) << LoggingTag() << ": " << __func__
                 << ": Waiting for Modem registration.";
    return;
  }

  if (!StateIsRegistered()) {
    LOG(WARNING) << LoggingTag() << ": " << __func__
                 << ": Cellular not registered, State: "
                 << GetStateString(state_);
    ConnectToPendingFailed(Service::kFailureNotRegistered);
    return;
  }
  if (modem_state_ != kModemStateRegistered) {
    LOG(WARNING) << LoggingTag() << ": " << __func__
                 << ": Modem not registered, State: "
                 << GetModemStateString(modem_state_);
    ConnectToPendingFailed(Service::kFailureNotRegistered);
    return;
  }

  SLOG(1) << LoggingTag() << ": " << __func__ << ": " << connect_pending_iccid_;
  connect_cancel_callback_.Cancel();
  connect_pending_callback_.Reset(base::BindOnce(
      &Cellular::ConnectToPendingAfterDelay, weak_ptr_factory_.GetWeakPtr()));
  dispatcher()->PostDelayedTask(FROM_HERE, connect_pending_callback_.callback(),
                                kPendingConnectDelay);
}

void Cellular::ConnectToPendingAfterDelay() {
  SLOG(1) << LoggingTag() << ": " << __func__ << ": " << connect_pending_iccid_;

  std::string pending_iccid;
  if (connect_pending_iccid_ == kUnknownIccid) {
    // Connect to the current iccid if we want to connect to an unknown
    // iccid. This usually occurs when the inactive slot's iccid is unknown, but
    // we want to connect to it after a slot switch.
    pending_iccid = iccid_;
  } else {
    pending_iccid = connect_pending_iccid_;
  }

  // Clear pending connect request regardless of whether a service is found.
  connect_pending_iccid_.clear();

  CellularServiceRefPtr service =
      manager()->cellular_service_provider()->FindService(pending_iccid);
  if (!service) {
    LOG(WARNING) << LoggingTag()
                 << ": No matching service for pending connect.";
    return;
  }

  Error error;
  LOG(INFO) << LoggingTag() << ": Connecting to pending Cellular Service: "
            << service->log_name();
  service->Connect(&error, "Pending connect");
  if (!error.IsSuccess())
    service->SetFailure(Service::kFailureConnect);
}

void Cellular::ConnectToPendingFailed(Service::ConnectFailure failure) {
  if (!connect_pending_iccid_.empty()) {
    SLOG(1) << LoggingTag() << ": " << __func__ << ": "
            << connect_pending_iccid_
            << " Failure: " << Service::ConnectFailureToString(failure);
    CellularServiceRefPtr service =
        manager()->cellular_service_provider()->FindService(
            connect_pending_iccid_);
    bool is_user_triggered = false;
    if (service) {
      service->SetFailure(failure);
      is_user_triggered = service->is_in_user_connect();
    }
    // populate the error for the sake of metrics
    Error error;
    switch (failure) {
      case Service::kFailureNotRegistered:
        error.Populate(Error::kNotRegistered);
        break;
      case Service::kFailureDisconnect:
        error.Populate(Error::kOperationAborted);
        break;
      case Service::kFailureSimLocked:
        error.Populate(Error::kPinRequired);
        break;
      default:
        error.Populate(Error::kOperationFailed);
        break;
    }
    NotifyCellularConnectionResult(std::move(error), connect_pending_iccid_,
                                   is_user_triggered,
                                   ApnList::ApnType::kDefault);
  }
  connect_cancel_callback_.Cancel();
  connect_pending_callback_.Cancel();
  connect_pending_iccid_.clear();
}

void Cellular::ConnectToPendingCancel() {
  LOG(WARNING) << LoggingTag() << ": " << __func__;
  ConnectToPendingFailed(Service::kFailureNotRegistered);
}

void Cellular::UpdateScanning() {
  bool scanning;
  switch (state_) {
    case State::kDisabled:
      scanning = false;
      break;
    case State::kEnabled:
      // Cellular is enabled, but the Modem object has not been created, or was
      // destroyed because the Modem is Inhibited or Locked, or StartModem
      // failed.
      scanning = !inhibited_ && modem_state_ != kModemStateLocked &&
                 modem_state_ != kModemStateFailed;
      break;
    case State::kModemStarting:
    case State::kModemStopping:
      scanning = true;
      break;
    case State::kModemStarted:
    case State::kRegistered:
    case State::kConnected:
    case State::kLinked:
      // When the modem is started and enabling or searching, treat as scanning.
      // Also set scanning if an active scan is in progress.
      scanning = modem_state_ == kModemStateEnabling ||
                 modem_state_ == kModemStateSearching ||
                 proposed_scan_in_progress_;
      break;
  }
  SetScanning(scanning);
}

void Cellular::RegisterProperties() {
  PropertyStore* store = this->mutable_store();

  // These properties do not have setters, and events are not generated when
  // they are changed.
  store->RegisterConstString(kDBusServiceProperty, &dbus_service_);
  store->RegisterConstString(kDBusObjectProperty, &dbus_path_str_);

  store->RegisterUint16(kScanIntervalProperty, &scan_interval_);

  // These properties have setters that should be used to change their values.
  // Events are generated whenever the values change.
  store->RegisterConstStringmap(kHomeProviderProperty, &home_provider_);
  store->RegisterConstBool(kSupportNetworkScanProperty, &scanning_supported_);
  store->RegisterConstString(kEidProperty, &eid_);
  store->RegisterConstString(kEsnProperty, &esn_);
  store->RegisterConstString(kFirmwareRevisionProperty, &firmware_revision_);
  store->RegisterConstString(kHardwareRevisionProperty, &hardware_revision_);
  store->RegisterConstString(kImeiProperty, &imei_);
  store->RegisterConstString(kImsiProperty, &imsi_);
  store->RegisterConstString(kMdnProperty, &mdn_);
  store->RegisterConstString(kMeidProperty, &meid_);
  store->RegisterConstString(kMinProperty, &min_);
  store->RegisterConstString(kManufacturerProperty, &manufacturer_);
  store->RegisterConstString(kModelIdProperty, &model_id_);
  store->RegisterConstString(kEquipmentIdProperty, &equipment_id_);
  store->RegisterConstBool(kScanningProperty, &scanning_);

  store->RegisterConstString(kSelectedNetworkProperty, &selected_network_);
  store->RegisterConstStringmaps(kFoundNetworksProperty, &found_networks_);
  store->RegisterConstBool(kProviderRequiresRoamingProperty,
                           &provider_requires_roaming_);
  store->RegisterConstBool(kSIMPresentProperty, &sim_present_);
  store->RegisterConstKeyValueStores(kSIMSlotInfoProperty, &sim_slot_info_);
  store->RegisterConstStringmaps(kCellularApnListProperty, &apn_list_);
  store->RegisterConstString(kIccidProperty, &iccid_);
  store->RegisterConstString(kPrimaryMultiplexedInterfaceProperty,
                             &primary_multiplexed_interface_);

  // TODO(pprabhu): Decide whether these need their own custom setters.
  HelpRegisterConstDerivedString(kTechnologyFamilyProperty,
                                 &Cellular::GetTechnologyFamily);
  HelpRegisterConstDerivedString(kDeviceIdProperty, &Cellular::GetDeviceId);
  HelpRegisterDerivedBool(kCellularPolicyAllowRoamingProperty,
                          &Cellular::GetPolicyAllowRoaming,
                          &Cellular::SetPolicyAllowRoaming);
  // TODO(b/277792069): Remove when Chrome removes the attach APN code.
  HelpRegisterDerivedBool(kUseAttachAPNProperty, &Cellular::GetUseAttachApn,
                          &Cellular::SetUseAttachApn);
  HelpRegisterDerivedBool(kInhibitedProperty, &Cellular::GetInhibited,
                          &Cellular::SetInhibited);

  store->RegisterDerivedKeyValueStore(
      kSIMLockStatusProperty,
      KeyValueStoreAccessor(new CustomAccessor<Cellular, KeyValueStore>(
          this, &Cellular::GetSimLockStatus, /*error=*/nullptr)));
}

void Cellular::UpdateModemProperties(const RpcIdentifier& dbus_path,
                                     const std::string& mac_address) {
  if (dbus_path_ == dbus_path) {
    SLOG(1) << LoggingTag() << ": " << __func__
            << ": Skipping update. Same dbus_path provided: "
            << dbus_path.value();
    return;
  }
  LOG(INFO) << LoggingTag() << ": " << __func__
            << ": Modem Path: " << dbus_path.value();
  SetDbusPath(dbus_path);
  SetModemState(kModemStateUnknown);
  set_mac_address(mac_address);
  CreateCapability();
}

const std::string& Cellular::GetSimCardId() const {
  if (!eid_.empty())
    return eid_;
  return iccid_;
}

bool Cellular::HasIccid(const std::string& iccid) const {
  if (iccid == iccid_)
    return true;
  for (const SimProperties& sim_properties : sim_slot_properties_) {
    if (sim_properties.iccid == iccid) {
      return true;
    }
  }
  return false;
}

void Cellular::SetSimProperties(
    const std::vector<SimProperties>& sim_properties, size_t primary_slot) {
  LOG(INFO) << LoggingTag() << ": " << __func__
            << ": Slots: " << sim_properties.size()
            << " Primary: " << primary_slot;
  if (sim_properties.empty()) {
    // This might occur while the Modem is starting.
    SetPrimarySimProperties(SimProperties());
    SetSimSlotProperties(sim_properties, 0);
    return;
  }
  if (primary_slot >= sim_properties.size()) {
    LOG(ERROR) << LoggingTag() << ": Invalid Primary Slot Id: " << primary_slot;
    primary_slot = 0u;
  }

  const SimProperties& primary_sim_properties = sim_properties[primary_slot];

  // Update SIM properties for the primary SIM slot and create or update the
  // primary Service.
  SetPrimarySimProperties(primary_sim_properties);

  // Update the KeyValueStore for Device.Cellular.SIMSlotInfo and emit it.
  SetSimSlotProperties(sim_properties, static_cast<int>(primary_slot));

  // Ensure that secondary services are created and updated.
  UpdateSecondaryServices();
}

void Cellular::OnProfilesChanged() {
  if (!service_) {
    LOG(ERROR) << LoggingTag()
               << ": 3GPP profiles were updated with no service.";
    return;
  }

  // Rebuild the APN try list.
  OnOperatorChanged();

  if (!StateIsConnected()) {
    return;
  }

  LOG(INFO) << LoggingTag() << ": Reconnecting for OTA profile update.";
  Disconnect(nullptr, "OTA profile update");
  SetPendingConnect(service_->iccid());
}

bool Cellular::CompareApns(const Stringmap& apn1, const Stringmap& apn2) const {
  static const std::string always_ignore_keys[] = {
      cellular::kApnVersionProperty, kApnNameProperty,
      kApnLanguageProperty,          kApnSourceProperty,
      kApnLocalizedNameProperty,     kApnIsRequiredByCarrierSpecProperty};
  std::set<std::string> ignore_keys{std::begin(always_ignore_keys),
                                    std::end(always_ignore_keys)};

  // Enforce the APN keys so that developers explicitly define the behavior
  // for each key in this function.
  static const std::string only_allowed_keys[] = {
      kApnProperty,         kApnTypesProperty,          kApnUsernameProperty,
      kApnPasswordProperty, kApnAuthenticationProperty, kApnIpTypeProperty,
      kApnAttachProperty};
  std::set<std::string> allowed_keys{std::begin(only_allowed_keys),
                                     std::end(only_allowed_keys)};
  for (auto const& pair : apn1) {
    if (ignore_keys.count(pair.first))
      continue;

    DCHECK(allowed_keys.count(pair.first)) << " key: " << pair.first;
    if (!base::Contains(apn2, pair.first) || pair.second != apn2.at(pair.first))
      return false;
    // Keys match, ignore them below.
    ignore_keys.insert(pair.first);
  }
  // Find keys in apn2 which are not in apn1.
  for (auto const& pair : apn2) {
    DCHECK(allowed_keys.count(pair.first) || ignore_keys.count(pair.first))
        << " key: " << pair.first;
    if (ignore_keys.count(pair.first) == 0)
      return false;
  }
  return true;
}

std::deque<Stringmap> Cellular::BuildAttachApnTryList() const {
  return BuildApnTryList(ApnList::ApnType::kAttach);
}

std::deque<Stringmap> Cellular::BuildDefaultApnTryList() const {
  return BuildApnTryList(ApnList::ApnType::kDefault);
}

std::deque<Stringmap> Cellular::BuildTetheringApnTryList() const {
  // TODO(b/249376151): Handle special cases for tethering based on modb flags
  return BuildApnTryList(ApnList::ApnType::kDun);
}

bool Cellular::IsRequiredByCarrierApn(const Stringmap& apn) const {
  // Only check the property in MODB APNs to avoid getting into a situation in
  // which the UI or user send the property by mistake and the UI cannot
  // update the APN list because there is an existing APN with the property
  // set to true.
  return base::Contains(apn, kApnSourceProperty) &&
         apn.at(kApnSourceProperty) == cellular::kApnSourceMoDb &&
         base::Contains(apn, kApnIsRequiredByCarrierSpecProperty) &&
         apn.at(kApnIsRequiredByCarrierSpecProperty) ==
             kApnIsRequiredByCarrierSpecTrue;
}

bool Cellular::RequiredApnExists(ApnList::ApnType apn_type) const {
  for (auto apn : apn_list_) {
    if (ApnList::IsApnType(apn, apn_type) && IsRequiredByCarrierApn(apn))
      return true;
  }
  return false;
}

std::deque<Stringmap> Cellular::BuildApnTryList(
    ApnList::ApnType apn_type) const {
  std::deque<Stringmap> apn_try_list;
  // When a required APN exists, no other APNs of that type will be included in
  // the try list.
  bool modb_required_apn_exists = RequiredApnExists(apn_type);
  // If a required APN exists, the last good APN is not added.
  bool add_last_good_apn = !modb_required_apn_exists;
  std::vector<const Stringmap*> custom_apns_info;
  const Stringmap* custom_apn_info = nullptr;
  const Stringmap* last_good_apn_info = nullptr;
  const Stringmaps* custom_apn_list = nullptr;
  // Add custom APNs(from UI or Admin)
  if (!modb_required_apn_exists && service_) {
    if (service_->custom_apn_list().has_value()) {
      custom_apn_list = &service_->custom_apn_list().value();
      for (const auto& custom_apn : *custom_apn_list) {
        if (ApnList::IsApnType(custom_apn, apn_type))
          custom_apns_info.emplace_back(&custom_apn);
      }
    } else if (service_->GetUserSpecifiedApn() &&
               ApnList::IsApnType(*service_->GetUserSpecifiedApn(), apn_type)) {
      custom_apn_info = service_->GetUserSpecifiedApn();
      custom_apns_info.emplace_back(custom_apn_info);
    }

    last_good_apn_info = service_->GetLastGoodApn();
    for (auto custom_apn : custom_apns_info) {
      apn_try_list.push_back(*custom_apn);
      if (!base::Contains(apn_try_list.back(), kApnSourceProperty))
        apn_try_list.back()[kApnSourceProperty] = kApnSourceUi;

      SLOG(3) << LoggingTag() << ": " << __func__
              << ": Adding User Specified APN: "
              << GetPrintableApnStringmap(apn_try_list.back());
      if (custom_apn_list ||
          (last_good_apn_info &&
           CompareApns(*last_good_apn_info, apn_try_list.back()))) {
        add_last_good_apn = false;
      }
    }
  }
  // With the revamp APN UI, if the user has entered an APN in the UI, only
  // customs APNs are used. Return early.
  if (custom_apn_list && custom_apn_list->size() > 0) {
    ValidateApnTryList(apn_try_list);
    return apn_try_list;
  }
  // Ensure all Modem APNs are added before MODB APNs.
  for (auto apn : apn_list_) {
    // TODO(b/267804414): Include modem APNs when the
    // |modb_required_apn_exists| is true. We need to exclude them for now to
    // enforce a DUN APN until multiple APNs are supported.
    if (!ApnList::IsApnType(apn, apn_type) ||
        (modb_required_apn_exists && !IsRequiredByCarrierApn(apn)))
      continue;
    DCHECK(base::Contains(apn, kApnSourceProperty));
    // Verify all APNs are either from the Modem or MODB.
    DCHECK(apn[kApnSourceProperty] == cellular::kApnSourceModem ||
           apn[kApnSourceProperty] == cellular::kApnSourceMoDb);
    if (apn[kApnSourceProperty] != cellular::kApnSourceModem)
      continue;
    apn_try_list.push_back(apn);
  }
  // Add MODB APNs and update the origin of the custom APN(only for old UI).
  int index_of_first_modb_apn = apn_try_list.size();
  for (const auto& apn : apn_list_) {
    if (!ApnList::IsApnType(apn, apn_type) ||
        (modb_required_apn_exists && !IsRequiredByCarrierApn(apn)))
      continue;
    // Updating the origin of the custom APN is only needed for the old UI,
    // since the APN UI revamp will include the correct APN source.
    if (!custom_apn_list && custom_apn_info &&
        CompareApns(*custom_apn_info, apn) &&
        base::Contains(apn, kApnSourceProperty)) {
      // If |custom_apn_info| is not null, it is located at the first position
      // of |apn_try_list|, and we update the APN source for it.
      apn_try_list[0][kApnSourceProperty] = apn.at(kApnSourceProperty);
      continue;
    }

    bool is_same_as_last_good_apn =
        last_good_apn_info && CompareApns(*last_good_apn_info, apn);
    if (is_same_as_last_good_apn)
      add_last_good_apn = false;

    if (base::Contains(apn, kApnSourceProperty) &&
        apn.at(kApnSourceProperty) == cellular::kApnSourceMoDb) {
      if (is_same_as_last_good_apn) {
        apn_try_list.insert(apn_try_list.begin() + index_of_first_modb_apn,
                            apn);
      } else {
        apn_try_list.push_back(apn);
      }
    }
  }
  // Add fallback empty APN as a last try for Default and Attach
  // TODO(b/267804414): Include the fallback APN when the
  // |modb_required_apn_exists| is true. We need to exclude it for now to
  // enforce a DUN APN until multiple APNs are supported.
  if (!modb_required_apn_exists && (apn_type == ApnList::ApnType::kDefault ||
                                    apn_type == ApnList::ApnType::kAttach)) {
    Stringmap empty_apn = BuildFallbackEmptyApn(apn_type);
    apn_try_list.push_back(empty_apn);
    bool is_same_as_last_good_apn =
        last_good_apn_info && CompareApns(*last_good_apn_info, empty_apn);
    if (is_same_as_last_good_apn)
      add_last_good_apn = false;
  }
  // The last good APN will be a last-ditch effort to connect in case the APN
  // list is misconfigured somehow.
  if (last_good_apn_info && add_last_good_apn &&
      ApnList::IsApnType(*last_good_apn_info, apn_type)) {
    apn_try_list.push_back(*last_good_apn_info);
    LOG(INFO) << LoggingTag() << ": " << __func__ << ": Adding last good APN: "
              << GetPrintableApnStringmap(*last_good_apn_info);
  }
  // Print list for debugging
  if (SLOG_IS_ON(Cellular, 3)) {
    std::string log_string =
        ": Try list: ApnType: " + ApnList::GetApnTypeString(apn_type);
    for (const auto& it : apn_try_list) {
      log_string += " " + GetPrintableApnStringmap(it);
    }
    SLOG(3) << __func__ << log_string;
  }
  ValidateApnTryList(apn_try_list);
  return apn_try_list;
}

void Cellular::SetScanningSupported(bool scanning_supported) {
  if (scanning_supported_ == scanning_supported)
    return;

  scanning_supported_ = scanning_supported;
  adaptor()->EmitBoolChanged(kSupportNetworkScanProperty, scanning_supported_);
}

void Cellular::SetEquipmentId(const std::string& equipment_id) {
  if (equipment_id_ == equipment_id)
    return;

  equipment_id_ = equipment_id;
  adaptor()->EmitStringChanged(kEquipmentIdProperty, equipment_id_);
}

void Cellular::SetEsn(const std::string& esn) {
  if (esn_ == esn)
    return;

  esn_ = esn;
  adaptor()->EmitStringChanged(kEsnProperty, esn_);
}

void Cellular::SetFirmwareRevision(const std::string& firmware_revision) {
  if (firmware_revision_ == firmware_revision)
    return;

  firmware_revision_ = firmware_revision;
  adaptor()->EmitStringChanged(kFirmwareRevisionProperty, firmware_revision_);
}

void Cellular::SetHardwareRevision(const std::string& hardware_revision) {
  if (hardware_revision_ == hardware_revision)
    return;

  hardware_revision_ = hardware_revision;
  adaptor()->EmitStringChanged(kHardwareRevisionProperty, hardware_revision_);
}

void Cellular::SetDeviceId(std::unique_ptr<DeviceId> device_id) {
  device_id_ = std::move(device_id);
}

void Cellular::SetImei(const std::string& imei) {
  if (imei_ == imei)
    return;

  imei_ = imei;
  adaptor()->EmitStringChanged(kImeiProperty, imei_);
}

void Cellular::SetPrimarySimProperties(const SimProperties& sim_properties) {
  SLOG(1) << LoggingTag() << ": " << __func__ << ": EID= " << sim_properties.eid
          << " ICCID= " << sim_properties.iccid
          << " IMSI= " << sim_properties.imsi
          << " OperatorId= " << sim_properties.operator_id
          << " ServiceProviderName= " << sim_properties.spn
          << " GID1= " << sim_properties.gid1;

  eid_ = sim_properties.eid;
  iccid_ = sim_properties.iccid;
  imsi_ = sim_properties.imsi;

  mobile_operator_info()->UpdateMCCMNC(sim_properties.operator_id);
  mobile_operator_info()->UpdateOperatorName(sim_properties.spn);
  mobile_operator_info()->UpdateICCID(iccid_);
  if (!imsi_.empty()) {
    mobile_operator_info()->UpdateIMSI(imsi_);
  }
  if (!sim_properties.gid1.empty()) {
    mobile_operator_info()->UpdateGID1(sim_properties.gid1);
  }

  adaptor()->EmitStringChanged(kEidProperty, eid_);
  adaptor()->EmitStringChanged(kIccidProperty, iccid_);
  adaptor()->EmitStringChanged(kImsiProperty, imsi_);
  SetSimPresent(!iccid_.empty());

  // Ensure Service creation once SIM properties are set.
  UpdateServices();
}

void Cellular::SetSimSlotProperties(
    const std::vector<SimProperties>& slot_properties, int primary_slot) {
  if (sim_slot_properties_ == slot_properties &&
      primary_sim_slot_ == primary_slot) {
    return;
  }
  SLOG(1) << LoggingTag() << ": " << __func__
          << ": Slots: " << slot_properties.size()
          << " Primary: " << primary_slot;
  sim_slot_properties_ = slot_properties;
  if (primary_sim_slot_ != primary_slot) {
    primary_sim_slot_ = primary_slot;
  }
  // Set |sim_slot_info_| and emit SIMSlotInfo
  sim_slot_info_.clear();
  for (int i = 0; i < static_cast<int>(slot_properties.size()); ++i) {
    const SimProperties& sim_properties = slot_properties[i];
    KeyValueStore properties;
    properties.Set(kSIMSlotInfoEID, sim_properties.eid);
    properties.Set(kSIMSlotInfoICCID, sim_properties.iccid);
    bool is_primary = i == primary_slot;
    properties.Set(kSIMSlotInfoPrimary, is_primary);
    sim_slot_info_.push_back(properties);
    SLOG(2) << LoggingTag() << ": " << __func__
            << ": Slot: " << sim_properties.slot
            << " EID: " << sim_properties.eid
            << " ICCID: " << sim_properties.iccid << " Primary: " << is_primary;
  }
  adaptor()->EmitKeyValueStoresChanged(kSIMSlotInfoProperty, sim_slot_info_);
}

void Cellular::SetMdn(const std::string& mdn) {
  if (mdn_ == mdn)
    return;

  mdn_ = mdn;
  adaptor()->EmitStringChanged(kMdnProperty, mdn_);
}

void Cellular::SetMeid(const std::string& meid) {
  if (meid_ == meid)
    return;

  meid_ = meid;
  adaptor()->EmitStringChanged(kMeidProperty, meid_);
}

void Cellular::SetMin(const std::string& min) {
  if (min_ == min)
    return;

  min_ = min;
  adaptor()->EmitStringChanged(kMinProperty, min_);
}

void Cellular::SetManufacturer(const std::string& manufacturer) {
  if (manufacturer_ == manufacturer)
    return;

  manufacturer_ = manufacturer;
  adaptor()->EmitStringChanged(kManufacturerProperty, manufacturer_);
}

void Cellular::SetModelId(const std::string& model_id) {
  if (model_id_ == model_id)
    return;

  model_id_ = model_id;
  adaptor()->EmitStringChanged(kModelIdProperty, model_id_);
}

void Cellular::SetMMPlugin(const std::string& mm_plugin) {
  mm_plugin_ = mm_plugin;
}

void Cellular::SetMaxActiveMultiplexedBearers(
    uint32_t max_multiplexed_bearers) {
  max_multiplexed_bearers_ = max_multiplexed_bearers;
}

void Cellular::StartLocationPolling() {
  CHECK(capability_);
  if (!capability_->IsLocationUpdateSupported()) {
    SLOG(2) << LoggingTag() << ": Location polling not enabled for "
            << mm_plugin_ << " plugin.";
    return;
  }

  if (polling_location_)
    return;

  polling_location_ = true;

  CHECK(poll_location_task_.IsCancelled());
  SLOG(2) << LoggingTag() << ": " << __func__
          << ": Starting location polling tasks.";

  // Schedule an immediate task
  poll_location_task_.Reset(base::BindOnce(&Cellular::PollLocationTask,
                                           weak_ptr_factory_.GetWeakPtr()));
  dispatcher()->PostTask(FROM_HERE, poll_location_task_.callback());
}

void Cellular::StopLocationPolling() {
  if (!polling_location_)
    return;
  polling_location_ = false;

  if (!poll_location_task_.IsCancelled()) {
    SLOG(2) << LoggingTag() << ": " << __func__
            << ": Cancelling outstanding timeout.";
    poll_location_task_.Cancel();
  }
}

void Cellular::SetDbusPath(const shill::RpcIdentifier& dbus_path) {
  dbus_path_ = dbus_path;
  dbus_path_str_ = dbus_path.value();
  adaptor()->EmitStringChanged(kDBusObjectProperty, dbus_path_str_);
}

void Cellular::SetScanning(bool scanning) {
  if (scanning_ == scanning)
    return;
  LOG(INFO) << LoggingTag() << ": " << __func__ << ": " << scanning
            << " State: " << GetStateString(state_)
            << " Modem State: " << GetModemStateString(modem_state_);
  if (scanning) {
    // Set Scanning=true immediately.
    SetScanningProperty(true);
    return;
  }
  // If the modem is disabled, set Scanning=false immediately.
  // A delayed clear in this case might hit after the service is destroyed.
  if (state_ == State::kDisabled) {
    SetScanningProperty(false);
    return;
  }
  // Delay Scanning=false to delay operations while the Modem is starting.
  // TODO(b/177588333): Make Modem and/or the MM dbus API more robust.
  if (!scanning_clear_callback_.IsCancelled())
    return;

  SLOG(2) << LoggingTag() << ": " << __func__ << ": Delaying clear";
  scanning_clear_callback_.Reset(base::BindOnce(
      &Cellular::SetScanningProperty, weak_ptr_factory_.GetWeakPtr(), false));
  dispatcher()->PostDelayedTask(FROM_HERE, scanning_clear_callback_.callback(),
                                kModemResetTimeout);
}

void Cellular::SetScanningProperty(bool scanning) {
  SLOG(2) << LoggingTag() << ": " << __func__ << ": " << scanning;
  if (!scanning_clear_callback_.IsCancelled())
    scanning_clear_callback_.Cancel();
  scanning_ = scanning;
  adaptor()->EmitBoolChanged(kScanningProperty, scanning_);

  if (scanning)
    metrics()->NotifyDeviceScanStarted(interface_index());
  else
    metrics()->NotifyDeviceScanFinished(interface_index());

  if (!scanning_)
    ConnectToPending();
}

void Cellular::SetSelectedNetwork(const std::string& selected_network) {
  if (selected_network_ == selected_network)
    return;

  selected_network_ = selected_network;
  adaptor()->EmitStringChanged(kSelectedNetworkProperty, selected_network_);
}

void Cellular::SetFoundNetworks(const Stringmaps& found_networks) {
  // There is no canonical form of a Stringmaps value.
  // So don't check for redundant updates.
  found_networks_ = found_networks;
  adaptor()->EmitStringmapsChanged(kFoundNetworksProperty, found_networks_);
}

void Cellular::SetPrimaryMultiplexedInterface(
    const std::string& interface_name) {
  if (primary_multiplexed_interface_ == interface_name) {
    return;
  }

  primary_multiplexed_interface_ = interface_name;
  adaptor()->EmitStringChanged(kPrimaryMultiplexedInterfaceProperty,
                               primary_multiplexed_interface_);
}

void Cellular::SetProviderRequiresRoaming(bool provider_requires_roaming) {
  if (provider_requires_roaming_ == provider_requires_roaming)
    return;

  provider_requires_roaming_ = provider_requires_roaming;
  adaptor()->EmitBoolChanged(kProviderRequiresRoamingProperty,
                             provider_requires_roaming_);
}

bool Cellular::IsRoamingAllowed() {
  return service_ && service_->IsRoamingAllowed();
}

void Cellular::SetApnList(const Stringmaps& apn_list) {
  // There is no canonical form of a Stringmaps value, so don't check for
  // redundant updates.
  apn_list_ = apn_list;
  adaptor()->EmitStringmapsChanged(kCellularApnListProperty, apn_list_);
}

void Cellular::UpdateHomeProvider() {
  SLOG(2) << LoggingTag() << ": " << __func__;

  Stringmap home_provider;
  auto AssingIfNotEmpty = [&](const std::string& key,
                              const std::string& value) {
    if (!value.empty())
      home_provider[key] = value;
  };
  if (mobile_operator_info_->IsMobileNetworkOperatorKnown()) {
    AssingIfNotEmpty(kOperatorCodeKey, mobile_operator_info_->mccmnc());
    AssingIfNotEmpty(kOperatorNameKey, mobile_operator_info_->operator_name());
    AssingIfNotEmpty(kOperatorCountryKey, mobile_operator_info_->country());
    AssingIfNotEmpty(kOperatorUuidKey, mobile_operator_info_->uuid());
  } else if (mobile_operator_info_->IsServingMobileNetworkOperatorKnown()) {
    SLOG(2) << "Serving provider proxying in for home provider.";
    AssingIfNotEmpty(kOperatorCodeKey, mobile_operator_info_->serving_mccmnc());
    AssingIfNotEmpty(kOperatorNameKey,
                     mobile_operator_info_->serving_operator_name());
    AssingIfNotEmpty(kOperatorCountryKey,
                     mobile_operator_info_->serving_country());
    AssingIfNotEmpty(kOperatorUuidKey, mobile_operator_info_->serving_uuid());
  }
  if (home_provider != home_provider_) {
    home_provider_ = home_provider;
    adaptor()->EmitStringmapChanged(kHomeProviderProperty, home_provider_);
  }
  // On the new APN UI revamp, modem and modb APNs are not shown to
  // the user and the behavior of modem APNs should not be altered.
  bool merge_similar_apns =
      !(service_ && service_->custom_apn_list().has_value());
  ApnList apn_list(merge_similar_apns);
  // TODO(b:180004055): remove this when we have captive portal checks that
  // mark APNs as bad and can skip the null APN for data connections
  if (manufacturer_ != kQ6V5ModemManufacturerName)
    apn_list.AddApns(capability_->GetProfiles(), ApnList::ApnSource::kModem);
  apn_list.AddApns(mobile_operator_info_->apn_list(),
                   ApnList::ApnSource::kModb);
  SetApnList(apn_list.GetList());

  SetProviderRequiresRoaming(mobile_operator_info_->requires_roaming());
}

void Cellular::UpdateServingOperator() {
  SLOG(3) << LoggingTag() << ": " << __func__;
  if (!service()) {
    return;
  }

  Stringmap serving_operator;
  auto AssingIfNotEmpty = [&](const std::string& key,
                              const std::string& value) {
    if (!value.empty())
      serving_operator[key] = value;
  };
  if (mobile_operator_info_->IsServingMobileNetworkOperatorKnown()) {
    AssingIfNotEmpty(kOperatorCodeKey, mobile_operator_info_->serving_mccmnc());
    AssingIfNotEmpty(kOperatorNameKey,
                     mobile_operator_info_->serving_operator_name());
    AssingIfNotEmpty(kOperatorCountryKey,
                     mobile_operator_info_->serving_country());
    AssingIfNotEmpty(kOperatorUuidKey, mobile_operator_info_->serving_uuid());
  } else if (mobile_operator_info_->IsMobileNetworkOperatorKnown()) {
    AssingIfNotEmpty(kOperatorCodeKey, mobile_operator_info_->mccmnc());
    AssingIfNotEmpty(kOperatorNameKey, mobile_operator_info_->operator_name());
    AssingIfNotEmpty(kOperatorCountryKey, mobile_operator_info_->country());
    AssingIfNotEmpty(kOperatorUuidKey, mobile_operator_info_->uuid());
  }

  service()->SetServingOperator(serving_operator);

  // Set friendly name of service.
  std::string service_name = mobile_operator_info_->friendly_operator_name(
      service()->roaming_state() == kRoamingStateRoaming);
  if (service_name.empty()) {
    LOG(WARNING) << LoggingTag()
                 << ": No properties for setting friendly name for: "
                 << service()->log_name();
    return;
  }
  SLOG(2) << LoggingTag() << ": " << __func__
          << ": Service: " << service()->log_name()
          << " Name: " << service_name;
  service()->SetFriendlyName(service_name);

  SetProviderRequiresRoaming(mobile_operator_info_->requires_roaming());
}

void Cellular::OnOperatorChanged() {
  SLOG(2) << LoggingTag() << ": " << __func__;
  CHECK(capability_);

  if (service()) {
    capability_->UpdateServiceOLP();
  }

  if (mobile_operator_info_->IsMobileNetworkOperatorKnown() ||
      mobile_operator_info_->IsServingMobileNetworkOperatorKnown()) {
    UpdateHomeProvider();
    UpdateServingOperator();
    ResetCarrierEntitlement();
  }
}

bool Cellular::StateIsConnected() {
  return state_ == State::kConnected || state_ == State::kLinked;
}

bool Cellular::StateIsRegistered() {
  return state_ == State::kRegistered || state_ == State::kConnected ||
         state_ == State::kLinked;
}

bool Cellular::StateIsStarted() {
  return state_ == State::kModemStarted || state_ == State::kRegistered ||
         state_ == State::kConnected || state_ == State::kLinked;
}

void Cellular::SetServiceForTesting(CellularServiceRefPtr service) {
  service_for_testing_ = service;
  service_ = service;
}

void Cellular::SetSelectedServiceForTesting(CellularServiceRefPtr service) {
  SelectService(service);
}

void Cellular::TetheringAllowedUpdated(bool allowed) {
  // TODO(b/267804414): This database is merged with service_providers.pbf, and
  // overrides a few carriers in it. This is used for fishfooding on carriers
  // that require multiple PDNs.
  mobile_operator_info_->ClearDatabasePaths();
  mobile_operator_info_->Reset();
  mobile_operator_info_->AddDefaultDatabasePaths();
  if (allowed && !base::PathExists(base::FilePath(
                     MobileOperatorInfo::kExclusiveOverrideDatabasePath))) {
    mobile_operator_info_->AddDatabasePath(
        base::FilePath(kTetheringTestDatabasePath));
  }
  mobile_operator_info_->Init();
  ReAttach();
}

void Cellular::EntitlementCheck(
    base::OnceCallback<void(TetheringManager::EntitlementStatus)> callback) {
  // Only one entitlement check request should exist at any point.
  DCHECK(entitlement_check_callback_.is_null());
  if (!entitlement_check_callback_.is_null()) {
    LOG(ERROR) << kEntitlementCheckAnomalyDetectorPrefix
               << "request received while another one is in progress";
    metrics()->NotifyCellularEntitlementCheckResult(
        Metrics::kCellularEntitlementCheckIllegalInProgress);
    dispatcher()->PostTask(
        FROM_HERE,
        base::BindOnce(std::move(callback),
                       TetheringManager::EntitlementStatus::kNotAllowed));
    return;
  }

  if (!mobile_operator_info_->tethering_allowed()) {
    LOG(ERROR) << kEntitlementCheckAnomalyDetectorPrefix
               << "tethering is not allowed by database settings";
    metrics()->NotifyCellularEntitlementCheckResult(
        Metrics::kCellularEntitlementCheckNotAllowedByModb);
    dispatcher()->PostTask(
        FROM_HERE,
        base::BindOnce(std::move(callback),
                       TetheringManager::EntitlementStatus::kNotAllowed));
    return;
  }
  // TODO(b/270210498): remove this check when tethering is allowed by default.
  if (!mobile_operator_info_->IsMobileNetworkOperatorKnown() &&
      !mobile_operator_info_->IsServingMobileNetworkOperatorKnown()) {
    LOG(ERROR) << kEntitlementCheckAnomalyDetectorPrefix
               << "carrier is not known.";
    metrics()->NotifyCellularEntitlementCheckResult(
        Metrics::kCellularEntitlementCheckUnknownCarrier);
    dispatcher()->PostTask(
        FROM_HERE,
        base::BindOnce(std::move(callback),
                       TetheringManager::EntitlementStatus::kNotAllowed));
    return;
  }

  auto network_addresses = GetPrimaryNetwork()->GetAddresses();
  if (network_addresses.empty()) {
    LOG(ERROR) << kEntitlementCheckAnomalyDetectorPrefix << "no IP address.";
    metrics()->NotifyCellularEntitlementCheckResult(
        Metrics::kCellularEntitlementCheckNoIp);
    dispatcher()->PostTask(
        FROM_HERE,
        base::BindOnce(std::move(callback),
                       TetheringManager::EntitlementStatus::kNotAllowed));
    return;
  }

  entitlement_check_callback_ = std::move(callback);
  // TODO(b/285242955): Use all available addresses instead of only primary one.
  carrier_entitlement_->Check(network_addresses[0],
                              GetPrimaryNetwork()->GetDNSServers(),
                              GetPrimaryNetwork()->interface_name(),
                              mobile_operator_info_->entitlement_config());
}

void Cellular::OnEntitlementCheckUpdated(CarrierEntitlement::Result result) {
  LOG(INFO) << "Entitlement check updated: " << static_cast<int>(result);
  switch (result) {
    case shill::CarrierEntitlement::Result::kAllowed:
      if (!entitlement_check_callback_.is_null()) {
        std::move(entitlement_check_callback_)
            .Run(TetheringManager::EntitlementStatus::kReady);
      }
      break;
    case shill::CarrierEntitlement::Result::kGenericError:
      LOG(ERROR) << kEntitlementCheckAnomalyDetectorPrefix << "Generic error";
      [[fallthrough]];
    case shill::CarrierEntitlement::Result::kUnrecognizedUser:  // FALLTHROUGH
    case shill::CarrierEntitlement::Result::kUserNotAllowedToTether:
      if (!entitlement_check_callback_.is_null()) {
        std::move(entitlement_check_callback_)
            .Run(TetheringManager::EntitlementStatus::kNotAllowed);
      }
      // TODO(b/273355097): Disconnect DUN and end hotspot session.
      break;
  }
}

}  // namespace shill
