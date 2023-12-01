// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/wake_on_wifi.h"

#include <errno.h>
#include <linux/nl80211.h>
#include <stdio.h>
#include <sys/timerfd.h>

#include <algorithm>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/cancelable_callback.h>
#include <base/check.h>
#include <base/check_op.h>
#include <base/containers/contains.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/time/time.h>

#include <chromeos/dbus/service_constants.h>

#include "shill/error.h"
#include "shill/event_dispatcher.h"
#include "shill/logging.h"
#include "shill/metrics.h"
#include "shill/net/event_history.h"
#include "shill/net/netlink_manager.h"
#include "shill/net/nl80211_message.h"
#include "shill/store/property_accessor.h"
#include "shill/wifi/wifi.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kWiFi;
}  // namespace Logging

const char WakeOnWiFi::kWakeOnWiFiNotAllowed[] = "Wake on WiFi not allowed";
const int WakeOnWiFi::kMaxSetWakeOnWiFiRetries = 2;
const uint32_t WakeOnWiFi::kDefaultWakeToScanPeriodSeconds = 15 * 60;
const uint32_t WakeOnWiFi::kDefaultNetDetectScanPeriodSeconds = 2 * 60;
// We tolerate no more than 3 dark resumes per minute and 10 dark resumes per
// 10 minutes  before we disable wake on WiFi on the NIC.
const int WakeOnWiFi::kMaxDarkResumesPerPeriodShort = 3;
const int WakeOnWiFi::kMaxDarkResumesPerPeriodLong = 10;
// If a connection is not established during dark resume, give up and prepare
// the system to wake on SSID 1 second before suspending again.
// TODO(samueltan): link this to
// Manager::kTerminationActionsTimeoutMilliseconds rather than hard-coding
// this value.
base::TimeDelta WakeOnWiFi::DarkResumeActionsTimeout =
    base::Milliseconds(18500);
// Scanning 1 frequency takes ~100ms, so retrying 5 times on 8 frequencies will
// take about 4 seconds, which is how long a full scan typically takes.
const int WakeOnWiFi::kMaxFreqsForDarkResumeScanRetries = 8;
const int WakeOnWiFi::kMaxDarkResumeScanRetries = 5;

WakeOnWiFi::WakeOnWiFi(NetlinkManager* netlink_manager,
                       EventDispatcher* dispatcher,
                       Metrics* metrics,
                       RecordWakeReasonCallback record_wake_reason_callback)
    : dispatcher_(dispatcher),
      netlink_manager_(netlink_manager),
      metrics_(metrics),
      num_set_wake_on_wifi_retries_(0),
      wake_on_wifi_max_ssids_(0),
      wiphy_index_(0),
      wiphy_index_received_(false),
      wake_on_wifi_allowed_(false),
      // Wake on WiFi features disabled by default at run-time for boards that
      // support wake on WiFi. Rely on Chrome to enable appropriate features via
      // DBus.
      wake_on_wifi_features_enabled_(kWakeOnWiFiFeaturesEnabledNone),
      in_dark_resume_(false),
      wake_to_scan_period_seconds_(kDefaultWakeToScanPeriodSeconds),
      net_detect_scan_period_seconds_(kDefaultNetDetectScanPeriodSeconds),
      last_wake_reason_(kWakeTriggerUnsupported),
      force_wake_to_scan_timer_(false),
      dark_resume_scan_retries_left_(0),
      connected_before_suspend_(false),
      record_wake_reason_callback_(record_wake_reason_callback),
      weak_ptr_factory_(this) {
  netlink_handler_ = base::BindRepeating(&WakeOnWiFi::OnWakeupReasonReceived,
                                         weak_ptr_factory_.GetWeakPtr());
  netlink_manager_->AddBroadcastHandler(netlink_handler_);
  dhcp_lease_renewal_timer_ = brillo::timers::SimpleAlarmTimer::Create();
  wake_to_scan_timer_ = brillo::timers::SimpleAlarmTimer::Create();
}

WakeOnWiFi::~WakeOnWiFi() {
  netlink_manager_->RemoveBroadcastHandler(netlink_handler_);
}

void WakeOnWiFi::InitPropertyStore(PropertyStore* store) {
  store->RegisterDerivedBool(kWakeOnWiFiAllowedProperty,
                             BoolAccessor(new CustomAccessor<WakeOnWiFi, bool>(
                                 this, &WakeOnWiFi::GetWakeOnWiFiAllowed,
                                 &WakeOnWiFi::SetWakeOnWiFiAllowed)));
  store->RegisterDerivedString(
      kWakeOnWiFiFeaturesEnabledProperty,
      StringAccessor(new CustomAccessor<WakeOnWiFi, std::string>(
          this, &WakeOnWiFi::GetWakeOnWiFiFeaturesEnabled,
          &WakeOnWiFi::SetWakeOnWiFiFeaturesEnabled)));
  store->RegisterUint32(kWakeToScanPeriodSecondsProperty,
                        &wake_to_scan_period_seconds_);
  store->RegisterUint32(kNetDetectScanPeriodSecondsProperty,
                        &net_detect_scan_period_seconds_);
  store->RegisterBool(kForceWakeToScanTimerProperty,
                      &force_wake_to_scan_timer_);
  store->RegisterDerivedString(
      kLastWakeReasonProperty,
      StringAccessor(new CustomAccessor<WakeOnWiFi, std::string>(
          this, &WakeOnWiFi::GetLastWakeReason, nullptr)));
}

void WakeOnWiFi::Start() {}

bool WakeOnWiFi::GetWakeOnWiFiAllowed(Error* /*error*/) {
  return wake_on_wifi_allowed_;
}

bool WakeOnWiFi::SetWakeOnWiFiAllowed(const bool& allowed, Error* error) {
  if (wake_on_wifi_allowed_ == allowed) {
    return false;
  }
  // Disable all WiFi features first.
  if (!allowed) {
    SetWakeOnWiFiFeaturesEnabled(kWakeOnWiFiFeaturesEnabledNone, error);
  }
  wake_on_wifi_allowed_ = allowed;
  return true;
}

std::string WakeOnWiFi::GetWakeOnWiFiFeaturesEnabled(Error* error) {
  return wake_on_wifi_features_enabled_;
}

bool WakeOnWiFi::SetWakeOnWiFiFeaturesEnabled(const std::string& enabled,
                                              Error* error) {
  if (!wake_on_wifi_allowed_) {
    error->Populate(Error::kIllegalOperation, kWakeOnWiFiNotAllowed);
    SLOG(7) << __func__ << ": " << kWakeOnWiFiNotAllowed;
    return false;
  }
  if (wake_on_wifi_features_enabled_ == enabled) {
    return false;
  }
  if (enabled != kWakeOnWiFiFeaturesEnabledDarkConnect &&
      enabled != kWakeOnWiFiFeaturesEnabledNone) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Invalid Wake on WiFi feature");
    return false;
  }
  wake_on_wifi_features_enabled_ = enabled;
  return true;
}

std::string WakeOnWiFi::GetLastWakeReason(Error* /*error*/) {
  switch (last_wake_reason_) {
    case kWakeTriggerDisconnect:
      return kWakeOnWiFiReasonDisconnect;
    case kWakeTriggerSSID:
      return kWakeOnWiFiReasonSSID;
    default:
      return kWakeOnWiFiReasonUnknown;
  }
}

void WakeOnWiFi::RunSuspendActionsDoneCallback(const Error& error) {
  if (!suspend_actions_done_callback_.is_null()) {
    std::move(suspend_actions_done_callback_).Run(error);
  }
}

// static
bool WakeOnWiFi::ConfigureWiphyIndex(Nl80211Message* msg, int32_t index) {
  if (!msg->attributes()->CreateU32Attribute(NL80211_ATTR_WIPHY,
                                             "WIPHY index")) {
    return false;
  }
  if (!msg->attributes()->SetU32AttributeValue(NL80211_ATTR_WIPHY, index)) {
    return false;
  }
  return true;
}

// static
bool WakeOnWiFi::ConfigureDisableWakeOnWiFiMessage(SetWakeOnWiFiMessage* msg,
                                                   uint32_t wiphy_index,
                                                   Error* error) {
  if (!ConfigureWiphyIndex(msg, wiphy_index)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                          "Failed to configure Wiphy index.");
    return false;
  }
  return true;
}

// static
bool WakeOnWiFi::ConfigureSetWakeOnWiFiSettingsMessage(
    SetWakeOnWiFiMessage* msg,
    const std::set<WakeOnWiFiTrigger>& trigs,
    uint32_t wiphy_index,
    uint32_t net_detect_scan_period_seconds,
    const std::vector<ByteString>& allowed_ssids,
    Error* error) {
  if (trigs.empty()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "No triggers to configure.");
    return false;
  }
  if (!ConfigureWiphyIndex(msg, wiphy_index)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                          "Failed to configure Wiphy index.");
    return false;
  }
  if (!msg->attributes()->CreateNestedAttribute(NL80211_ATTR_WOWLAN_TRIGGERS,
                                                "WoWLAN Triggers")) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                          "Could not create nested attribute "
                          "NL80211_ATTR_WOWLAN_TRIGGERS");
    return false;
  }
  if (!msg->attributes()->SetNestedAttributeHasAValue(
          NL80211_ATTR_WOWLAN_TRIGGERS)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                          "Could not set nested attribute "
                          "NL80211_ATTR_WOWLAN_TRIGGERS");
    return false;
  }

  AttributeListRefPtr triggers;
  if (!msg->attributes()->GetNestedAttributeList(NL80211_ATTR_WOWLAN_TRIGGERS,
                                                 &triggers)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                          "Could not get nested attribute list "
                          "NL80211_ATTR_WOWLAN_TRIGGERS");
    return false;
  }
  // Add triggers.
  for (WakeOnWiFiTrigger t : trigs) {
    switch (t) {
      case kWakeTriggerDisconnect: {
        if (!triggers->CreateFlagAttribute(NL80211_WOWLAN_TRIG_DISCONNECT,
                                           "Wake on Disconnect")) {
          LOG(ERROR) << __func__
                     << ": Could not create flag attribute "
                        "NL80211_WOWLAN_TRIG_DISCONNECT";
          return false;
        }
        if (!triggers->SetFlagAttributeValue(NL80211_WOWLAN_TRIG_DISCONNECT,
                                             true)) {
          LOG(ERROR) << __func__
                     << ": Could not set flag attribute "
                        "NL80211_WOWLAN_TRIG_DISCONNECT";
          return false;
        }
        break;
      }
      case kWakeTriggerSSID: {
        if (!triggers->CreateNestedAttribute(NL80211_WOWLAN_TRIG_NET_DETECT,
                                             "Wake on SSID trigger")) {
          Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                                "Could not create nested attribute "
                                "NL80211_WOWLAN_TRIG_NET_DETECT");
          return false;
        }
        if (!triggers->SetNestedAttributeHasAValue(
                NL80211_WOWLAN_TRIG_NET_DETECT)) {
          Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                                "Could not set nested attribute "
                                "NL80211_WOWLAN_TRIG_NET_DETECT");
          return false;
        }
        AttributeListRefPtr scan_attributes;
        if (!triggers->GetNestedAttributeList(NL80211_WOWLAN_TRIG_NET_DETECT,
                                              &scan_attributes)) {
          Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                                "Could not get nested attribute list "
                                "NL80211_WOWLAN_TRIG_NET_DETECT");
          return false;
        }
        if (!scan_attributes->CreateU32Attribute(
                NL80211_ATTR_SCHED_SCAN_INTERVAL,
                "NL80211_ATTR_SCHED_SCAN_INTERVAL")) {
          Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                                "Could not get create U32 attribute "
                                "NL80211_ATTR_SCHED_SCAN_INTERVAL");
          return false;
        }
        if (!scan_attributes->SetU32AttributeValue(
                NL80211_ATTR_SCHED_SCAN_INTERVAL,
                net_detect_scan_period_seconds * 1000)) {
          Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                                "Could not get set U32 attribute "
                                "NL80211_ATTR_SCHED_SCAN_INTERVAL");
          return false;
        }
        if (!scan_attributes->CreateNestedAttribute(
                NL80211_ATTR_SCHED_SCAN_MATCH,
                "NL80211_ATTR_SCHED_SCAN_MATCH")) {
          Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                                "Could not create nested attribute list "
                                "NL80211_ATTR_SCHED_SCAN_MATCH");
          return false;
        }
        if (!scan_attributes->SetNestedAttributeHasAValue(
                NL80211_ATTR_SCHED_SCAN_MATCH)) {
          Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                                "Could not set nested attribute "
                                "NL80211_ATTR_SCAN_SSIDS");
          return false;
        }
        AttributeListRefPtr ssids;
        if (!scan_attributes->GetNestedAttributeList(
                NL80211_ATTR_SCHED_SCAN_MATCH, &ssids)) {
          Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                                "Could not get nested attribute list "
                                "NL80211_ATTR_SCHED_SCAN_MATCH");
          return false;
        }
        int ssid_num = 0;
        for (const ByteString& ssid_bytes : allowed_ssids) {
          if (!ssids->CreateNestedAttribute(
                  ssid_num, "NL80211_ATTR_SCHED_SCAN_MATCH_SINGLE")) {
            Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                                  "Could not create nested attribute list "
                                  "NL80211_ATTR_SCHED_SCAN_MATCH_SINGLE");
            return false;
          }
          if (!ssids->SetNestedAttributeHasAValue(ssid_num)) {
            Error::PopulateAndLog(
                FROM_HERE, error, Error::kOperationFailed,
                "Could not set value for nested attribute list "
                "NL80211_ATTR_SCHED_SCAN_MATCH_SINGLE");
            return false;
          }
          AttributeListRefPtr single_ssid;
          if (!ssids->GetNestedAttributeList(ssid_num, &single_ssid)) {
            Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                                  "Could not get nested attribute list "
                                  "NL80211_ATTR_SCHED_SCAN_MATCH_SINGLE");
            return false;
          }
          if (!single_ssid->CreateRawAttribute(
                  NL80211_SCHED_SCAN_MATCH_ATTR_SSID,
                  "NL80211_SCHED_SCAN_MATCH_ATTR_SSID")) {
            Error::PopulateAndLog(
                FROM_HERE, error, Error::kOperationFailed,
                "Could not create NL80211_SCHED_SCAN_MATCH_ATTR_SSID");
            return false;
          }
          if (!single_ssid->SetRawAttributeValue(
                  NL80211_SCHED_SCAN_MATCH_ATTR_SSID, ssid_bytes)) {
            Error::PopulateAndLog(
                FROM_HERE, error, Error::kOperationFailed,
                "Could not set NL80211_SCHED_SCAN_MATCH_ATTR_SSID");
            return false;
          }
          ++ssid_num;
        }
        break;
      }
      default: {
        LOG(ERROR) << __func__ << ": Unrecognized trigger";
        return false;
      }
    }
  }
  return true;
}

// static
bool WakeOnWiFi::ConfigureGetWakeOnWiFiSettingsMessage(
    GetWakeOnWiFiMessage* msg, uint32_t wiphy_index, Error* error) {
  if (!ConfigureWiphyIndex(msg, wiphy_index)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                          "Failed to configure Wiphy index.");
    return false;
  }
  return true;
}

// static
bool WakeOnWiFi::WakeOnWiFiSettingsMatch(
    const Nl80211Message& msg,
    const std::set<WakeOnWiFiTrigger>& trigs,
    uint32_t net_detect_scan_period_seconds,
    const std::vector<ByteString>& allowed_ssids) {
  if (msg.command() != NL80211_CMD_GET_WOWLAN &&
      msg.command() != NL80211_CMD_SET_WOWLAN) {
    LOG(ERROR) << __func__ << ": "
               << "Invalid message command";
    return false;
  }
  AttributeListConstRefPtr triggers;
  if (!msg.const_attributes()->ConstGetNestedAttributeList(
          NL80211_ATTR_WOWLAN_TRIGGERS, &triggers)) {
    // No triggers in the returned message, which is valid iff we expect there
    // to be no triggers programmed into the NIC.
    return trigs.empty();
  }
  // If we find a trigger in |msg| that we do not have a corresponding flag
  // for in |trigs|, we have a mismatch.
  bool unused_flag;
  AttributeListConstRefPtr unused_list;
  if (triggers->GetFlagAttributeValue(NL80211_WOWLAN_TRIG_DISCONNECT,
                                      &unused_flag) &&
      !base::Contains(trigs, kWakeTriggerDisconnect)) {
    SLOG(2) << __func__
            << ": Wake on disconnect trigger not expected but found";
    return false;
  }
  if (triggers->ConstGetNestedAttributeList(NL80211_WOWLAN_TRIG_NET_DETECT,
                                            &unused_list) &&
      !base::Contains(trigs, kWakeTriggerSSID)) {
    SLOG(2) << __func__ << ": Wake on SSID trigger not expected but found";
    return false;
  }
  // Check that each expected trigger is present in |msg| with matching
  // setting values.
  for (WakeOnWiFiTrigger t : trigs) {
    switch (t) {
      case kWakeTriggerDisconnect: {
        bool wake_on_disconnect;
        if (!triggers->GetFlagAttributeValue(NL80211_WOWLAN_TRIG_DISCONNECT,
                                             &wake_on_disconnect)) {
          LOG(ERROR) << __func__ << ": "
                     << "Could not get the flag NL80211_WOWLAN_TRIG_DISCONNECT";
          return false;
        }
        if (!wake_on_disconnect) {
          SLOG(2) << __func__ << ": Wake on disconnect flag not set.";
          return false;
        }
        break;
      }
      case kWakeTriggerSSID: {
        std::set<ByteString, decltype(&ByteString::IsLessThan)> expected_ssids(
            allowed_ssids.begin(), allowed_ssids.end(), ByteString::IsLessThan);
        AttributeListConstRefPtr scan_attributes;
        if (!triggers->ConstGetNestedAttributeList(
                NL80211_WOWLAN_TRIG_NET_DETECT, &scan_attributes)) {
          LOG(ERROR) << __func__ << ": "
                     << "Could not get nested attribute list "
                        "NL80211_WOWLAN_TRIG_NET_DETECT";
          return false;
        }
        uint32_t interval;
        if (!scan_attributes->GetU32AttributeValue(
                NL80211_ATTR_SCHED_SCAN_INTERVAL, &interval)) {
          LOG(ERROR) << __func__ << ": "
                     << "Could not get set U32 attribute "
                        "NL80211_ATTR_SCHED_SCAN_INTERVAL";
          return false;
        }
        if (interval != net_detect_scan_period_seconds * 1000) {
          SLOG(2) << __func__ << ": Net Detect scan period mismatch";
          return false;
        }
        AttributeListConstRefPtr ssids;
        if (!scan_attributes->ConstGetNestedAttributeList(
                NL80211_ATTR_SCHED_SCAN_MATCH, &ssids)) {
          LOG(ERROR) << __func__ << ": "
                     << "Could not get nested attribute list "
                        "NL80211_ATTR_SCHED_SCAN_MATCH";
          return false;
        }
        bool ssid_mismatch_found = false;
        size_t ssid_num_mismatch = expected_ssids.size();
        AttributeIdIterator ssid_iter(*ssids);
        AttributeListConstRefPtr single_ssid;
        ByteString ssid;
        int ssid_index;
        while (!ssid_iter.AtEnd()) {
          ssid.Clear();
          ssid_index = ssid_iter.GetId();
          if (!ssids->ConstGetNestedAttributeList(ssid_index, &single_ssid)) {
            LOG(ERROR) << __func__ << ": "
                       << "Could not get nested ssid attribute list #"
                       << ssid_index;
            return false;
          }
          if (!single_ssid->GetRawAttributeValue(
                  NL80211_SCHED_SCAN_MATCH_ATTR_SSID, &ssid)) {
            LOG(ERROR) << __func__ << ": "
                       << "Could not get attribute "
                          "NL80211_SCHED_SCAN_MATCH_ATTR_SSID";
            return false;
          }
          if (!base::Contains(expected_ssids, ssid)) {
            ssid_mismatch_found = true;
            break;
          } else {
            --ssid_num_mismatch;
          }
          ssid_iter.Advance();
        }
        if (ssid_mismatch_found || ssid_num_mismatch) {
          SLOG(2) << __func__ << ": Net Detect SSID mismatch";
          return false;
        }
        break;
      }
      default: {
        LOG(ERROR) << __func__ << ": Unrecognized trigger";
        return false;
      }
    }
  }
  return true;
}

void WakeOnWiFi::OnWakeOnWiFiSettingsErrorResponse(
    NetlinkManager::AuxiliaryMessageType type,
    const NetlinkMessage* raw_message) {
  Error error(Error::kOperationFailed);
  switch (type) {
    case NetlinkManager::kErrorFromKernel:
      if (!raw_message) {
        error.Populate(Error::kOperationFailed, "Unknown error from kernel");
        break;
      }
      if (raw_message->message_type() == ErrorAckMessage::GetMessageType()) {
        const ErrorAckMessage* error_ack_message =
            static_cast<const ErrorAckMessage*>(raw_message);
        if (error_ack_message->error() == EOPNOTSUPP) {
          error.Populate(Error::kNotSupported);
        }
      }
      break;

    case NetlinkManager::kUnexpectedResponseType:
      error.Populate(Error::kNotRegistered,
                     "Message not handled by regular message handler:");
      break;

    case NetlinkManager::kTimeoutWaitingForResponse:
      // CMD_SET_WOWLAN messages do not receive responses, so this error type
      // is received when NetlinkManager times out the message handler. Return
      // immediately rather than run the done callback since this event does
      // not signify the completion of suspend actions.
      return;
      break;

    default:
      error.Populate(
          Error::kOperationFailed,
          "Unexpected auxiliary message type: " + std::to_string(type));
      break;
  }
  RunSuspendActionsDoneCallback(error);
}

// static
void WakeOnWiFi::OnSetWakeOnWiFiConnectionResponse(
    const Nl80211Message& nl80211_message) {
  // NOP because kernel does not send a response to NL80211_CMD_SET_WOWLAN
  // requests.
}

void WakeOnWiFi::RequestWakeOnWiFiSettings() {
  SLOG(2) << __func__;
  Error e;
  GetWakeOnWiFiMessage get_wowlan_msg;
  CHECK(wiphy_index_received_);
  if (!ConfigureGetWakeOnWiFiSettingsMessage(&get_wowlan_msg, wiphy_index_,
                                             &e)) {
    LOG(ERROR) << e.message();
    return;
  }
  netlink_manager_->SendNl80211Message(
      &get_wowlan_msg,
      base::BindRepeating(&WakeOnWiFi::VerifyWakeOnWiFiSettings,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindRepeating(&NetlinkManager::OnAckDoNothing),
      base::BindRepeating(&NetlinkManager::OnNetlinkMessageError));
}

void WakeOnWiFi::VerifyWakeOnWiFiSettings(
    const Nl80211Message& nl80211_message) {
  SLOG(2) << __func__;
  if (WakeOnWiFiSettingsMatch(nl80211_message, wake_on_wifi_triggers_,
                              net_detect_scan_period_seconds_,
                              wake_on_allowed_ssids_)) {
    SLOG(2) << __func__ << ": "
            << "Wake on WiFi settings successfully verified";
    RunSuspendActionsDoneCallback(Error(Error::kSuccess));
  } else {
    LOG(ERROR) << __func__
               << " failed: discrepancy between wake-on-packet "
                  "settings on NIC and those in local data "
                  "structure detected";
    RetrySetWakeOnWiFiConnections();
  }
}

void WakeOnWiFi::ApplyWakeOnWiFiSettings() {
  SLOG(2) << __func__;
  if (!wiphy_index_received_) {
    LOG(ERROR) << "Interface index not yet received";
    return;
  }
  if (wake_on_wifi_triggers_.empty()) {
    SLOG(1) << "No triggers to be programmed, so disable wake on WiFi";
    DisableWakeOnWiFi();
    return;
  }
  Error error;
  SetWakeOnWiFiMessage set_wowlan_msg;
  if (!ConfigureSetWakeOnWiFiSettingsMessage(
          &set_wowlan_msg, wake_on_wifi_triggers_, wiphy_index_,
          net_detect_scan_period_seconds_, wake_on_allowed_ssids_, &error)) {
    LOG(ERROR) << error.message();
    RunSuspendActionsDoneCallback(
        Error(Error::kOperationFailed, error.message()));
    return;
  }
  if (!netlink_manager_->SendNl80211Message(
          &set_wowlan_msg,
          base::BindRepeating(&WakeOnWiFi::OnSetWakeOnWiFiConnectionResponse),
          base::BindRepeating(&NetlinkManager::OnAckDoNothing),
          base::BindRepeating(&WakeOnWiFi::OnWakeOnWiFiSettingsErrorResponse,
                              weak_ptr_factory_.GetWeakPtr()))) {
    RunSuspendActionsDoneCallback(
        Error(Error::kOperationFailed, "SendNl80211Message failed"));
    return;
  }

  verify_wake_on_wifi_settings_callback_.Reset(base::BindOnce(
      &WakeOnWiFi::RequestWakeOnWiFiSettings, weak_ptr_factory_.GetWeakPtr()));
  dispatcher_->PostDelayedTask(
      FROM_HERE, verify_wake_on_wifi_settings_callback_.callback(),
      kVerifyWakeOnWiFiSettingsDelay);
}

void WakeOnWiFi::DisableWakeOnWiFi() {
  SLOG(2) << __func__;
  Error error;
  SetWakeOnWiFiMessage disable_wowlan_msg;
  CHECK(wiphy_index_received_);
  if (!ConfigureDisableWakeOnWiFiMessage(&disable_wowlan_msg, wiphy_index_,
                                         &error)) {
    LOG(ERROR) << error.message();
    RunSuspendActionsDoneCallback(
        Error(Error::kOperationFailed, error.message()));
    return;
  }
  wake_on_wifi_triggers_.clear();
  if (!netlink_manager_->SendNl80211Message(
          &disable_wowlan_msg,
          base::BindRepeating(&WakeOnWiFi::OnSetWakeOnWiFiConnectionResponse),
          base::BindRepeating(&NetlinkManager::OnAckDoNothing),
          base::BindRepeating(&WakeOnWiFi::OnWakeOnWiFiSettingsErrorResponse,
                              weak_ptr_factory_.GetWeakPtr()))) {
    RunSuspendActionsDoneCallback(
        Error(Error::kOperationFailed, "SendNl80211Message failed"));
    return;
  }

  verify_wake_on_wifi_settings_callback_.Reset(base::BindOnce(
      &WakeOnWiFi::RequestWakeOnWiFiSettings, weak_ptr_factory_.GetWeakPtr()));
  dispatcher_->PostDelayedTask(
      FROM_HERE, verify_wake_on_wifi_settings_callback_.callback(),
      kVerifyWakeOnWiFiSettingsDelay);
}

void WakeOnWiFi::RetrySetWakeOnWiFiConnections() {
  SLOG(2) << __func__;
  if (num_set_wake_on_wifi_retries_ < kMaxSetWakeOnWiFiRetries) {
    ApplyWakeOnWiFiSettings();
    ++num_set_wake_on_wifi_retries_;
  } else {
    SLOG(2) << __func__ << ": max retry attempts reached";
    num_set_wake_on_wifi_retries_ = 0;
    RunSuspendActionsDoneCallback(Error(Error::kOperationFailed));
  }
}

bool WakeOnWiFi::WakeOnWiFiDisabled() {
  return wake_on_wifi_features_enabled_ == kWakeOnWiFiFeaturesEnabledNone;
}

bool WakeOnWiFi::WakeOnWiFiDarkConnectEnabledAndSupported() {
  if (wake_on_wifi_features_enabled_ == kWakeOnWiFiFeaturesEnabledNone) {
    return false;
  }
  if (!base::Contains(wake_on_wifi_triggers_supported_,
                      kWakeTriggerDisconnect) ||
      !base::Contains(wake_on_wifi_triggers_supported_, kWakeTriggerSSID)) {
    return false;
  }
  return true;
}

void WakeOnWiFi::ParseWakeOnWiFiCapabilities(
    const Nl80211Message& nl80211_message) {
  // Verify NL80211_CMD_NEW_WIPHY.
  if (nl80211_message.command() != NewWiphyMessage::kCommand) {
    LOG(ERROR) << "Received unexpected command:" << nl80211_message.command();
    return;
  }
  AttributeListConstRefPtr triggers_supported;
  if (nl80211_message.const_attributes()->ConstGetNestedAttributeList(
          NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED, &triggers_supported)) {
    bool disconnect_supported = false;
    if (triggers_supported->GetFlagAttributeValue(
            NL80211_WOWLAN_TRIG_DISCONNECT, &disconnect_supported)) {
      if (disconnect_supported) {
        wake_on_wifi_triggers_supported_.insert(
            WakeOnWiFi::kWakeTriggerDisconnect);
        SLOG(7) << "Waking on disconnect supported by this WiFi device";
      }
    }
    if (triggers_supported->GetU32AttributeValue(NL80211_WOWLAN_TRIG_NET_DETECT,
                                                 &wake_on_wifi_max_ssids_)) {
      wake_on_wifi_triggers_supported_.insert(WakeOnWiFi::kWakeTriggerSSID);
      SLOG(7) << "Waking on up to " << wake_on_wifi_max_ssids_
              << " SSIDs supported by this WiFi device";
    }
  }
}

void WakeOnWiFi::OnWakeupReasonReceived(const NetlinkMessage& netlink_message) {
  // We only handle wakeup reason messages in this handler, which is are
  // nl80211 messages with the NL80211_CMD_SET_WOWLAN command.
  if (netlink_message.message_type() != Nl80211Message::GetMessageType()) {
    SLOG(7) << __func__ << ": "
            << "Not a NL80211 Message";
    return;
  }
  const Nl80211Message& wakeup_reason_msg =
      *reinterpret_cast<const Nl80211Message*>(&netlink_message);
  if (wakeup_reason_msg.command() != SetWakeOnWiFiMessage::kCommand) {
    SLOG(7) << __func__ << ": "
            << "Not a NL80211_CMD_SET_WOWLAN message";
    return;
  }
  uint32_t wiphy_index;
  if (!wakeup_reason_msg.const_attributes()->GetU32AttributeValue(
          NL80211_ATTR_WIPHY, &wiphy_index)) {
    LOG(ERROR) << "NL80211_CMD_NEW_WIPHY had no NL80211_ATTR_WIPHY";
    return;
  }
  if (!wiphy_index_received_) {
    SLOG(7) << __func__ << ": "
            << "Interface index not yet received";
    return;
  }
  if (wiphy_index != wiphy_index_) {
    SLOG(7) << __func__ << ": "
            << "Wakeup reason not meant for this interface";
    return;
  }
  SLOG(2) << __func__ << ": "
          << "Parsing wakeup reason";
  AttributeListConstRefPtr triggers;
  if (!wakeup_reason_msg.const_attributes()->ConstGetNestedAttributeList(
          NL80211_ATTR_WOWLAN_TRIGGERS, &triggers)) {
    SLOG(2) << __func__ << ": "
            << "Wakeup reason: Not wake on WiFi related";
    return;
  }
  bool wake_flag;
  if (triggers->GetFlagAttributeValue(NL80211_WOWLAN_TRIG_DISCONNECT,
                                      &wake_flag)) {
    SLOG(2) << __func__ << ": "
            << "Wakeup reason: Disconnect";
    last_wake_reason_ = kWakeTriggerDisconnect;
    record_wake_reason_callback_.Run(GetLastWakeReason(nullptr));
    return;
  }
  AttributeListConstRefPtr results_list;
  if (triggers->ConstGetNestedAttributeList(
          NL80211_WOWLAN_TRIG_NET_DETECT_RESULTS, &results_list)) {
    // It is possible that NL80211_WOWLAN_TRIG_NET_DETECT_RESULTS is present
    // along with another wake trigger attribute. What this means is that the
    // firmware has detected a network, but the platform did not actually wake
    // on the detection of that network. In these cases, we will not parse the
    // net detect results; we return after parsing and reporting the actual
    // wakeup reason above.
    SLOG(2) << __func__ << ": "
            << "Wakeup reason: SSID";
    last_wake_reason_ = kWakeTriggerSSID;
    record_wake_reason_callback_.Run(GetLastWakeReason(nullptr));
    last_ssid_match_freqs_ = ParseWakeOnSSIDResults(results_list);
    return;
  }
  SLOG(2) << __func__ << ": "
          << "Wakeup reason: Not supported";
}

void WakeOnWiFi::OnBeforeSuspend(
    bool is_connected,
    const std::vector<ByteString>& allowed_ssids,
    ResultCallback done_callback,
    base::OnceClosure renew_dhcp_lease_callback,
    base::OnceClosure remove_supplicant_networks_callback,
    std::optional<base::TimeDelta> time_to_next_lease_renewal) {
  connected_before_suspend_ = is_connected;
  if (WakeOnWiFiDisabled()) {
    // Wake on WiFi not supported or not enabled, so immediately report success.
    std::move(done_callback).Run(Error(Error::kSuccess));
    return;
  }
  LOG(INFO) << __func__ << ": Wake on WiFi features enabled: "
            << wake_on_wifi_features_enabled_;
  suspend_actions_done_callback_ = std::move(done_callback);
  wake_on_allowed_ssids_ = allowed_ssids;
  dark_resume_history_.Clear();
  if (time_to_next_lease_renewal && is_connected &&
      *time_to_next_lease_renewal < kImmediateDHCPLeaseRenewalThreshold) {
    // Renew DHCP lease immediately if we have one that is expiring soon.
    std::move(renew_dhcp_lease_callback).Run();
    dispatcher_->PostTask(
        FROM_HERE,
        base::BindOnce(&WakeOnWiFi::BeforeSuspendActions,
                       weak_ptr_factory_.GetWeakPtr(), is_connected,
                       std::nullopt,
                       std::move(remove_supplicant_networks_callback)));
  } else {
    dispatcher_->PostTask(
        FROM_HERE,
        base::BindOnce(&WakeOnWiFi::BeforeSuspendActions,
                       weak_ptr_factory_.GetWeakPtr(), is_connected,
                       time_to_next_lease_renewal,
                       std::move(remove_supplicant_networks_callback)));
  }
}

void WakeOnWiFi::OnAfterResume() {
  SLOG(1) << __func__;
  wake_to_scan_timer_->Stop();
  dhcp_lease_renewal_timer_->Stop();
  if (WakeOnWiFiDarkConnectEnabledAndSupported()) {
    // Unconditionally disable wake on WiFi on resume if these features
    // were enabled before the last suspend.
    DisableWakeOnWiFi();
  }
}

void WakeOnWiFi::OnDarkResume(
    bool is_connected,
    const std::vector<ByteString>& allowed_ssids,
    ResultCallback done_callback,
    base::OnceClosure renew_dhcp_lease_callback,
    InitiateScanCallback initiate_scan_callback,
    const base::RepeatingClosure& remove_supplicant_networks_callback) {
  if (WakeOnWiFiDisabled()) {
    // Wake on WiFi not supported or not enabled, so immediately report success.
    std::move(done_callback).Run(Error(Error::kSuccess));
    return;
  }

  LOG(INFO) << __func__ << ": "
            << "Wake reason " << last_wake_reason_;
  dark_resume_scan_retries_left_ = 0;
  suspend_actions_done_callback_ = std::move(done_callback);
  wake_on_allowed_ssids_ = allowed_ssids;

  if (last_wake_reason_ == kWakeTriggerSSID ||
      last_wake_reason_ == kWakeTriggerDisconnect ||
      (last_wake_reason_ == kWakeTriggerUnsupported && !is_connected)) {
    // We want to disable wake on WiFi in two specific cases of thrashing:
    //   1) Repeatedly waking on SSID in the presence of an AP that the WiFi
    //      device cannot connect to
    //   2) Repeatedly waking on disconnect because of a an AP that repeatedly
    //      disconnects the WiFi device but allows it to reconnect immediately
    // Therefore, we only count dark resumes caused by either of these wake
    // reasons when deciding whether or not to throttle wake on WiFi.
    //
    // In case the WiFi driver does not support wake reason reporting, we use
    // the WiFi device's connection status on dark resume as a proxy for these
    // wake reasons (i.e. when we wake on either SSID or disconnect, we should
    // be disconnected). This is not reliable for wake on disconnect, as the
    // WiFi device will report that it is connected as it enters dark
    // resume (crbug.com/505072).
    dark_resume_history_.RecordEvent();
  }
  if (dark_resume_history_.CountEventsWithinInterval(
          kDarkResumeFrequencySamplingPeriodShort.InSeconds(),
          EventHistory::kClockTypeBoottime) >= kMaxDarkResumesPerPeriodShort ||
      dark_resume_history_.CountEventsWithinInterval(
          kDarkResumeFrequencySamplingPeriodLong.InSeconds(),
          EventHistory::kClockTypeBoottime) >= kMaxDarkResumesPerPeriodLong) {
    LOG(ERROR) << __func__ << ": "
               << "Too many dark resumes; disabling wake on WiFi temporarily";
    // If too many dark resumes have triggered recently, we are probably
    // thrashing. Stop this by disabling wake on WiFi on the NIC, and
    // starting the wake to scan timer so that normal wake on WiFi behavior
    // resumes only |wake_to_scan_period_seconds_| later.
    dhcp_lease_renewal_timer_->Stop();
    wake_to_scan_timer_->Start(FROM_HERE,
                               base::Seconds(wake_to_scan_period_seconds_),
                               base::DoNothing());
    DisableWakeOnWiFi();
    dark_resume_history_.Clear();
    last_ssid_match_freqs_.clear();
    return;
  }

  switch (last_wake_reason_) {
    case kWakeTriggerSSID:
    case kWakeTriggerDisconnect: {
      remove_supplicant_networks_callback.Run();
      InitiateScanInDarkResume(std::move(initiate_scan_callback),
                               last_wake_reason_ == kWakeTriggerSSID
                                   ? last_ssid_match_freqs_
                                   : WiFi::FreqSet());
      break;
    }
    case kWakeTriggerUnsupported:
    default: {
      if (is_connected) {
        std::move(renew_dhcp_lease_callback).Run();
      } else {
        remove_supplicant_networks_callback.Run();
        InitiateScanInDarkResume(std::move(initiate_scan_callback),
                                 WiFi::FreqSet());
      }
    }
  }

  // Only set dark resume to true after checking if we need to disable wake on
  // WiFi since calling WakeOnWiFi::DisableWakeOnWiFi directly bypasses
  // WakeOnWiFi::BeforeSuspendActions where |in_dark_resume_| is set to false.
  in_dark_resume_ = true;
  // Assume that we are disconnected if we time out. Consequently, we do not
  // need to start a DHCP lease renewal timer.
  dark_resume_actions_timeout_callback_.Reset(base::BindOnce(
      &WakeOnWiFi::BeforeSuspendActions, weak_ptr_factory_.GetWeakPtr(), false,
      std::nullopt, remove_supplicant_networks_callback));
  dispatcher_->PostDelayedTask(FROM_HERE,
                               dark_resume_actions_timeout_callback_.callback(),
                               DarkResumeActionsTimeout);
}

void WakeOnWiFi::BeforeSuspendActions(
    bool is_connected,
    std::optional<base::TimeDelta> time_to_next_lease_renewal,
    base::OnceClosure remove_supplicant_networks_callback) {
  LOG(INFO) << __func__ << ": "
            << (is_connected ? "connected" : "not connected");
  // Note: No conditional compilation because all entry points to this functions
  // are already conditionally compiled based on DISABLE_WAKE_ON_WIFI.

  last_ssid_match_freqs_.clear();
  last_wake_reason_ = kWakeTriggerUnsupported;
  // Add relevant triggers to be programmed into the NIC.
  wake_on_wifi_triggers_.clear();
  if (WakeOnWiFiDarkConnectEnabledAndSupported()) {
    if (is_connected) {
      SLOG(2) << __func__ << ": "
              << "Enabling wake on disconnect";
      wake_on_wifi_triggers_.insert(kWakeTriggerDisconnect);
      wake_on_wifi_triggers_.erase(kWakeTriggerSSID);
      wake_to_scan_timer_->Stop();
      if (time_to_next_lease_renewal) {
        // Timer callback is NO-OP since dark resume logic (the
        // kWakeTriggerUnsupported case) will initiate DHCP lease renewal.
        dhcp_lease_renewal_timer_->Start(FROM_HERE, *time_to_next_lease_renewal,
                                         base::DoNothing());
      }
    } else {
      // Force a disconnect in case supplicant is currently in the process of
      // connecting, and remove all networks so scans triggered in dark resume
      // are passive.
      std::move(remove_supplicant_networks_callback).Run();
      dhcp_lease_renewal_timer_->Stop();
      wake_on_wifi_triggers_.erase(kWakeTriggerDisconnect);
      if (!wake_on_allowed_ssids_.empty()) {
        SLOG(2) << __func__ << ": "
                << "Enabling wake on SSID";
        wake_on_wifi_triggers_.insert(kWakeTriggerSSID);
      }
      int num_extra_ssids =
          wake_on_allowed_ssids_.size() - wake_on_wifi_max_ssids_;
      if (num_extra_ssids > 0 || force_wake_to_scan_timer_) {
        SLOG(2) << __func__ << ": "
                << "Starting wake to scan timer - "
                << (num_extra_ssids > 0 ? "extra SSIDs" : "forced");
        if (num_extra_ssids > 0) {
          SLOG(2) << __func__ << ": " << num_extra_ssids << " extra SSIDs.";
        }
        // Start wake to scan timer in case the only SSIDs available for
        // auto-connect during suspend are the ones that we do not program our
        // NIC to wake on.
        // Timer callback is NO-OP since dark resume logic (the
        // kWakeTriggerUnsupported case) will initiate a passive scan.
        wake_to_scan_timer_->Start(FROM_HERE,
                                   base::Seconds(wake_to_scan_period_seconds_),
                                   base::DoNothing());
        // Trim SSID list to the max size that the NIC supports.
        wake_on_allowed_ssids_.resize(wake_on_wifi_max_ssids_);
      }
    }
  }

  // Only call Cancel() here since it deallocates the underlying callback that
  // |remove_supplicant_networks_callback| references, which is invoked above.
  dark_resume_actions_timeout_callback_.Cancel();

  if (!in_dark_resume_ && wake_on_wifi_triggers_.empty()) {
    // No need program NIC on normal resume in this case since wake on WiFi
    // would already have been disabled on the last (non-dark) resume.
    SLOG(1) << "No need to disable wake on WiFi on NIC in regular "
               "suspend";
    RunSuspendActionsDoneCallback(Error(Error::kSuccess));
    return;
  }

  in_dark_resume_ = false;
  ApplyWakeOnWiFiSettings();
}

// static
WiFi::FreqSet WakeOnWiFi::ParseWakeOnSSIDResults(
    AttributeListConstRefPtr results_list) {
  WiFi::FreqSet freqs;
  AttributeIdIterator results_iter(*results_list);
  if (results_iter.AtEnd()) {
    SLOG(2) << __func__ << ": "
            << "Wake on SSID results not available";
    return freqs;
  }
  AttributeListConstRefPtr result;
  int ssid_num = 0;
  for (; !results_iter.AtEnd(); results_iter.Advance()) {
    if (!results_list->ConstGetNestedAttributeList(results_iter.GetId(),
                                                   &result)) {
      LOG(ERROR) << __func__ << ": "
                 << "Could not get result #" << results_iter.GetId()
                 << " in ssid_results";
      return freqs;
    }
    ByteString ssid_bytestring;
    if (!result->GetRawAttributeValue(NL80211_ATTR_SSID, &ssid_bytestring)) {
      // We assume that the SSID attribute must be present in each result.
      LOG(ERROR) << __func__ << ": "
                 << "No SSID available for result #" << results_iter.GetId();
      continue;
    }
    SLOG(2) << "SSID " << ssid_num << ": "
            << std::string(ssid_bytestring.GetConstData(),
                           ssid_bytestring.GetConstData() +
                               ssid_bytestring.GetLength());
    AttributeListConstRefPtr frequencies;
    uint32_t freq_value;
    if (result->ConstGetNestedAttributeList(NL80211_ATTR_SCAN_FREQUENCIES,
                                            &frequencies)) {
      AttributeIdIterator freq_iter(*frequencies);
      for (; !freq_iter.AtEnd(); freq_iter.Advance()) {
        if (frequencies->GetU32AttributeValue(freq_iter.GetId(), &freq_value)) {
          freqs.insert(freq_value);
          SLOG(7) << "Frequency: " << freq_value;
        }
      }
    } else {
      SLOG(2) << __func__ << ": "
              << "No frequencies available for result #"
              << results_iter.GetId();
    }
    ++ssid_num;
  }
  return freqs;
}

void WakeOnWiFi::InitiateScanInDarkResume(
    InitiateScanCallback initiate_scan_callback, const WiFi::FreqSet& freqs) {
  SLOG(2) << __func__;
  if (!freqs.empty() && freqs.size() <= kMaxFreqsForDarkResumeScanRetries) {
    SLOG(2) << __func__ << ": "
            << "Allowing up to " << kMaxDarkResumeScanRetries
            << " retries for passive scan on " << freqs.size()
            << " frequencies";
    dark_resume_scan_retries_left_ = kMaxDarkResumeScanRetries;
  }
  std::move(initiate_scan_callback).Run(freqs);
}

void WakeOnWiFi::OnConnectedAndReachable(
    std::optional<base::TimeDelta> time_to_next_lease_renewal) {
  SLOG(2) << __func__;
  if (WakeOnWiFiDisabled()) {
    SLOG(2) << "Wake on WiFi not enabled";
  }
  if (!in_dark_resume_) {
    SLOG(2) << "Not in dark resume";
    return;
  }
  BeforeSuspendActions(true, time_to_next_lease_renewal, base::DoNothing());
}

void WakeOnWiFi::ReportConnectedToServiceAfterWake(bool is_connected,
                                                   int seconds_in_suspend) {
  if (connected_before_suspend_) {
    LOG(INFO) << "NotifySuspendDurationAfterWake:"
              << " is_connected: " << is_connected
              << " is_dark_connect_enabled: "
              << WakeOnWiFiDarkConnectEnabledAndSupported()
              << " seconds_in_suspend: " << seconds_in_suspend;
  }
}

void WakeOnWiFi::OnNoAutoConnectableServicesAfterScan(
    const std::vector<ByteString>& allowed_ssids,
    base::OnceClosure remove_supplicant_networks_callback,
    InitiateScanCallback initiate_scan_callback) {
  SLOG(2) << __func__ << ": "
          << (in_dark_resume_ ? "In dark resume" : "Not in dark resume");
  if (WakeOnWiFiDisabled()) {
    // The scan is not triggered by us, ignore.
    return;
  }
  if (!in_dark_resume_) {
    return;
  }
  if (dark_resume_scan_retries_left_) {
    --dark_resume_scan_retries_left_;
    SLOG(2) << __func__ << ": "
            << "Retrying dark resume scan (" << dark_resume_scan_retries_left_
            << " tries left)";
    // Note: a scan triggered by supplicant in dark resume might cause a
    // retry, but we consider this acceptable.
    std::move(initiate_scan_callback).Run(last_ssid_match_freqs_);
  } else {
    wake_on_allowed_ssids_ = allowed_ssids;
    // Assume that if there are no services available for auto-connect, then we
    // cannot be connected. Therefore, no need for lease renewal parameters.
    BeforeSuspendActions(false, std::nullopt,
                         std::move(remove_supplicant_networks_callback));
  }
}

void WakeOnWiFi::OnWiphyIndexReceived(uint32_t index) {
  wiphy_index_ = index;
  wiphy_index_received_ = true;
}

void WakeOnWiFi::OnScanStarted(bool is_active_scan) {
  if (!in_dark_resume_) {
    return;
  }
  if (last_wake_reason_ == kWakeTriggerUnsupported) {
    // We don't expect active scans to be started when we wake on RTC timers.
    if (is_active_scan) {
      LOG(ERROR) << "Unexpected active scan launched in dark resume";
    }
  }
}

void WakeOnWiFi::OnScanCompleted() {}

}  // namespace shill
