// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/mobile_operator_info.h"

#include <algorithm>

#include "shill/cellular/mobile_operator_mapper.h"
#include "shill/ipconfig.h"
#include "shill/logging.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kCellular;
}  // namespace Logging

// static
const char MobileOperatorInfo::kDefaultDatabasePath[] =
    "/usr/share/shill/serviceproviders.pbf";
// The exclusive-override db can be used to replace the default modb.
const char MobileOperatorInfo::kExclusiveOverrideDatabasePath[] =
    "/var/cache/shill/serviceproviders-exclusive-override.pbf";

std::string MobileOperatorInfo::GetLogPrefix(const char* func) const {
  return info_owner_ + ": " + func;
}

MobileOperatorInfo::MobileOperatorInfo(EventDispatcher* dispatcher,
                                       const std::string& info_owner,
                                       MobileOperatorMapper* home,
                                       MobileOperatorMapper* serving)
    : info_owner_(info_owner) {
  home_.reset(home);
  serving_.reset(serving);
  AddDefaultDatabasePaths();
}

MobileOperatorInfo::MobileOperatorInfo(EventDispatcher* dispatcher,
                                       const std::string& info_owner)
    : info_owner_(info_owner) {
  home_ =
      std::make_unique<MobileOperatorMapper>(dispatcher, info_owner + ":home");
  serving_ = std::make_unique<MobileOperatorMapper>(dispatcher,
                                                    info_owner + ":serving");
  AddDefaultDatabasePaths();
}

MobileOperatorInfo::~MobileOperatorInfo() = default;

void MobileOperatorInfo::AddDefaultDatabasePaths() {
  if (base::PathExists(base::FilePath(kExclusiveOverrideDatabasePath)))
    AddDatabasePath(base::FilePath(kExclusiveOverrideDatabasePath));
  else
    AddDatabasePath(base::FilePath(kDefaultDatabasePath));
}
void MobileOperatorInfo::ClearDatabasePaths() {
  SLOG(3) << GetLogPrefix(__func__);
  home_->ClearDatabasePaths();
  serving_->ClearDatabasePaths();
}

void MobileOperatorInfo::AddDatabasePath(const base::FilePath& absolute_path) {
  SLOG(3) << GetLogPrefix(__func__);
  home_->AddDatabasePath(absolute_path);
  serving_->AddDatabasePath(absolute_path);
}

bool MobileOperatorInfo::Init() {
  auto result_home = home_->Init(
      base::BindRepeating(&MobileOperatorInfo::OnHomeOperatorChanged,
                          weak_ptr_factory_.GetWeakPtr()));
  auto result_serving = serving_->Init(
      base::BindRepeating(&MobileOperatorInfo::OnServingOperatorChanged,
                          weak_ptr_factory_.GetWeakPtr()));
  SLOG(3) << GetLogPrefix(__func__) << ": Result["
          << (result_home && result_serving) << "]";
  return result_home && result_serving;
}

void MobileOperatorInfo::AddObserver(MobileOperatorInfo::Observer* observer) {
  SLOG(3) << GetLogPrefix(__func__);
  observers_.AddObserver(observer);
}

void MobileOperatorInfo::RemoveObserver(
    MobileOperatorInfo::Observer* observer) {
  SLOG(3) << GetLogPrefix(__func__);
  observers_.RemoveObserver(observer);
}

void MobileOperatorInfo::OnHomeOperatorChanged() {
  SLOG(3) << GetLogPrefix(__func__);
  for (MobileOperatorInfo::Observer& observer : observers_)
    observer.OnOperatorChanged();
}

void MobileOperatorInfo::OnServingOperatorChanged() {
  SLOG(3) << GetLogPrefix(__func__);
  for (MobileOperatorInfo::Observer& observer : observers_)
    observer.OnOperatorChanged();
}

bool MobileOperatorInfo::IsMobileNetworkOperatorKnown() const {
  auto result = home_->IsMobileNetworkOperatorKnown();
  SLOG(3) << GetLogPrefix(__func__) << ": Result[" << result << "]";
  return result;
}

bool MobileOperatorInfo::IsMobileVirtualNetworkOperatorKnown() const {
  auto result = home_->IsMobileVirtualNetworkOperatorKnown();
  SLOG(3) << GetLogPrefix(__func__) << ": Result[" << result << "]";
  return result;
}

bool MobileOperatorInfo::IsServingMobileNetworkOperatorKnown() const {
  auto result = serving_->IsMobileNetworkOperatorKnown();
  SLOG(3) << GetLogPrefix(__func__) << ": Result[" << result << "]";
  return result;
}

// ///////////////////////////////////////////////////////////////////////////
// Getters.
const std::string& MobileOperatorInfo::uuid() const {
  return home_->uuid();
}

const std::string& MobileOperatorInfo::operator_name() const {
  return home_->operator_name();
}

const std::string& MobileOperatorInfo::country() const {
  return home_->country();
}

const std::string& MobileOperatorInfo::mccmnc() const {
  return home_->mccmnc();
}

const std::string& MobileOperatorInfo::gid1() const {
  return home_->gid1();
}

const std::string& MobileOperatorInfo::serving_uuid() const {
  return serving_->uuid();
}

const std::string& MobileOperatorInfo::serving_operator_name() const {
  return serving_->operator_name();
}

const std::string& MobileOperatorInfo::serving_country() const {
  return serving_->country();
}

const std::string& MobileOperatorInfo::serving_mccmnc() const {
  return serving_->mccmnc();
}

const std::vector<MobileOperatorMapper::MobileAPN>&
MobileOperatorInfo::apn_list() const {
  return home_->apn_list();
}

const std::vector<MobileOperatorMapper::OnlinePortal>&
MobileOperatorInfo::olp_list() const {
  return home_->olp_list();
}

std::string MobileOperatorInfo::friendly_operator_name(bool is_roaming) const {
  std::string operator_name;
  std::string mccmnc;
  if (IsServingMobileNetworkOperatorKnown()) {
    operator_name = serving_->operator_name();
    mccmnc = serving_->mccmnc();
  } else if (IsMobileNetworkOperatorKnown()) {
    operator_name = home_->operator_name();
    mccmnc = home_->mccmnc();
  }

  std::string service_name;
  if (!operator_name.empty()) {
    // If roaming, try to show "<home-provider> | <serving-operator>", per 3GPP
    // rules (TS 31.102 and annex A of 122.101).
    if (is_roaming && !home_->operator_name().empty() &&
        home_->operator_name() != operator_name) {
      service_name += home_->operator_name() + " | ";
    }
    service_name += operator_name;
  } else if (!mccmnc.empty()) {
    // We could not get a name for the operator, just use the code.
    service_name = "cellular_" + mccmnc;
  }
  SLOG(3) << GetLogPrefix(__func__) << ": Result[" << service_name
          << "]. is_roaming:" << std::boolalpha << is_roaming;
  return service_name;
}

bool MobileOperatorInfo::requires_roaming() const {
  if (!home_->IsMobileNetworkOperatorKnown() &&
      !home_->IsMobileVirtualNetworkOperatorKnown())
    return false;
  return home_->requires_roaming() ||
         home_->RequiresRoamingOnOperator(serving_.get());
}

bool MobileOperatorInfo::tethering_allowed() const {
  return home_->tethering_allowed();
}

bool MobileOperatorInfo::use_dun_apn_as_default() const {
  return home_->use_dun_apn_as_default();
}

const MobileOperatorMapper::EntitlementConfig&
MobileOperatorInfo::entitlement_config() const {
  return home_->entitlement_config();
}

int32_t MobileOperatorInfo::mtu() const {
  // Choose the smaller mtu size.
  if (serving_->mtu() != IPConfig::kUndefinedMTU &&
      home_->mtu() != IPConfig::kUndefinedMTU)
    return std::min(serving_->mtu(), home_->mtu());
  else if (home_->mtu() != IPConfig::kUndefinedMTU)
    return home_->mtu();

  return serving_->mtu();
}

// ///////////////////////////////////////////////////////////////////////////
// Functions used to notify this object of operator data changes.
void MobileOperatorInfo::UpdateIMSI(const std::string& imsi) {
  home_->UpdateIMSI(imsi);
}

void MobileOperatorInfo::UpdateICCID(const std::string& iccid) {
  home_->UpdateICCID(iccid);
}

void MobileOperatorInfo::UpdateMCCMNC(const std::string& mccmnc) {
  home_->UpdateMCCMNC(mccmnc);
}

void MobileOperatorInfo::UpdateOperatorName(const std::string& operator_name) {
  home_->UpdateOperatorName(operator_name);
}

void MobileOperatorInfo::UpdateServingMCCMNC(const std::string& mccmnc) {
  serving_->UpdateMCCMNC(mccmnc);
}

void MobileOperatorInfo::UpdateServingOperatorName(
    const std::string& operator_name) {
  serving_->UpdateOperatorName(operator_name);
}

void MobileOperatorInfo::UpdateGID1(const std::string& gid1) {
  home_->UpdateGID1(gid1);
}

void MobileOperatorInfo::Reset() {
  home_->Reset();
  serving_->Reset();
}

}  // namespace shill
