// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/mobile_operator_mapper.h"

#include <memory>
#include <optional>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <brillo/http/http_request.h>
#include <chromeos/dbus/service_constants.h>
#include <google/protobuf/repeated_field.h>
#include <re2/re2.h>

#include "base/notreached.h"
#include "base/ranges/algorithm.h"
#include "shill/cellular/carrier_entitlement.h"
#include "shill/cellular/mobile_operator_storage.h"
#include "shill/ipconfig.h"
#include "shill/logging.h"
#include "shill/mobile_operator_db/mobile_operator_db.pb.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kCellular;
}  // namespace Logging

const int MobileOperatorMapper::kMCCMNCMinLen = 5;

namespace {

std::string GetApnAuthentication(
    const shill::mobile_operator_db::MobileAPN& apn) {
  if (apn.has_authentication()) {
    switch (apn.authentication()) {
      case mobile_operator_db::MobileAPN_Authentication_PAP:
        return kApnAuthenticationPap;
      case mobile_operator_db::MobileAPN_Authentication_CHAP:
        return kApnAuthenticationChap;
      default:
        break;
    }
  }
  return std::string();
}

std::optional<std::string> GetIpType(
    const shill::mobile_operator_db::MobileAPN& apn) {
  if (!apn.has_ip_type()) {
    return kApnIpTypeV4;
  }

  switch (apn.ip_type()) {
    case mobile_operator_db::MobileAPN_IpType_UNKNOWN:
      return std::nullopt;
    case mobile_operator_db::MobileAPN_IpType_IPV4:
      return kApnIpTypeV4;
    case mobile_operator_db::MobileAPN_IpType_IPV6:
      return kApnIpTypeV6;
    case mobile_operator_db::MobileAPN_IpType_IPV4V6:
      return kApnIpTypeV4V6;
    default:
      return kApnIpTypeV4;
  }
}

std::set<std::string> GetApnTypes(
    const shill::mobile_operator_db::MobileAPN& apn) {
  if (apn.type().size() == 0) {
    // We should never reach this point. Unit tests validate that at least 1
    // ApnType exist.
    LOG(ERROR) << " APN: " << apn.apn() << " does not contain an APN type.";
    DCHECK(false);
    return {kApnTypeDefault};
  }
  std::set<std::string> apn_types;
  for (const auto& apn_type : apn.type()) {
    switch (apn_type) {
      case mobile_operator_db::MobileAPN_ApnType_DEFAULT:
        apn_types.insert(kApnTypeDefault);
        break;
      case mobile_operator_db::MobileAPN_ApnType_IA:
        apn_types.insert(kApnTypeIA);
        break;
      case mobile_operator_db::MobileAPN_ApnType_DUN:
        apn_types.insert(kApnTypeDun);
        break;
    }
  }
  return apn_types;
}

}  // namespace

std::string MobileOperatorMapper::GetLogPrefix(const char* func) const {
  return info_owner_ + ": " + func;
}

MobileOperatorMapper::MobileOperatorMapper(EventDispatcher* dispatcher,
                                           const std::string& info_owner)
    : dispatcher_(dispatcher),
      info_owner_(info_owner),
      operator_code_type_(OperatorCodeType::kUnknown),
      current_mno_(nullptr),
      current_mvno_(nullptr),
      requires_roaming_(false),
      tethering_allowed_(false),
      use_dun_apn_as_default_(false),
      mtu_(IPConfig::kUndefinedMTU),
      user_olp_empty_(true),
      weak_ptr_factory_(this) {}

MobileOperatorMapper::~MobileOperatorMapper() {
  on_operator_changed_cb_.Cancel();
}

void MobileOperatorMapper::ClearDatabasePaths() {
  SLOG(3) << GetLogPrefix(__func__);
  database_paths_.clear();
  databases_.clear();
}

void MobileOperatorMapper::AddDatabasePath(
    const base::FilePath& absolute_path) {
  SLOG(3) << GetLogPrefix(__func__);
  database_paths_.push_back(absolute_path);
}

bool MobileOperatorMapper::Init(
    MobileOperatorMapperOnOperatorChangedCallback cb) {
  SLOG(3) << GetLogPrefix(__func__);
  on_operator_changed_cb_.Reset(cb);

  // |databases_| is guaranteed to be set once |Init| is called.
  databases_.clear();
  if (database_paths_.empty())
    return false;

  for (const auto& database_path : database_paths_) {
    const mobile_operator_db::MobileOperatorDB* database =
        MobileOperatorStorage::GetInstance()->GetDatabase(database_path);
    if (!database)
      return false;

    databases_.push_back(database);
  }
  PreprocessDatabase();
  return true;
}

bool MobileOperatorMapper::IsMobileNetworkOperatorKnown() const {
  bool result = (current_mno_ != nullptr);
  SLOG(3) << GetLogPrefix(__func__) << ": Result[" << result << "]";
  return result;
}

bool MobileOperatorMapper::IsMobileVirtualNetworkOperatorKnown() const {
  bool result = (current_mvno_ != nullptr);
  SLOG(3) << GetLogPrefix(__func__) << ": Result[" << result << "]";
  return result;
}

// ///////////////////////////////////////////////////////////////////////////
// Getters.
const std::string& MobileOperatorMapper::uuid() const {
  SLOG(3) << GetLogPrefix(__func__) << ": Result[" << uuid_ << "]";
  return uuid_;
}

const std::string& MobileOperatorMapper::operator_name() const {
  SLOG(3) << GetLogPrefix(__func__) << ": Result[" << operator_name_ << "]";
  return operator_name_;
}

const std::string& MobileOperatorMapper::country() const {
  SLOG(3) << GetLogPrefix(__func__) << ": Result[" << country_ << "]";
  return country_;
}

const std::string& MobileOperatorMapper::mccmnc() const {
  SLOG(3) << GetLogPrefix(__func__) << ": Result[" << mccmnc_ << "]";
  return mccmnc_;
}

const std::string& MobileOperatorMapper::gid1() const {
  SLOG(3) << GetLogPrefix(__func__) << ": Result[" << gid1_ << "]";
  return gid1_;
}

const std::vector<std::string>& MobileOperatorMapper::mccmnc_list() const {
  if (SLOG_IS_ON(Cellular, 3)) {
    std::stringstream pp_result;
    for (const auto& mccmnc : mccmnc_list_) {
      pp_result << mccmnc << " ";
    }
    SLOG(3) << GetLogPrefix(__func__) << ": Result[" << pp_result.str() << "]";
  }
  return mccmnc_list_;
}

const MobileOperatorMapper::EntitlementConfig&
MobileOperatorMapper::entitlement_config() {
  SLOG(3) << GetLogPrefix(__func__) << ": url Result["
          << entitlement_config_.url << "]";
  SLOG(3) << GetLogPrefix(__func__) << ": method Result["
          << entitlement_config_.method << "]";

  entitlement_config_.params.clear();
  for (const auto& param : mhs_entitlement_params_) {
    switch (param) {
      case shill::mobile_operator_db::Data_EntitlementParam::
          Data_EntitlementParam_IMSI:
        entitlement_config_.params[CarrierEntitlement::kImsiProperty] =
            user_imsi_;
        break;
    }
  }
  if (SLOG_IS_ON(Cellular, 3)) {
    std::stringstream pp_result;
    for (const auto& entry : entitlement_config_.params) {
      pp_result << entry.first << " ";
    }
    SLOG(3) << GetLogPrefix(__func__) << ": params Result[" << pp_result.str()
            << "]";
  }

  return entitlement_config_;
}

const std::vector<MobileOperatorMapper::LocalizedName>&
MobileOperatorMapper::operator_name_list() const {
  if (SLOG_IS_ON(Cellular, 3)) {
    std::stringstream pp_result;
    for (const auto& operator_name : operator_name_list_) {
      pp_result << "(" << operator_name.name << ", " << operator_name.language
                << ") ";
    }
    SLOG(3) << GetLogPrefix(__func__) << ": Result[" << pp_result.str() << "]";
  }
  return operator_name_list_;
}

const std::vector<MobileOperatorMapper::MobileAPN>&
MobileOperatorMapper::apn_list() const {
  return apn_list_;
}

const std::vector<MobileOperatorMapper::OnlinePortal>&
MobileOperatorMapper::olp_list() const {
  if (SLOG_IS_ON(Cellular, 3)) {
    std::stringstream pp_result;
    for (const auto& olp : olp_list_) {
      pp_result << "(url: " << olp.url << ", method: " << olp.method
                << ", post_data: " << olp.post_data << ") ";
    }
    SLOG(3) << GetLogPrefix(__func__) << ": Result[" << pp_result.str() << "]";
  }
  return olp_list_;
}

bool MobileOperatorMapper::requires_roaming() const {
  SLOG(3) << GetLogPrefix(__func__) << ": Result[" << requires_roaming_ << "]";
  return requires_roaming_;
}

bool MobileOperatorMapper::tethering_allowed() const {
  SLOG(3) << GetLogPrefix(__func__) << ": Result[" << tethering_allowed_ << "]";
  return tethering_allowed_;
}

bool MobileOperatorMapper::use_dun_apn_as_default() const {
  SLOG(3) << GetLogPrefix(__func__) << ": Result[" << use_dun_apn_as_default_
          << "]";
  return use_dun_apn_as_default_;
}

int32_t MobileOperatorMapper::mtu() const {
  SLOG(3) << GetLogPrefix(__func__) << ": Result[" << mtu_ << "]";
  return mtu_;
}

// ///////////////////////////////////////////////////////////////////////////
// Functions used to notify this object of operator data changes.
void MobileOperatorMapper::UpdateIMSI(const std::string& imsi) {
  SLOG(3) << GetLogPrefix(__func__) << "(" << imsi << ")";
  bool operator_changed = false;
  if (user_imsi_ == imsi) {
    return;
  }

  SLOG(1) << GetLogPrefix(__func__) << ": " << imsi;
  user_imsi_ = imsi;

  if (!user_mccmnc_.empty()) {
    SLOG(2) << GetLogPrefix(__func__) << ": MCCMNC=" << user_mccmnc_;
    if (!base::StartsWith(imsi, user_mccmnc_,
                          base::CompareCase::INSENSITIVE_ASCII)) {
      LOG(WARNING) << GetLogPrefix(__func__)
                   << "MCCMNC is not a substring of the IMSI.";
    }
  } else {
    // Attempt to determine the MNO from IMSI since MCCMNC is absent.
    if (!(AppendToCandidatesByMCCMNC(imsi.substr(0, kMCCMNCMinLen)) ||
          AppendToCandidatesByMCCMNC(imsi.substr(0, kMCCMNCMinLen + 1))))
      LOG(WARNING) << GetLogPrefix(__func__) << "Unknown MCCMNC values ["
                   << imsi.substr(0, kMCCMNCMinLen) << "] ["
                   << imsi.substr(0, kMCCMNCMinLen + 1) << "].";

    if (!candidates_by_operator_code_.empty()) {
      // We found some candidates using IMSI.
      operator_changed |= UpdateMNO();
    }
  }
  operator_changed |= UpdateMVNO();
  if (raw_apn_filters_types_.count(
          mobile_operator_db::Filter_Type::Filter_Type_IMSI))
    HandleAPNListUpdate();

  // No special notification should be sent for this property, since the object
  // does not expose |imsi| as a property at all.
  if (operator_changed) {
    PostNotifyOperatorChanged();
  }
}

void MobileOperatorMapper::UpdateICCID(const std::string& iccid) {
  SLOG(3) << GetLogPrefix(__func__) << "(" << iccid << ")";
  if (user_iccid_ == iccid) {
    return;
  }

  SLOG(1) << GetLogPrefix(__func__) << ": " << iccid;
  user_iccid_ = iccid;
  if (raw_apn_filters_types_.count(
          mobile_operator_db::Filter_Type::Filter_Type_ICCID))
    HandleAPNListUpdate();

  // |iccid| is not an exposed property, so don't raise event for just this
  // property update.
  if (UpdateMVNO()) {
    PostNotifyOperatorChanged();
  }
}

void MobileOperatorMapper::UpdateMCCMNC(const std::string& mccmnc) {
  SLOG(3) << GetLogPrefix(__func__) << "(" << mccmnc << ")";
  if (user_mccmnc_ == mccmnc) {
    return;
  }

  SLOG(3) << GetLogPrefix(__func__) << ": " << mccmnc;
  user_mccmnc_ = mccmnc;
  HandleMCCMNCUpdate();
  candidates_by_operator_code_.clear();
  if (!AppendToCandidatesByMCCMNC(mccmnc))
    LOG(WARNING) << GetLogPrefix(__func__) << "Unknown MCCMNC value [" << mccmnc
                 << "].";

  if (raw_apn_filters_types_.count(
          mobile_operator_db::Filter_Type::Filter_Type_MCCMNC))
    HandleAPNListUpdate();

  // Always update M[V]NO, even if we found no candidates, since we might have
  // lost some candidates due to an incorrect MCCMNC.
  bool operator_changed = false;
  operator_changed |= UpdateMNO();
  operator_changed |= UpdateMVNO();
  if (operator_changed || ShouldNotifyPropertyUpdate()) {
    PostNotifyOperatorChanged();
  }
}

void MobileOperatorMapper::UpdateOperatorName(
    const std::string& operator_name) {
  SLOG(3) << GetLogPrefix(__func__) << "(" << operator_name << ")";
  bool operator_changed = false;
  if (user_operator_name_ == operator_name) {
    return;
  }
  user_operator_name_ = operator_name;
  if (operator_name.empty()) {
    Reset();
    return;
  }

  SLOG(2) << GetLogPrefix(__func__) << ": " << operator_name;
  HandleOperatorNameUpdate();

  // We must update the candidates by name anyway.
  StringToMNOListMap::const_iterator cit =
      name_to_mnos_.find(NormalizeOperatorName(operator_name));
  candidates_by_name_.clear();
  if (cit != name_to_mnos_.end()) {
    candidates_by_name_ = cit->second;
    // We should never have inserted an empty vector into the map.
    DCHECK(!candidates_by_name_.empty());
  } else {
    LOG(INFO) << GetLogPrefix(__func__) << "Operator name [" << operator_name
              << "] "
              << "(Normalized: [" << NormalizeOperatorName(operator_name)
              << "]) does not match any MNO.";
  }
  if (raw_apn_filters_types_.count(
          mobile_operator_db::Filter_Type::Filter_Type_OPERATOR_NAME))
    HandleAPNListUpdate();

  operator_changed |= UpdateMNO();
  operator_changed |= UpdateMVNO();
  if (operator_changed || ShouldNotifyPropertyUpdate()) {
    PostNotifyOperatorChanged();
  }
}

void MobileOperatorMapper::UpdateGID1(const std::string& gid1) {
  SLOG(3) << GetLogPrefix(__func__) << "(" << gid1 << ")";
  if (user_gid1_ == gid1) {
    return;
  }

  SLOG(1) << GetLogPrefix(__func__) << ": " << gid1;
  user_gid1_ = gid1;
  HandleGID1Update();
  if (raw_apn_filters_types_.count(
          mobile_operator_db::Filter_Type::Filter_Type_GID1)) {
    HandleAPNListUpdate();
  }

  // No special notification should be sent for this property, since the object
  // does not expose |gid1| as a property at all.
  if (UpdateMVNO()) {
    PostNotifyOperatorChanged();
  }
}

void MobileOperatorMapper::UpdateOnlinePortal(const std::string& url,
                                              const std::string& method,
                                              const std::string& post_data) {
  SLOG(3) << GetLogPrefix(__func__) << "(" << url << ", " << method << ", "
          << post_data << ")";
  if (!user_olp_empty_ && user_olp_.url == url && user_olp_.method == method &&
      user_olp_.post_data == post_data) {
    return;
  }

  SLOG(3) << GetLogPrefix(__func__) << ": " << url;
  user_olp_empty_ = false;
  user_olp_.url = url;
  user_olp_.method = method;
  user_olp_.post_data = post_data;
  HandleOnlinePortalUpdate();

  // OnlinePortal is never used in deciding M[V]NO.
  if (ShouldNotifyPropertyUpdate()) {
    PostNotifyOperatorChanged();
  }
}

void MobileOperatorMapper::Reset() {
  SLOG(1) << GetLogPrefix(__func__);
  bool should_notify = current_mno_ != nullptr || current_mvno_ != nullptr;

  current_mno_ = nullptr;
  current_mvno_ = nullptr;
  operator_code_type_ = OperatorCodeType::kUnknown;
  candidates_by_operator_code_.clear();
  candidates_by_name_.clear();

  ClearDBInformation();

  user_imsi_.clear();
  user_iccid_.clear();
  user_mccmnc_.clear();
  user_operator_name_.clear();
  user_olp_empty_ = true;
  user_olp_.url.clear();
  user_olp_.method.clear();
  user_olp_.post_data.clear();

  if (should_notify) {
    PostNotifyOperatorChanged();
  }
}

void MobileOperatorMapper::PreprocessDatabase() {
  SLOG(3) << GetLogPrefix(__func__);

  mccmnc_to_mnos_.clear();
  name_to_mnos_.clear();

  std::set<std::string> uuids;
  // Iterate the databases in reverse. This allows the use of duplicate uuids
  // to override MNOs. For example, we could add a second database, which has
  // an MNO with the same uuid as another MNO in the default database, to
  // completely override the info in the default database.
  for (int i = databases_.size() - 1; i >= 0; i--) {
    const auto& mnos = databases_[i]->mno();
    for (const auto& mno : mnos) {
      // MobileNetworkOperator::data is a required field.
      DCHECK(mno.has_data());
      const auto& data = mno.data();
      if (uuids.count(mno.data().uuid())) {
        LOG(INFO) << GetLogPrefix(__func__)
                  << "MNO skipped because uuid:" << mno.data().uuid()
                  << " already exists";
        continue;
      }
      uuids.insert(mno.data().uuid());

      const auto& mccmncs = data.mccmnc();
      for (const auto& mccmnc : mccmncs) {
        InsertIntoStringToMNOListMap(&mccmnc_to_mnos_, mccmnc, &mno);
      }

      const auto& localized_names = data.localized_name();
      for (const auto& localized_name : localized_names) {
        // LocalizedName::name is a required field.
        DCHECK(localized_name.has_name());
        InsertIntoStringToMNOListMap(
            &name_to_mnos_, NormalizeOperatorName(localized_name.name()), &mno);
      }
    }
  }
}

// This function assumes that duplicate |values| are never inserted for the
// same |key|. If you do that, the function is too dumb to deduplicate the
// |value|s, and two copies will get stored.
void MobileOperatorMapper::InsertIntoStringToMNOListMap(
    StringToMNOListMap* table,
    const std::string& key,
    const shill::mobile_operator_db::MobileNetworkOperator* value) {
  (*table)[key].push_back(value);
}

bool MobileOperatorMapper::AppendToCandidatesByMCCMNC(
    const std::string& mccmnc) {
  operator_code_type_ = OperatorCodeType::kMCCMNC;
  StringToMNOListMap::const_iterator cit = mccmnc_to_mnos_.find(mccmnc);
  if (cit == mccmnc_to_mnos_.end()) {
    LOG(WARNING) << GetLogPrefix(__func__) << "Unknown MCCMNC value [" << mccmnc
                 << "].";
    return false;
  }

  // We should never have inserted an empty vector into the map.
  DCHECK(!cit->second.empty());
  for (const auto& mno : cit->second) {
    candidates_by_operator_code_.push_back(mno);
  }
  return true;
}

std::string MobileOperatorMapper::OperatorCodeString() const {
  switch (operator_code_type_) {
    case OperatorCodeType::kMCCMNC:
      return "MCCMNC";
    case OperatorCodeType::kUnknown:
      return "UnknownOperatorCodeType";
  }
}

bool MobileOperatorMapper::UpdateMNO() {
  SLOG(3) << GetLogPrefix(__func__);
  const shill::mobile_operator_db::MobileNetworkOperator* candidate = nullptr;

  // The only way |operator_code_type_| can be |OperatorCodeType::kUnknown| is
  // that we haven't received any operator_code updates yet.
  DCHECK(operator_code_type_ == OperatorCodeType::kMCCMNC ||
         user_mccmnc_.empty());

  if (candidates_by_operator_code_.size() == 1) {
    candidate = candidates_by_operator_code_[0];
    if (!candidates_by_name_.empty()) {
      bool found_match = false;
      for (auto candidate_by_name : candidates_by_name_) {
        if (candidate_by_name == candidate) {
          found_match = true;
          break;
        }
      }
      if (!found_match) {
        const std::string& operator_code = user_mccmnc_;
        SLOG(1) << GetLogPrefix(__func__) << "MNO determined by "
                << OperatorCodeString() << " [" << operator_code
                << "] does not match any suggested by name["
                << user_operator_name_ << "]. " << OperatorCodeString()
                << " overrides name!";
      }
    }
  } else if (candidates_by_operator_code_.size() > 1) {
    // Try to find an intersection of the two candidate lists. These lists
    // should be almost always of length 1. Simply iterate.
    for (auto candidate_by_mccmnc : candidates_by_operator_code_) {
      for (auto candidate_by_name : candidates_by_name_) {
        if (candidate_by_mccmnc == candidate_by_name) {
          candidate = candidate_by_mccmnc;
          break;
        }
      }
      if (candidate != nullptr) {
        break;
      }
    }
    if (candidate == nullptr) {
      const std::string& operator_code = user_mccmnc_;
      SLOG(1) << GetLogPrefix(__func__) << "MNOs suggested by "
              << OperatorCodeString() << " [" << operator_code
              << "] are multiple and disjoint from those suggested "
              << "by name[" << user_operator_name_ << "].";
      candidate = PickOneFromDuplicates(candidates_by_operator_code_);
    }
  } else {  // candidates_by_operator_code_.size() == 0
    // Special case: In case we had a *wrong* operator_code update, we want
    // to override the suggestions from |user_operator_name_|. We should not
    // determine an MNO in this case.
    if (operator_code_type_ == OperatorCodeType::kMCCMNC &&
        !user_mccmnc_.empty()) {
      SLOG(1) << GetLogPrefix(__func__) << "A non-matching "
              << OperatorCodeString() << " "
              << "was reported by the user."
              << "We fail the MNO match in this case.";
    } else if (candidates_by_name_.size() == 1) {
      candidate = candidates_by_name_[0];
    } else if (candidates_by_name_.size() > 1) {
      SLOG(1) << GetLogPrefix(__func__) << "Multiple MNOs suggested by name["
              << user_operator_name_ << "], and none by MCCMNC.";
      candidate = PickOneFromDuplicates(candidates_by_name_);
    } else {  // candidates_by_name_.size() == 0
      SLOG(1) << GetLogPrefix(__func__) << "No candidates suggested.";
    }
  }

  if (candidate != current_mno_) {
    current_mno_ = candidate;
    RefreshDBInformation();
    return true;
  }
  return false;
}

bool MobileOperatorMapper::UpdateMVNO() {
  SLOG(3) << GetLogPrefix(__func__);

  std::vector<const shill::mobile_operator_db::MobileVirtualNetworkOperator*>
      candidate_mvnos;
  for (const auto& database : databases_) {
    for (const auto& mvno : database->mvno()) {
      candidate_mvnos.push_back(&mvno);
    }
  }
  if (current_mno_) {
    for (const auto& mvno : current_mno_->mvno()) {
      candidate_mvnos.push_back(&mvno);
    }
  }

  for (const auto* candidate_mvno : candidate_mvnos) {
    bool passed_all_filters = true;
    for (const auto& filter : candidate_mvno->mvno_filter()) {
      if (!FilterMatches(filter)) {
        passed_all_filters = false;
        break;
      }
    }
    if (passed_all_filters) {
      if (current_mvno_ == candidate_mvno) {
        return false;
      }
      current_mvno_ = candidate_mvno;
      RefreshDBInformation();
      return true;
    }
  }

  // We did not find any valid MVNO.
  if (current_mvno_ != nullptr) {
    current_mvno_ = nullptr;
    RefreshDBInformation();
    return true;
  }
  return false;
}

const shill::mobile_operator_db::MobileNetworkOperator*
MobileOperatorMapper::PickOneFromDuplicates(
    const std::vector<const shill::mobile_operator_db::MobileNetworkOperator*>&
        duplicates) const {
  if (duplicates.empty())
    return nullptr;

  for (auto candidate : duplicates) {
    if (candidate->earmarked()) {
      SLOG(2) << GetLogPrefix(__func__)
              << "Picking earmarked candidate: " << candidate->data().uuid();
      return candidate;
    }
  }
  SLOG(2) << GetLogPrefix(__func__)
          << "No earmarked candidate found. Choosing the first.";
  return duplicates[0];
}

bool MobileOperatorMapper::FilterMatches(
    const shill::mobile_operator_db::Filter& filter,
    std::string to_match) const {
  DCHECK(filter.has_regex() || filter.has_exclude_regex() ||
         filter.range_size());
  if (to_match.empty()) {
    switch (filter.type()) {
      case mobile_operator_db::Filter_Type_IMSI:
        to_match = user_imsi_;
        break;
      case mobile_operator_db::Filter_Type_ICCID:
        to_match = user_iccid_;
        break;
      case mobile_operator_db::Filter_Type_OPERATOR_NAME:
        to_match = user_operator_name_;
        break;
      case mobile_operator_db::Filter_Type_MCCMNC:
        to_match = user_mccmnc_;
        break;
      case mobile_operator_db::Filter_Type_GID1:
        to_match = user_gid1_;
        break;
      default:
        SLOG(1) << GetLogPrefix(__func__) << "Unknown filter type ["
                << filter.type() << "]";
        return false;
    }
  }
  // |to_match| can be empty if we have no *user provided* information of the
  // correct type.
  if (to_match.empty()) {
    SLOG(2) << GetLogPrefix(__func__)
            << "Nothing to match against (filter: " << filter.regex() << ").";
    return false;
  }

  // Match against numerical ranges rather than a regular expression
  if (filter.range_size()) {
    uint64_t match_value;
    if (!base::StringToUint64(to_match, &match_value)) {
      SLOG(3) << GetLogPrefix(__func__)
              << "Need a number to match against a range (" << match_value
              << ").";
      return false;
    }

    for (auto r : filter.range()) {
      if ((r.start() <= match_value) && (match_value <= r.end()))
        return true;
    }
    // No range is matching
    return false;
  }

  if (filter.has_regex()) {
    re2::RE2 filter_regex = {filter.regex()};
    if (!RE2::FullMatch(to_match, filter_regex)) {
      SLOG(2) << GetLogPrefix(__func__) << "Skipping because string '"
              << to_match << "' is not a "
              << "match of regexp '" << filter.regex();
      return false;
    }

    SLOG(2) << GetLogPrefix(__func__) << "Regex '" << filter.regex()
            << "' matches '" << to_match << "'.";
  }

  if (filter.has_exclude_regex()) {
    re2::RE2 filter_regex = {filter.exclude_regex()};
    if (RE2::FullMatch(to_match, filter_regex)) {
      SLOG(2) << GetLogPrefix(__func__) << "Skipping because string '"
              << to_match << "' is a "
              << "match of exclude_regex '" << filter.exclude_regex();
      return false;
    }

    SLOG(2) << GetLogPrefix(__func__) << "'" << to_match
            << "' doesn't match exclude_regex '" << filter.exclude_regex()
            << "'.";
  }

  return true;
}

void MobileOperatorMapper::RefreshDBInformation() {
  ClearDBInformation();

  if (current_mno_ == nullptr) {
    return;
  }

  // |data| is a required field.
  DCHECK(current_mno_->has_data());
  SLOG(2) << GetLogPrefix(__func__) << "Reloading MNO data.";
  ReloadData(current_mno_->data());

  if (current_mvno_ != nullptr) {
    // |data| is a required field.
    DCHECK(current_mvno_->has_data());
    SLOG(2) << GetLogPrefix(__func__) << "Reloading MVNO data.";
    ReloadData(current_mvno_->data());
  }
}

void MobileOperatorMapper::ClearDBInformation() {
  uuid_.clear();
  country_.clear();
  mccmnc_list_.clear();
  HandleMCCMNCUpdate();
  operator_name_list_.clear();
  prioritizes_db_operator_name_ = false;
  HandleOperatorNameUpdate();
  apn_list_.clear();
  raw_apn_list_.clear();
  raw_apn_filters_types_.clear();
  HandleAPNListUpdate();
  olp_list_.clear();
  raw_olp_list_.clear();
  HandleOnlinePortalUpdate();
  requires_roaming_ = false;
  tethering_allowed_ = false;
  use_dun_apn_as_default_ = false;
  roaming_filter_list_.clear();
  mtu_ = IPConfig::kUndefinedMTU;
  entitlement_config_ = {};
  mhs_entitlement_params_.clear();
}

void MobileOperatorMapper::ReloadData(
    const shill::mobile_operator_db::Data& data) {
  SLOG(3) << GetLogPrefix(__func__);
  // |uuid_| is *always* overwritten. An MNO and MVNO should not share the
  // |uuid_|.
  CHECK(data.has_uuid());
  uuid_ = data.uuid();

  if (data.has_country()) {
    country_ = data.country();
  }

  if (data.has_prioritizes_name()) {
    prioritizes_db_operator_name_ = data.prioritizes_name();
  }

  if (data.localized_name_size() > 0) {
    operator_name_list_.clear();
    for (const auto& localized_name : data.localized_name()) {
      operator_name_list_.push_back(
          {localized_name.name(), localized_name.language()});
    }
    HandleOperatorNameUpdate();
  }

  if (data.has_requires_roaming()) {
    requires_roaming_ = data.requires_roaming();
  }

  // The following tethering properties are always overwritten because each
  // MNO/MVNO decides how tethering works on their network.
  tethering_allowed_ = data.tethering_allowed();
  use_dun_apn_as_default_ = data.use_dun_apn_as_default();
  entitlement_config_.url = data.mhs_entitlement_url();
  switch (data.mhs_entitlement_method()) {
    case shill::mobile_operator_db::GET:
      entitlement_config_.method = brillo::http::request_type::kGet;
      break;
    case shill::mobile_operator_db::POST:
      entitlement_config_.method = brillo::http::request_type::kPost;
      break;
  }
  // mhs_entitlement_url_ = data.mhs_entitlement_url();
  mhs_entitlement_params_.clear();
  if (data.mhs_entitlement_param_size() > 0) {
    for (const auto& param : data.mhs_entitlement_param()) {
      mhs_entitlement_params_.insert(
          static_cast<shill::mobile_operator_db::Data_EntitlementParam>(param));
    }
  }

  if (data.roaming_filter_size() > 0) {
    roaming_filter_list_.clear();
    for (const auto& filter : data.roaming_filter()) {
      roaming_filter_list_.push_back(filter);
    }
  }

  if (data.mtu()) {
    mtu_ = data.mtu();
  }

  if (data.olp_size() > 0) {
    raw_olp_list_.clear();
    // Copy the olp list so we can mutate it.
    for (const auto& olp : data.olp()) {
      raw_olp_list_.push_back(olp);
    }
    HandleOnlinePortalUpdate();
  }

  if (data.mccmnc_size() > 0) {
    mccmnc_list_.clear();
    for (const auto& mccmnc : data.mccmnc()) {
      mccmnc_list_.push_back(mccmnc);
    }
    HandleMCCMNCUpdate();
  }

  if (data.mobile_apn_size() > 0) {
    raw_apn_list_.clear();
    raw_apn_filters_types_.clear();
    // Copy the olp list so we can mutate it.
    for (const auto& mobile_apn : data.mobile_apn()) {
      raw_apn_list_.push_back(mobile_apn);
      for (const auto& filter : mobile_apn.apn_filter()) {
        raw_apn_filters_types_.insert(filter.type());
      }
    }
    HandleAPNListUpdate();
  }
}

void MobileOperatorMapper::HandleMCCMNCUpdate() {
  if (!user_mccmnc_.empty()) {
    bool append_to_list = true;
    for (const auto& mccmnc : mccmnc_list_) {
      append_to_list &= (user_mccmnc_ != mccmnc);
    }
    if (append_to_list) {
      mccmnc_list_.push_back(user_mccmnc_);
    }
  }

  if (!user_mccmnc_.empty()) {
    mccmnc_ = user_mccmnc_;
  } else if (!mccmnc_list_.empty()) {
    mccmnc_ = mccmnc_list_[0];
  } else {
    mccmnc_.clear();
  }

  // Chain the GID1 update processing in case it needs to be cleared
  // after the mccmnc_ update
  HandleGID1Update();
}

void MobileOperatorMapper::HandleOperatorNameUpdate() {
  if (!user_operator_name_.empty()) {
    std::vector<MobileOperatorMapper::LocalizedName> localized_names;
    MobileOperatorMapper::LocalizedName localized_name{user_operator_name_, ""};
    localized_names.emplace_back(localized_name);
    for (auto it = operator_name_list_.begin();
         it != operator_name_list_.end();) {
      if (it->name == user_operator_name_) {
        localized_name = {user_operator_name_, it->language};
        localized_names.push_back(localized_name);
        operator_name_list_.erase(it);
      } else {
        it++;
      }
    }

    operator_name_list_.insert(
        (prioritizes_db_operator_name_ ? operator_name_list_.end()
                                       : operator_name_list_.begin()),
        localized_names.begin(), localized_names.end());
  }

  operator_name_ =
      operator_name_list_.empty() ? "" : operator_name_list_[0].name;
}

// The user-specified GID1 will be used exclusively if the user-specified
// MCCMNC is in use, otherwise unused.
void MobileOperatorMapper::HandleGID1Update() {
  if (!mccmnc_.empty() && (mccmnc_ == user_mccmnc_) && !user_gid1_.empty())
    gid1_ = user_gid1_;
  else
    gid1_.clear();
}

// Warning: Currently, an MCCMNC update by itself does not result in
// recomputation of the |olp_list_|. This means that if the new MCCMNC
// causes an online portal filter to match, we'll miss that.
// This won't be a problem if either the MNO or the MVNO changes, since data is
// reloaded then.
// This is a corner case that we don't expect to hit, since MCCMNC doesn't
// really change in a running system.
void MobileOperatorMapper::HandleOnlinePortalUpdate() {
  // Always recompute |olp_list_|. We don't expect this list to be big.
  olp_list_.clear();
  for (const auto& raw_olp : raw_olp_list_) {
    if (!raw_olp.has_olp_filter() || FilterMatches(raw_olp.olp_filter())) {
      olp_list_.push_back(MobileOperatorMapper::OnlinePortal{
          raw_olp.url(),
          (raw_olp.method() == shill::mobile_operator_db::GET) ? "GET" : "POST",
          raw_olp.post_data()});
    }
  }
  if (!user_olp_empty_) {
    bool append_user_olp = true;
    for (const auto& olp : olp_list_) {
      append_user_olp &=
          (olp.url != user_olp_.url || olp.method != user_olp_.method ||
           olp.post_data != user_olp_.post_data);
    }
    if (append_user_olp) {
      olp_list_.push_back(user_olp_);
    }
  }
}

void MobileOperatorMapper::HandleAPNListUpdate() {
  SLOG(3) << GetLogPrefix(__func__);
  // Always recompute |apn_list_|. We don't expect this list to be big.
  apn_list_.clear();
  for (const auto& apn_data : raw_apn_list_) {
    bool passed_all_filters = true;
    for (const auto& filter : apn_data.apn_filter()) {
      if (!FilterMatches(filter)) {
        passed_all_filters = false;
        break;
      }
    }
    if (!passed_all_filters)
      continue;

    MobileOperatorMapper::MobileAPN apn;
    apn.apn = apn_data.apn();
    apn.username = apn_data.username();
    apn.password = apn_data.password();
    for (const auto& localized_name : apn_data.localized_name()) {
      apn.operator_name_list.push_back(
          {localized_name.name(), localized_name.language()});
    }
    apn.authentication = GetApnAuthentication(apn_data);
    apn.apn_types = GetApnTypes(apn_data);
    std::optional<std::string> ip_type = GetIpType(apn_data);
    if (!ip_type.has_value()) {
      LOG(INFO) << GetLogPrefix(__func__) << "Unknown IP type for APN \""
                << apn_data.apn() << "\"";
      continue;
    }
    apn.ip_type = ip_type.value();
    apn.is_required_by_carrier_spec = apn_data.is_required_by_carrier_spec();

    apn_list_.push_back(std::move(apn));
  }
}

void MobileOperatorMapper::PostNotifyOperatorChanged() {
  SLOG(3) << GetLogPrefix(__func__);
  // If there was an outstanding task, it will get replaced.
  notify_operator_changed_task_.Reset(
      base::BindOnce(&MobileOperatorMapper::NotifyOperatorChanged,
                     weak_ptr_factory_.GetWeakPtr()));
  dispatcher_->PostTask(FROM_HERE, notify_operator_changed_task_.callback());
}

void MobileOperatorMapper::NotifyOperatorChanged() {
  if (!on_operator_changed_cb_.IsCancelled()) {
    on_operator_changed_cb_.callback().Run();
  }
}

bool MobileOperatorMapper::ShouldNotifyPropertyUpdate() const {
  return IsMobileNetworkOperatorKnown() ||
         IsMobileVirtualNetworkOperatorKnown();
}

std::string MobileOperatorMapper::NormalizeOperatorName(
    const std::string& name) const {
  auto result = base::ToLowerASCII(name);
  base::RemoveChars(result, base::kWhitespaceASCII, &result);
  return result;
}

bool MobileOperatorMapper::RequiresRoamingOnOperator(
    const MobileOperatorMapper* serving_operator) const {
  if (!serving_operator || serving_operator->mccmnc().empty())
    return false;

  for (const auto& filter : roaming_filter_list_) {
    if (filter.type() != mobile_operator_db::Filter_Type_MCCMNC ||
        (!filter.has_regex() && !filter.has_exclude_regex())) {
      continue;
    }
    bool requires_roaming = FilterMatches(filter, serving_operator->mccmnc());
    if (requires_roaming) {
      SLOG(1)
          << GetLogPrefix(__func__)
          << "Roaming is required on serving operator due to roaming filtering";
      return true;
    }
    SLOG(2) << GetLogPrefix(__func__)
            << "Serving operator MCCMNC: " << serving_operator->mccmnc()
            << " filtering regex: " << filter.regex()
            << " results, requires_roaming: " << requires_roaming;
  }
  return false;
}

}  // namespace shill
