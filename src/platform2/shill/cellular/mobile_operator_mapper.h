// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_MOBILE_OPERATOR_MAPPER_H_
#define SHILL_CELLULAR_MOBILE_OPERATOR_MAPPER_H_

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <base/cancelable_callback.h>
#include <base/files/file_util.h>
#include <base/memory/weak_ptr.h>
#include <base/observer_list.h>
#include <google/protobuf/text_format.h>
#include <gtest/gtest_prod.h>

#include "shill/data_types.h"
#include "shill/event_dispatcher.h"
#include "shill/mobile_operator_db/mobile_operator_db.pb.h"

namespace shill {

using MobileOperatorMapperOnOperatorChangedCallback = base::RepeatingClosure;

class MobileOperatorMapper {
 public:
  using StringToMNOListMap =
      std::map<std::string,
               std::vector<const mobile_operator_db::MobileNetworkOperator*>>;

  MobileOperatorMapper(EventDispatcher* dispatcher,
                       const std::string& info_owner);
  MobileOperatorMapper(const MobileOperatorMapper&) = delete;
  MobileOperatorMapper& operator=(const MobileOperatorMapper&) = delete;

  virtual ~MobileOperatorMapper();

  // ///////////////////////////////////////////////////////////////////////////
  // Objects that encapsulate related information about the mobile operator.

  // Encapsulates a name and the language that name has been localized to.
  // The name can be a carrier name, or the name that a cellular carrier
  // prefers to show for a certain access point.
  struct LocalizedName {
    // The name as it appears in the corresponding language.
    std::string name;
    // The language of this localized name. The format of a language is a two
    // letter language code, e.g. 'en' for English.
    // It is legal for an instance of LocalizedName to have an empty |language|
    // field, as sometimes the underlying database does not contain that
    // information.
    std::string language;

   private:
    auto tuple() const { return std::make_tuple(name, language); }

   public:
    bool operator==(const LocalizedName& rhs) const {
      return tuple() == rhs.tuple();
    }
  };

  // Encapsulates information on a mobile access point name. This information
  // is usually necessary for 3GPP networks to be able to connect to a mobile
  // network.
  struct MobileAPN {
    // The access point url, which is fed to the modemmanager while connecting.
    std::string apn;
    // A list of localized names for this access point. Usually there is only
    // one for each country that the associated cellular carrier operates in.
    std::vector<LocalizedName> operator_name_list;
    // The username and password fields that are required by the modemmanager.
    // Either of these values can be empty if none is present. If a MobileAPN
    // instance that is obtained from this parser contains a non-empty value
    // for username/password, this usually means that the carrier requires
    // a certain default pair.
    std::string username;
    std::string password;
    // The authentication method for sending username / password, which could
    // be one of the following values:
    // * (empty):
    //   - When no username or password is provided, no authentication method
    //     is specified.
    //   - When a username and password is provided, the default authentication
    //     method is used (which is PAP for most cases in the current
    //     implementation of ModemManager).
    // * "pap" (kApnAuthenticationPap):
    //   - Password Authentication Protocol (PAP) is used for authentication
    // * "chap" (kApnAuthenticationChap):
    //   - Challenge-Handshake Authentication Protocol (CHAP) for authentication
    std::string authentication;
    // A list of APN types.
    std::set<std::string> apn_types;
    // IP type as one of "ipv4", "ipv6", "ipv4v6" (dual-stack)
    std::string ip_type;
    // If the APN overrides all other APNs of the same type.
    bool is_required_by_carrier_spec = false;

   private:
    auto tuple() const {
      return std::make_tuple(apn, operator_name_list, username, password,
                             authentication, apn_types, ip_type,
                             is_required_by_carrier_spec);
    }

   public:
    bool operator==(const MobileAPN& rhs) const {
      return tuple() == rhs.tuple();
    }
  };

  // Encapsulates information about the Online payment portal used by chrome to
  // redirect users for some carriers.
  struct OnlinePortal {
    std::string url;
    std::string method;
    std::string post_data;

   private:
    auto tuple() const { return std::make_tuple(url, method, post_data); }

   public:
    bool operator==(const OnlinePortal& rhs) const {
      return tuple() == rhs.tuple();
    }
  };

  // Encapsulates information about the entitlement check.
  struct EntitlementConfig {
    // The url used for the mobile hotspot entitlement check using the ChromeOS
    // open source entitlement check implementation.
    std::string url;
    // The HTTP method used for the entitlement check http request.
    std::string method;
    // Parameters to be included in the entitlement check message body.
    Stringmap params;
  };

  // These functions can be called before Init to read non default database
  // file(s). Files included earlier will take precedence over later additions.
  virtual void ClearDatabasePaths();
  virtual void AddDatabasePath(const base::FilePath& absolute_path);

  std::string GetLogPrefix(const char* func) const;
  virtual bool Init(
      MobileOperatorMapperOnOperatorChangedCallback on_operator_changed);

  // ///////////////////////////////////////////////////////////////////////////
  // Functions to obtain information about the current mobile operator.
  // Any of these accessors can return an empty response if the information is
  // not available. Use |IsMobileNetworkOperatorKnown| and
  // |IsMobileVirtualNetworkOperatorKnown| to determine if a fix on the operator
  // has been made. Note that the information returned by the other accessors is
  // only valid when at least |IsMobileNetworkOperatorKnown| returns true. Their
  // values are undefined otherwise.

  // Query whether a mobile network operator has been successfully determined.
  virtual bool IsMobileNetworkOperatorKnown() const;
  // Query whether a mobile network operator has been successfully
  // determined.
  bool IsMobileVirtualNetworkOperatorKnown() const;

  // The unique identifier of this carrier. This is primarily used to
  // identify the user profile in store for each carrier. This identifier is
  // access technology agnostic.
  virtual const std::string& uuid() const;

  virtual const std::string& operator_name() const;
  virtual const std::string& country() const;
  virtual const std::string& mccmnc() const;
  virtual const std::string& gid1() const;

  // A given MVNO can be associated with multiple mcc/mnc pairs. A list of all
  // associated mcc/mnc pairs concatenated together.
  const std::vector<std::string>& mccmnc_list() const;
  // All localized names associated with this carrier entry.
  const std::vector<LocalizedName>& operator_name_list() const;
  // All access point names associated with this carrier entry.
  virtual const std::vector<MobileAPN>& apn_list() const;
  // All Online Payment Portal URLs associated with this carrier entry. There
  // are usually multiple OLPs based on access technology and it is up to the
  // application to use the appropriate one.
  virtual const std::vector<OnlinePortal>& olp_list() const;

  // Some carriers are only available while roaming. This is mainly used by
  // Chrome.
  virtual bool requires_roaming() const;
  // Weather the carrier allows tethering or not.
  virtual bool tethering_allowed() const;
  // If the carrier requires all traffic to go through the DUN APN when
  // tethering.
  virtual bool use_dun_apn_as_default() const;
  // The entitlement check configuration.
  virtual const EntitlementConfig& entitlement_config();
  // Parameters to be included in the entitlement check message body.
  virtual int32_t mtu() const;

  // ///////////////////////////////////////////////////////////////////////////
  // Functions used to notify this object of operator data changes.
  // The Update* methods update the corresponding property of the network
  // operator, and this value may be used to determine the M[V]NO.
  // These values are also the values reported through accessors, overriding any
  // information from the database.

  // Throw away all information provided to the object, and start from top.
  virtual void Reset();

  virtual void UpdateMCCMNC(const std::string& mccmnc);
  virtual void UpdateIMSI(const std::string& imsi);
  void UpdateICCID(const std::string& iccid);
  virtual void UpdateOperatorName(const std::string& operator_name);
  void UpdateGID1(const std::string& gid1);
  void UpdateOnlinePortal(const std::string& url,
                          const std::string& method,
                          const std::string& post_data);

  virtual bool RequiresRoamingOnOperator(
      const MobileOperatorMapper* serving_operator) const;

 private:
  friend class MobileOperatorMapperInitTest;

  // ///////////////////////////////////////////////////////////////////////////
  // Static variables.
  // MCCMNC can be of length 5 or 6. When using this constant, keep in mind that
  // the length of MCCMNC can by |kMCCMNCMinLen| or |kMCCMNCMinLen + 1|.
  static const int kMCCMNCMinLen;

  // ///////////////////////////////////////////////////////////////////////////
  // Functions.
  void PreprocessDatabase();
  // This function assumes that duplicate |values| are never inserted for the
  // same |key|. If you do that, the function is too dumb to deduplicate the
  // |value|s, and two copies will get stored.
  void InsertIntoStringToMNOListMap(
      StringToMNOListMap* table,
      const std::string& key,
      const mobile_operator_db::MobileNetworkOperator* value);

  bool UpdateMNO();
  bool UpdateMVNO();
  bool FilterMatches(const shill::mobile_operator_db::Filter& filter,
                     std::string to_match = "") const;
  const mobile_operator_db::MobileNetworkOperator* PickOneFromDuplicates(
      const std::vector<const mobile_operator_db::MobileNetworkOperator*>&
          duplicates) const;
  // Reloads the information about M[V]NO from the database.
  void RefreshDBInformation();
  void ClearDBInformation();
  // Reload all data from |data|.
  // Semantics: If a field data.x exists, then it *overwrites* the current
  // information gained from data.x. E.g., if |data.name_size() > 0| is true,
  // then we replace *all* names. Otherwise, we leave names untouched.
  // This allows MVNOs to overwrite information obtained from the corresponding
  // MNO.
  void ReloadData(const mobile_operator_db::Data& data);
  // Append candidates recognized by |mccmnc| to the candidate list.
  bool AppendToCandidatesByMCCMNC(const std::string& mccmnc);
  std::string OperatorCodeString() const;

  // Notifies all observers that the operator has changed.
  void PostNotifyOperatorChanged();
  // The actual notification is sent out here. This should not be called
  // directly from any function.
  void NotifyOperatorChanged();

  // For a property update that does not result in an M[V]NO update, this
  // function determines whether observers should be notified anyway.
  bool ShouldNotifyPropertyUpdate() const;

  // OperatorName comparisons for determining the MNO are done after normalizing
  // the names to ignore case and spaces.
  std::string NormalizeOperatorName(const std::string& name) const;

  // These functions encapsulate the logic to update different properties
  // properly whenever an update is either received from the user or the
  // database.
  void HandleMCCMNCUpdate();
  void HandleGID1Update();
  void HandleOperatorNameUpdate();
  void HandleOnlinePortalUpdate();
  void HandleAPNListUpdate();

  // Accessor functions for testing purpose only.
  const std::vector<const mobile_operator_db::MobileOperatorDB*> databases() {
    return databases_;
  }

  // ///////////////////////////////////////////////////////////////////////////
  // Data.
  // Not owned by MobileOperatorMapper.
  EventDispatcher* const dispatcher_;

  const std::string info_owner_;

  // Owned by MobileOperatorMapper, may be created externally.
  std::vector<base::FilePath> database_paths_;

  base::CancelableOnceClosure notify_operator_changed_task_;

  std::vector<const mobile_operator_db::MobileOperatorDB*> databases_;
  StringToMNOListMap mccmnc_to_mnos_;
  StringToMNOListMap name_to_mnos_;

  // |candidates_by_operator_code| can be determined using MCCMNC.
  enum class OperatorCodeType {
    kUnknown,
    kMCCMNC,
  };
  OperatorCodeType operator_code_type_;
  std::vector<const mobile_operator_db::MobileNetworkOperator*>
      candidates_by_operator_code_;

  std::vector<const mobile_operator_db::MobileNetworkOperator*>
      candidates_by_name_;
  const mobile_operator_db::MobileNetworkOperator* current_mno_;
  const mobile_operator_db::MobileVirtualNetworkOperator* current_mvno_;

  // These fields are the information expected to be populated by this object
  // after successfully determining the MVNO.
  std::string uuid_;
  std::string operator_name_;
  std::string country_;
  std::string mccmnc_;
  std::string gid1_;
  std::vector<std::string> mccmnc_list_;
  EntitlementConfig entitlement_config_;
  std::set<shill::mobile_operator_db::Data_EntitlementParam>
      mhs_entitlement_params_;
  std::vector<MobileOperatorMapper::LocalizedName> operator_name_list_;
  bool prioritizes_db_operator_name_;
  std::vector<mobile_operator_db::MobileAPN> raw_apn_list_;
  std::set<mobile_operator_db::Filter_Type> raw_apn_filters_types_;
  std::vector<MobileOperatorMapper::MobileAPN> apn_list_;
  std::vector<MobileOperatorMapper::OnlinePortal> olp_list_;
  std::vector<mobile_operator_db::OnlinePortal> raw_olp_list_;
  bool requires_roaming_;
  bool tethering_allowed_;
  bool use_dun_apn_as_default_;
  std::vector<mobile_operator_db::Filter> roaming_filter_list_;
  int32_t mtu_;
  // These fields store the data obtained from the Update* methods.
  // The database information is kept separate from the information gathered
  // through the Update* methods, because one or the other may be given
  // precedence in different situations.
  // Note: For simplicity, we do not allow the user to enforce an empty value
  // for these variables. So, if |user_mccmnc_| == "", the |mccmnc_| obtained
  // from the database will be used, even if |user_mccmnc_| was explicitly set
  // by the user.
  std::string user_imsi_;
  std::string user_iccid_;
  std::string user_mccmnc_;
  std::string user_operator_name_;
  std::string user_gid1_;
  bool user_olp_empty_;
  MobileOperatorMapper::OnlinePortal user_olp_;
  base::CancelableRepeatingClosure on_operator_changed_cb_;

  // This must be the last data member of this class.
  base::WeakPtrFactory<MobileOperatorMapper> weak_ptr_factory_{this};
};

}  // namespace shill

#endif  // SHILL_CELLULAR_MOBILE_OPERATOR_MAPPER_H_
