// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_CELLULAR_SERVICE_H_
#define SHILL_CELLULAR_CELLULAR_SERVICE_H_

#include <memory>
#include <set>
#include <string>
#include <utility>

#include <base/strings/string_piece.h>
#include <base/time/time.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/cellular/cellular.h"
#include "shill/cellular/subscription_state.h"
#include "shill/mockable.h"
#include "shill/refptr_types.h"
#include "shill/service.h"

namespace shill {

class Error;
class Manager;

class CellularService : public Service {
 public:
  enum ActivationType {
    kActivationTypeNonCellular,  // For future use
    kActivationTypeOMADM,        // For future use
    kActivationTypeOTA,
    kActivationTypeOTASP,
    kActivationTypeUnknown
  };

  // A CellularService is associated with a single SIM Profile, uniquely
  // identified by |iccid|. For pSIM profiles this also identifies the SIM card.
  // For eSIM profiles, |eid| is non-empty and identifies the eSIM card.
  // A CellularService may not be the active service for the associated
  // device, so its eID, ICCID and IMSI properties may not match the device
  // properties.
  CellularService(Manager* manager,
                  const std::string& imsi,
                  const std::string& iccid,
                  const std::string& eid);
  CellularService(const CellularService&) = delete;
  CellularService& operator=(const CellularService&) = delete;

  ~CellularService() override;

  void SetDevice(Cellular* device);

  // Public Service overrides
  void CompleteCellularActivation(Error* error) override;
  std::string GetStorageIdentifier() const override;
  std::string GetLoadableStorageIdentifier(
      const StoreInterface& storage) const override;
  bool IsLoadableFrom(const StoreInterface& storage) const override;
  bool Load(const StoreInterface* storage) override;
  bool Save(StoreInterface* storage) override;
  bool IsVisible() const override;
  void AutoConnect() override;

  // See matching method in cellular.h for details.
  const std::string& GetSimCardId() const;

  const std::string& imsi() const { return imsi_; }
  const std::string& iccid() const { return iccid_; }
  const std::string& eid() const { return eid_; }
  const CellularRefPtr& cellular() const { return cellular_; }

  void SetActivationType(ActivationType type);
  std::string GetActivationTypeString() const;

  mockable void SetActivationState(const std::string& state);
  mockable const std::string& activation_state() const {
    return activation_state_;
  }

  void SetOLP(const std::string& url,
              const std::string& method,
              const std::string& post_data);
  const Stringmap& olp() const { return olp_; }

  void SetUsageURL(const std::string& url);
  const std::string& usage_url() const { return usage_url_; }

  void SetServingOperator(const Stringmap& serving_operator);
  const Stringmap& serving_operator() const { return serving_operator_; }

  // Utility function that can be used to convert MCC code (defined by the ITU
  // in http://handle.itu.int/11.1002/pub/80f1788f-en) into ISO 3166-1 alpha-2.
  // For example when called with "311" it should return "US".  On failure empty
  // string is returned.
  static std::string MCCToAlpha2(const std::string& mcc);

  // Sets network technology to |technology| and broadcasts the property change.
  void SetNetworkTechnology(const std::string& technology);
  const std::string& network_technology() const { return network_technology_; }

  // Sets roaming state to |state| and broadcasts the property change.
  void SetRoamingState(const std::string& state);
  const std::string& roaming_state() const { return roaming_state_; }
  // Checks device rules as well as service rules and returns if roaming is
  // allowed for this service.
  bool IsRoamingAllowed();
  // Returns true if we are registered on a roaming network, but roaming is
  // disallowed.
  bool IsRoamingRuleViolated();

  const std::string& ppp_username() const { return ppp_username_; }
  const std::string& ppp_password() const { return ppp_password_; }

  const std::optional<Stringmaps>& custom_apn_list() const {
    return custom_apn_list_;
  }

  Stringmap* GetUserSpecifiedApn();
  Stringmap* GetLastGoodApn();
  virtual void SetLastGoodApn(const Stringmap& apn_info);
  virtual void ClearLastGoodApn();
  Stringmap* GetLastAttachApn();
  virtual void SetLastAttachApn(const Stringmap& apn_info);
  virtual void ClearLastAttachApn();
  virtual void SetLastConnectedAttachApn(const Stringmap& apn_info);
  virtual void ClearLastConnectedAttachApn();

  void NotifySubscriptionStateChanged(SubscriptionState subscription_state);

  static const char kStorageAPN[];
  static const char kStorageIccid[];
  static const char kStorageImsi[];
  static const char kStoragePPPUsername[];
  static const char kStoragePPPPassword[];
  static const char kStorageSimCardId[];
  static const char kStorageCustomApnList[];
  static const char kStorageAllowRoaming[];

  // Used to copy the value of Device.AllowRoaming by service_provider for
  // SIM's inserted before M94. Also used by unit tests.
  void set_allow_roaming(bool allow_roaming) { allow_roaming_ = allow_roaming; }

  void set_activation_state_for_testing(const std::string& activation_state) {
    activation_state_ = activation_state;
  }
  void set_apn_info_for_testing(const Stringmap& apn_info) {
    apn_info_ = apn_info;
  }
  void set_custom_apn_list_for_testing(const Stringmaps& custom_apn_list) {
    custom_apn_list_ = custom_apn_list;
  }

 protected:
  // Protected Service overrides
  void OnConnect(Error* error) override;
  void OnDisconnect(Error* error, const char* reason) override;
  bool IsAutoConnectable(const char** reason) const override;
  base::TimeDelta GetMinAutoConnectCooldownTime() const override;
  base::TimeDelta GetMaxAutoConnectCooldownTime() const override;
  bool IsDisconnectable(Error* error) const override;
  bool IsMeteredByServiceProperties() const override;
  RpcIdentifier GetDeviceRpcId(Error* error) const override;

 private:
  friend class CellularCapability3gppTest;
  friend class CellularCapabilityCdmaTest;
  friend class CellularServiceTest;
  friend class CellularTest;

  template <typename key_type, typename value_type>
  friend class ContainsCellularPropertiesMatcherP2;

  FRIEND_TEST(CellularTest, Connect);
  FRIEND_TEST(CellularTest, FriendlyServiceName);
  FRIEND_TEST(CellularTest, GetLogin);  // ppp_username_, ppp_password_
  FRIEND_TEST(CellularServiceTest, SetApn);
  FRIEND_TEST(CellularServiceTest, SetAttachApn);
  FRIEND_TEST(CellularServiceTest, ClearApn);
  FRIEND_TEST(CellularServiceTest, LastGoodApn);
  FRIEND_TEST(CellularServiceTest, LastConnectedAttachApn);
  FRIEND_TEST(CellularServiceTest, IsAutoConnectable);
  FRIEND_TEST(CellularServiceTest, LoadResetsPPPAuthFailure);
  FRIEND_TEST(CellularServiceTest, SaveAndLoadApn);
  FRIEND_TEST(CellularServiceTest, IgnoreUnversionedLastGoodApn);
  FRIEND_TEST(CellularServiceTest, MergeDetailsFromApnList);
  FRIEND_TEST(CellularServiceTest, CustomSetterNoopChange);
  FRIEND_TEST(CellularServiceTest, SetAllowRoaming);

  // Used in CellularServiceTest
  static const char kAutoConnActivating[];
  static const char kAutoConnSimUnselected[];
  static const char kAutoConnBadPPPCredentials[];
  static const char kAutoConnDeviceDisabled[];
  static const char kAutoConnNotRegistered[];
  static const char kAutoConnOutOfCredits[];
  static const char kAutoConnConnectFailed[];
  static const char kAutoConnInhibited[];
  static const char kAutoConnNoDevice[];

  void HelpRegisterDerivedString(
      base::StringPiece name,
      std::string (CellularService::*get)(Error* error),
      bool (CellularService::*set)(const std::string& value, Error* error));
  void HelpRegisterDerivedStringmap(
      base::StringPiece name,
      Stringmap (CellularService::*get)(Error* error),
      bool (CellularService::*set)(const Stringmap& value, Error* error));
  void HelpRegisterDerivedStringmaps(
      base::StringPiece name,
      Stringmaps (CellularService::*get)(Error* error),
      bool (CellularService::*set)(const Stringmaps& value, Error* error),
      void (CellularService::*clear)(Error*));
  void HelpRegisterDerivedBool(base::StringPiece name,
                               bool (CellularService::*get)(Error* error),
                               bool (CellularService::*set)(const bool&,
                                                            Error*));
  std::set<std::string> GetStorageGroupsWithProperty(
      const StoreInterface& storage,
      const std::string& key,
      const std::string& value) const;
  std::string CalculateActivationType(Error* error);
  Stringmap GetApn(Error* error);
  bool SetApn(const Stringmap& value, Error* error);
  Stringmap* GetLastConnectedDefaultApn();
  Stringmap* GetLastConnectedAttachApn();
  KeyValueStore GetStorageProperties() const;
  std::string GetDefaultStorageIdentifier() const;
  bool IsOutOfCredits(Error* /*error*/);
  bool SetAllowRoaming(const bool& value, Error* error);
  bool GetAllowRoaming(Error* /*error*/);
  Stringmap ValidateCustomApn(const Stringmap& value, bool using_apn_revamp_ui);
  Stringmaps GetCustomApnList(Error* error);
  bool SetCustomApnList(const Stringmaps& value, Error* error);
  // This function is used to completely remove the property. The existence of
  // the property indicates if the new APN UI revamp is used or not.
  void ClearCustomApnList(Error*);

  // The IMSI for the SIM. This is saved in the Profile and emitted as a
  // property so that it is available for non primary SIM Profiles.
  // This is set on construction when available, or may be loaded from a saved
  // Profile entry.
  std::string imsi_;

  // ICCID uniquely identifies a SIM profile.
  const std::string iccid_;

  // EID of the associated eSIM card, or empty for a SIM profile associated with
  // a physical SIM card.
  const std::string eid_;

  ActivationType activation_type_ = kActivationTypeUnknown;
  std::string activation_state_;
  Stringmap serving_operator_;
  std::string network_technology_;
  std::string roaming_state_;
  Stringmap olp_;
  std::string usage_url_;
  Stringmap apn_info_;
  std::optional<Stringmaps> custom_apn_list_;
  Stringmap last_good_apn_info_;
  // Stores the attach APN used for the initial EPS settings
  Stringmap last_attach_apn_info_;
  // Similar to |last_good_apn_info_|, but isn't cleared when the connection
  // fails. This property will be removed after the APN Revamp project is
  // completely migrated (b/251512775).
  Stringmap last_connected_default_apn_info_;
  // The last attach APN used for a successful connection. Persisted when the
  // service is saved. This property will be removed after the APN Revamp
  // project is completely migrated (b/251512775).
  Stringmap last_connected_attach_apn_info_;
  std::string ppp_username_;
  std::string ppp_password_;
  bool allow_roaming_ = false;
  bool provider_requires_roaming_ = false;

  // The storage identifier defaults to cellular_{iccid}.
  std::string storage_identifier_;

  // The Cellular Device associated with this Service. Note: This may not be
  // the active service for |cellular_| if there are multiple SIM profiles for
  // |cellular_|.
  CellularRefPtr cellular_;

  // Flag indicating if the user has run out of data credits.
  bool out_of_credits_ = false;
};

}  // namespace shill

#endif  // SHILL_CELLULAR_CELLULAR_SERVICE_H_
