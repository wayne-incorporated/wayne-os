// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/cellular_capability_3gpp.h"

#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/service_constants.h>
#include <ModemManager/ModemManager.h>

#include "shill/cellular/cellular.h"
#include "shill/cellular/cellular_bearer.h"
#include "shill/cellular/cellular_service.h"
#include "shill/cellular/cellular_service_provider.h"
#include "shill/cellular/mock_cellular.h"
#include "shill/cellular/mock_cellular_service.h"
#include "shill/cellular/mock_mm1_modem_location_proxy.h"
#include "shill/cellular/mock_mm1_modem_modem3gpp_profile_manager_proxy.h"
#include "shill/cellular/mock_mm1_modem_modem3gpp_proxy.h"
#include "shill/cellular/mock_mm1_modem_proxy.h"
#include "shill/cellular/mock_mm1_modem_signal_proxy.h"
#include "shill/cellular/mock_mm1_modem_simple_proxy.h"
#include "shill/cellular/mock_mm1_sim_proxy.h"
#include "shill/cellular/mock_mobile_operator_info.h"
#include "shill/cellular/mock_modem_info.h"
#include "shill/cellular/mock_pending_activation_store.h"
#include "shill/dbus/dbus_properties_proxy.h"
#include "shill/dbus/fake_properties_proxy.h"
#include "shill/error.h"
#include "shill/mock_adaptors.h"
#include "shill/mock_control.h"
#include "shill/mock_device_info.h"
#include "shill/mock_event_dispatcher.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/mock_profile.h"
#include "shill/store/fake_store.h"
#include "shill/test_event_dispatcher.h"
#include "shill/testing.h"

using testing::_;
using testing::AnyNumber;
using testing::InSequence;
using testing::Invoke;
using testing::Mock;
using testing::NiceMock;
using testing::Return;
using testing::ReturnRef;
using testing::SaveArg;
using testing::WithArg;

namespace shill {

namespace {

const uint32_t kAccessTechnologies =
    MM_MODEM_ACCESS_TECHNOLOGY_LTE | MM_MODEM_ACCESS_TECHNOLOGY_HSPA_PLUS;
const char kDefaultActiveBearerPathPrefix[] = "/bearer/default/active";
const char kDunActiveBearerPathPrefix[] = "/bearer/dun/active";
const char kDefaultInactiveBearerPathPrefix[] = "/bearer/default/inactive";
const char kDunInactiveBearerPathPrefix[] = "/bearer/default/inactive";
constexpr char kDeviceId[] = "<device_id>";
const char kEid[] = "310100000002";
const char kIccid[] = "1234567890";
const char kImei[] = "999911110000";
const char kImsi[] = "310100000001";
const char kSimPathPrefix[] = "/foo/sim";
const RpcIdentifier kSimPath1("/foo/sim/1");
const RpcIdentifier kSimPath2("/foo/sim/2");

}  // namespace

MATCHER_P(HasApn, expected_apn, "") {
  return arg.template Contains<std::string>(CellularBearer::kMMApnProperty) &&
         expected_apn ==
             arg.template Get<std::string>(CellularBearer::kMMApnProperty);
}

MATCHER(HasNoUser, "") {
  return !arg.template Contains<std::string>(CellularBearer::kMMUserProperty);
}

MATCHER_P(HasUser, expected_user, "") {
  return arg.template Contains<std::string>(CellularBearer::kMMUserProperty) &&
         expected_user ==
             arg.template Get<std::string>(CellularBearer::kMMUserProperty);
}

MATCHER(HasNoPassword, "") {
  return !arg.template Contains<std::string>(
      CellularBearer::kMMPasswordProperty);
}

MATCHER_P(HasPassword, expected_password, "") {
  return arg.template Contains<std::string>(
             CellularBearer::kMMPasswordProperty) &&
         expected_password ==
             arg.template Get<std::string>(CellularBearer::kMMPasswordProperty);
}

MATCHER(HasNoAllowedAuth, "") {
  return !arg.template Contains<std::string>(
      CellularBearer::kMMAllowedAuthProperty);
}

MATCHER_P(HasAllowedAuth, expected_authentication, "") {
  return arg.template Contains<uint32_t>(
             CellularBearer::kMMAllowedAuthProperty) &&
         expected_authentication ==
             arg.template Get<uint32_t>(CellularBearer::kMMAllowedAuthProperty);
}

MATCHER(HasNoIpType, "") {
  return !arg.template Contains<uint32_t>(CellularBearer::kMMIpTypeProperty);
}

MATCHER_P(HasIpType, expected_ip_type, "") {
  return arg.template Contains<uint32_t>(CellularBearer::kMMIpTypeProperty) &&
         expected_ip_type ==
             arg.template Get<uint32_t>(CellularBearer::kMMIpTypeProperty);
}

class CellularCapability3gppTest : public testing::TestWithParam<std::string> {
 public:
  CellularCapability3gppTest()
      : control_interface_(this),
        manager_(&control_interface_, &dispatcher_, &metrics_),
        device_info_(&manager_),
        modem_info_(&control_interface_, &manager_),
        modem_3gpp_proxy_(new NiceMock<mm1::MockModemModem3gppProxy>()),
        modem_3gpp_profile_manager_proxy_(
            new NiceMock<mm1::MockModemModem3gppProfileManagerProxy>()),
        modem_proxy_(new mm1::MockModemProxy()),
        modem_signal_proxy_(new NiceMock<mm1::MockModemSignalProxy>()),
        modem_simple_proxy_(new NiceMock<mm1::MockModemSimpleProxy>()),
        profile_(new NiceMock<MockProfile>(&manager_)),
        mock_mobile_operator_info_(nullptr) {
    cellular_service_provider_.set_profile_for_testing(profile_);
  }

  ~CellularCapability3gppTest() override = default;

  void SetUp() override {
    EXPECT_CALL(*modem_proxy_, set_state_changed_callback(_))
        .Times(AnyNumber());
    EXPECT_CALL(manager_, device_info()).WillRepeatedly(Return(&device_info_));
    EXPECT_CALL(manager_, modem_info()).WillRepeatedly(Return(&modem_info_));

    cellular_ = new Cellular(&manager_, "", "00:01:02:03:04:05", 0, "",
                             RpcIdentifier(""));
    service_ = new MockCellularService(&manager_, cellular_);
    device_adaptor_ = static_cast<DeviceMockAdaptor*>(cellular_->adaptor());
    capability_ = static_cast<CellularCapability3gpp*>(
        cellular_->capability_for_testing());
    cellular_->SetServiceForTesting(service_);
    cellular_->SetSelectedServiceForTesting(service_);
    cellular_service_provider_.Start();
    metrics_.RegisterDevice(cellular_->interface_index(),
                            Technology::kCellular);

    EXPECT_CALL(*service_, activation_state())
        .WillRepeatedly(ReturnRef(kActivationStateUnknown));
    EXPECT_CALL(*service_, SetStrength(0)).Times(AnyNumber());

    VerifyAndSetActivationExpectations();

    EXPECT_CALL(manager_, cellular_service_provider())
        .WillRepeatedly(Return(&cellular_service_provider_));

    EXPECT_CALL(*profile_, GetConstStorage())
        .WillRepeatedly(Return(&profile_storage_));
    EXPECT_CALL(*profile_, GetStorage())
        .WillRepeatedly(Return(&profile_storage_));

    SetMockMobileOperatorInfoObjects();
  }

  void TearDown() override {
    metrics_.DeregisterDevice(cellular_->interface_index());
    cellular_service_provider_.Stop();
    metrics_.RegisterDevice(cellular_->interface_index(),
                            Technology::kCellular);
    cellular_->SetServiceForTesting(nullptr);
    cellular_->SetSelectedServiceForTesting(nullptr);
    service_ = nullptr;
    CHECK(cellular_->HasOneRef());
    cellular_ = nullptr;
    device_adaptor_ = nullptr;
  }

  void VerifyAndSetActivationExpectations() {
    Mock::VerifyAndClearExpectations(
        modem_info_.mock_pending_activation_store());

    // kStateUnknown leads to minimal extra work in maintaining
    // activation state.
    ON_CALL(*modem_info_.mock_pending_activation_store(),
            GetActivationState(PendingActivationStore::kIdentifierICCID, _))
        .WillByDefault(Return(PendingActivationStore::kStateUnknown));
    EXPECT_CALL(*modem_info_.mock_pending_activation_store(),
                GetActivationState(PendingActivationStore::kIdentifierICCID, _))
        .Times(AnyNumber());
    EXPECT_CALL(*service_, SetActivationState(kActivationStateActivated))
        .Times(AnyNumber());
  }

  // Saves |sim_properties| for |path| to be provided by FakePropertiesProxy.
  void SetSimProperties(const RpcIdentifier& path,
                        const KeyValueStore& sim_properties) {
    sim_paths_.push_back(path);
    sim_properties_.push_back(sim_properties);
  }

  // Calls capability_->OnPropertiesChanged with Modem.SIM = |path|.
  void SetSimPath(const RpcIdentifier& path) {
    KeyValueStore modem_properties;
    modem_properties.Set<RpcIdentifier>(MM_MODEM_PROPERTY_SIM, path);
    capability_->OnPropertiesChanged(MM_DBUS_INTERFACE_MODEM, modem_properties);
    dispatcher_.DispatchPendingEvents();
  }

  // Calls capability_->OnPropertiesChanged with Modem.SIM = |path| and
  // Modem.SIMSLOTS = |sim_properties_|.
  void UpdateSims(const RpcIdentifier& path) {
    KeyValueStore modem_properties;
    modem_properties.Set<RpcIdentifier>(MM_MODEM_PROPERTY_SIM, path);
    RpcIdentifiers slots;
    for (const auto& path : sim_paths_)
      slots.push_back(path);
    modem_properties.Set<RpcIdentifiers>(MM_MODEM_PROPERTY_SIMSLOTS, slots);
    capability_->OnPropertiesChanged(MM_DBUS_INTERFACE_MODEM, modem_properties);
    dispatcher_.DispatchPendingEvents();
  }

  // Sets up a single SIM path and properties.
  void SetSimPropertiesAndPath(const RpcIdentifier& path,
                               const KeyValueStore& sim_properties) {
    SetSimProperties(path, sim_properties);
    UpdateSims(path);
  }

  void SetCellularSimProperties(const Cellular::SimProperties& sim_properties) {
    std::vector<Cellular::SimProperties> slot_properties;
    slot_properties.push_back(sim_properties);
    cellular_->SetSimProperties(slot_properties, 0u);
  }

  void SetDefaultCellularSimProperties() {
    Cellular::SimProperties sim_properties;
    sim_properties.eid = kEid;
    sim_properties.iccid = kIccid;
    sim_properties.imsi = kImsi;
    SetCellularSimProperties(sim_properties);
  }

  void ClearCellularSimProperties() {
    SetCellularSimProperties(Cellular::SimProperties());
  }

  void ClearCapabilitySimProperties() {
    sim_paths_.clear();
    sim_properties_.clear();
    UpdateSims(RpcIdentifier());
  }

  void CreateService() {
    // The following constants are never directly accessed by the tests.
    const char kFriendlyServiceName[] = "default_test_service_name";
    const char kOperatorCode[] = "10010";
    const char kOperatorName[] = "default_test_operator_name";
    const char kOperatorCountry[] = "us";

    // Simulate all the side-effects of Cellular::CreateService
    auto service =
        new CellularService(&manager_, cellular_->imsi(), cellular_->iccid(),
                            cellular_->GetSimCardId());
    service->SetFriendlyName(kFriendlyServiceName);

    Stringmap serving_operator;
    serving_operator[kOperatorCodeKey] = kOperatorCode;
    serving_operator[kOperatorNameKey] = kOperatorName;
    serving_operator[kOperatorCountryKey] = kOperatorCountry;
    service->SetServingOperator(serving_operator);
    cellular_->set_home_provider_for_testing(serving_operator);
    cellular_->SetServiceForTesting(service);
  }

  void ExpectModemAndModem3gppProperties() {
    modem_properties_.Set<uint32_t>(MM_MODEM_PROPERTY_ACCESSTECHNOLOGIES,
                                    kAccessTechnologies);
    std::tuple<uint32_t, bool> signal_signal{90, true};
    modem_properties_.SetVariant(MM_MODEM_PROPERTY_SIGNALQUALITY,
                                 brillo::Any(signal_signal));

    // Set fake modem 3gpp properties.
    modem_3gpp_properties_.Set<uint32_t>(
        MM_MODEM_MODEM3GPP_PROPERTY_ENABLEDFACILITYLOCKS, 0);
    modem_3gpp_properties_.Set<std::string>(MM_MODEM_MODEM3GPP_PROPERTY_IMEI,
                                            kImei);

    // Set up mock modem signal properties.
    KeyValueStore modem_signal_property_lte;
    modem_signal_property_lte.Set<double>(
        CellularCapability3gpp::kRsrpProperty,
        CellularCapability3gpp::kRsrpBounds.min_threshold);
    modem_signal_properties_.Set<KeyValueStore>(MM_MODEM_SIGNAL_PROPERTY_LTE,
                                                modem_signal_property_lte);
  }

  void InvokeEnable(bool enable, ResultCallback callback, int timeout) {
    std::move(callback).Run(Error(Error::kSuccess));
  }
  void InvokeEnableFail(bool enable, ResultCallback callback, int timeout) {
    std::move(callback).Run(Error(Error::kOperationFailed));
  }
  void InvokeEnableInWrongState(bool enable,
                                ResultCallback callback,
                                int timeout) {
    std::move(callback).Run(Error(Error::kWrongState));
  }
  void InvokeList(ResultVariantDictionariesOnceCallback callback, int timeout) {
    std::move(callback).Run(VariantDictionaries(), Error());
  }
  void InvokeSetPowerState(const uint32_t& power_state,
                           ResultCallback callback,
                           int timeout) {
    std::move(callback).Run(Error(Error::kSuccess));
  }

  void SetSignalProxy() {
    capability_->proxies_initialized_ = true;
    capability_->modem_signal_proxy_ = std::move(modem_signal_proxy_);
  }

  void SetSimpleProxy() {
    capability_->proxies_initialized_ = true;
    capability_->modem_simple_proxy_ = std::move(modem_simple_proxy_);
  }

  void SetMockMobileOperatorInfoObjects() {
    CHECK(!mock_mobile_operator_info_);
    mock_mobile_operator_info_ =
        new NiceMock<MockMobileOperatorInfo>(&dispatcher_, "HomeProvider");
    mock_mobile_operator_info_->Init();
    cellular_->set_mobile_operator_info_for_testing(mock_mobile_operator_info_);
  }

  void ReleaseCapabilityProxies() {
    EXPECT_EQ(true, capability_->proxies_initialized_);
    capability_->ReleaseProxies();
    EXPECT_EQ(nullptr, capability_->modem_3gpp_proxy_);
    EXPECT_EQ(nullptr, capability_->modem_3gpp_profile_manager_proxy_);
    EXPECT_EQ(nullptr, capability_->modem_proxy_);
    EXPECT_EQ(nullptr, capability_->modem_location_proxy_);
    EXPECT_EQ(nullptr, capability_->modem_signal_proxy_);
    EXPECT_EQ(nullptr, capability_->modem_simple_proxy_);
  }

  void SetRegistrationDroppedUpdateTimeout(base::TimeDelta timeout) {
    capability_->registration_dropped_update_timeout_ = timeout;
  }

  void SetMockRegistrationDroppedUpdateCallback() {
    capability_->registration_dropped_update_callback_.Reset(base::BindOnce(
        &CellularCapability3gppTest::FakeCallback, base::Unretained(this)));
  }

  void ConnectionAttemptComplete(ApnList::ApnType apn_type,
                                 const Error& error) {
    return capability_->ConnectionAttemptComplete(apn_type, error);
  }
  bool ConnectionAttemptInitialize(ApnList::ApnType apn_type,
                                   const std::deque<Stringmap>& apn_try_list,
                                   ResultCallback result_callback) {
    return capability_->ConnectionAttemptInitialize(apn_type, apn_try_list,
                                                    std::move(result_callback));
  }

  KeyValueStore ConnectionAttemptNextProperties(ApnList::ApnType apn_type) {
    return capability_->ConnectionAttemptNextProperties(apn_type);
  }
  void ConnectionAttemptConnect(ApnList::ApnType apn_type) {
    capability_->ConnectionAttemptConnect(apn_type);
  }
  void ConnectionAttemptOnConnectReply(ApnList::ApnType apn_type,
                                       const RpcIdentifier& bearer,
                                       const Error& error) {
    capability_->ConnectionAttemptOnConnectReply(apn_type, bearer, error);
  }

  void StartModem(Error* error) {
    base::test::TestFuture<Error> e;
    capability_->StartModem(GetResultCallback(&e));
    *error = e.Get();
  }

  void StopModem(Error* error) {
    base::test::TestFuture<Error> e;
    capability_->StopModem(GetResultCallback(&e));
    *error = e.Get();
  }

  void InitProxies() { capability_->InitProxies(); }

  MOCK_METHOD(void, TestCallback, (const Error&));
  MOCK_METHOD(void, FakeCallback, ());

 protected:
  brillo::VariantDictionary GetSimProperties(const RpcIdentifier& sim_path) {
    const auto iter = std::find(sim_paths_.begin(), sim_paths_.end(), sim_path);
    if (iter == sim_paths_.end())
      return brillo::VariantDictionary();
    size_t idx = iter - sim_paths_.begin();
    return sim_properties_[idx].properties();
  }

  class TestControl : public MockControl {
   public:
    explicit TestControl(CellularCapability3gppTest* test) : test_(test) {
      KeyValueStore default_connect_properties;
      default_connect_properties.Set<uint32_t>(
          CellularBearer::kMMApnTypeProperty, MM_BEARER_APN_TYPE_DEFAULT);

      KeyValueStore dun_connect_properties;
      dun_connect_properties.Set<uint32_t>(CellularBearer::kMMApnTypeProperty,
                                           MM_BEARER_APN_TYPE_TETHERING);

      KeyValueStore ip4config;
      ip4config.Set<uint32_t>("method", MM_BEARER_IP_METHOD_DHCP);

      // Default active bearer
      default_active_bearer_properties_.Set<bool>(MM_BEARER_PROPERTY_CONNECTED,
                                                  true);
      default_active_bearer_properties_.Set<std::string>(
          MM_BEARER_PROPERTY_INTERFACE, "fake0");
      default_active_bearer_properties_.Set<KeyValueStore>(
          MM_BEARER_PROPERTY_PROPERTIES, default_connect_properties);
      default_active_bearer_properties_.Set<KeyValueStore>(
          MM_BEARER_PROPERTY_IP4CONFIG, ip4config);

      // Default inactive bearer
      default_inactive_bearer_properties_.Set<bool>(
          MM_BEARER_PROPERTY_CONNECTED, false);
      default_inactive_bearer_properties_.Set<KeyValueStore>(
          MM_BEARER_PROPERTY_PROPERTIES, default_connect_properties);

      // Dun active bearer
      dun_active_bearer_properties_.Set<bool>(MM_BEARER_PROPERTY_CONNECTED,
                                              true);
      dun_active_bearer_properties_.Set<std::string>(
          MM_BEARER_PROPERTY_INTERFACE, "fake1");
      dun_active_bearer_properties_.Set<KeyValueStore>(
          MM_BEARER_PROPERTY_PROPERTIES, dun_connect_properties);
      dun_active_bearer_properties_.Set<KeyValueStore>(
          MM_BEARER_PROPERTY_IP4CONFIG, ip4config);

      // Dun inactive bearer
      dun_inactive_bearer_properties_.Set<bool>(MM_BEARER_PROPERTY_CONNECTED,
                                                false);
      dun_inactive_bearer_properties_.Set<KeyValueStore>(
          MM_BEARER_PROPERTY_PROPERTIES, dun_connect_properties);
    }

    std::unique_ptr<mm1::ModemLocationProxyInterface>
    CreateMM1ModemLocationProxy(const RpcIdentifier& /*path*/,
                                const std::string& /*service*/) override {
      return std::make_unique<mm1::MockModemLocationProxy>();
    }

    std::unique_ptr<mm1::ModemModem3gppProxyInterface>
    CreateMM1ModemModem3gppProxy(const RpcIdentifier& /*path*/,
                                 const std::string& /*service*/) override {
      return std::move(test_->modem_3gpp_proxy_);
    }

    std::unique_ptr<mm1::ModemModem3gppProfileManagerProxyInterface>
    CreateMM1ModemModem3gppProfileManagerProxy(
        const RpcIdentifier& /*path*/,
        const std::string& /*service*/) override {
      return std::move(test_->modem_3gpp_profile_manager_proxy_);
    }

    std::unique_ptr<mm1::ModemProxyInterface> CreateMM1ModemProxy(
        const RpcIdentifier& /*path*/,
        const std::string& /*service*/) override {
      return std::move(test_->modem_proxy_);
    }

    std::unique_ptr<mm1::ModemSignalProxyInterface> CreateMM1ModemSignalProxy(
        const RpcIdentifier& /*path*/,
        const std::string& /*service*/) override {
      return std::move(test_->modem_signal_proxy_);
    }

    std::unique_ptr<mm1::ModemSimpleProxyInterface> CreateMM1ModemSimpleProxy(
        const RpcIdentifier& /*path*/,
        const std::string& /*service*/) override {
      return std::move(test_->modem_simple_proxy_);
    }

    std::unique_ptr<mm1::SimProxyInterface> CreateMM1SimProxy(
        const RpcIdentifier& /*path*/,
        const std::string& /*service*/) override {
      return std::make_unique<mm1::MockSimProxy>();
    }

    std::unique_ptr<DBusPropertiesProxy> CreateDBusPropertiesProxy(
        const RpcIdentifier& path, const std::string& /*service*/) override {
      std::unique_ptr<DBusPropertiesProxy> properties_proxy =
          DBusPropertiesProxy::CreateDBusPropertiesProxyForTesting(
              std::make_unique<FakePropertiesProxy>());
      FakePropertiesProxy* fake_properties = static_cast<FakePropertiesProxy*>(
          properties_proxy->GetDBusPropertiesProxyForTesting());
      if (path.value().find(kSimPathPrefix) != std::string::npos) {
        fake_properties->SetDictionaryForTesting(MM_DBUS_INTERFACE_SIM,
                                                 test_->GetSimProperties(path));
      } else if (path.value().find(kDefaultActiveBearerPathPrefix) !=
                 std::string::npos) {
        fake_properties->SetDictionaryForTesting(
            MM_DBUS_INTERFACE_BEARER,
            default_active_bearer_properties_.properties());
      } else if (path.value().find(kDefaultInactiveBearerPathPrefix) !=
                 std::string::npos) {
        fake_properties->SetDictionaryForTesting(
            MM_DBUS_INTERFACE_BEARER,
            default_inactive_bearer_properties_.properties());
      } else if (path.value().find(kDunActiveBearerPathPrefix) !=
                 std::string::npos) {
        fake_properties->SetDictionaryForTesting(
            MM_DBUS_INTERFACE_BEARER,
            dun_active_bearer_properties_.properties());
      } else if (path.value().find(kDunInactiveBearerPathPrefix) !=
                 std::string::npos) {
        fake_properties->SetDictionaryForTesting(
            MM_DBUS_INTERFACE_BEARER,
            dun_inactive_bearer_properties_.properties());
      } else {
        fake_properties->SetDictionaryForTesting(
            MM_DBUS_INTERFACE_MODEM, test_->modem_properties_.properties());
        fake_properties->SetForTesting(MM_DBUS_INTERFACE_MODEM,
                                       MM_MODEM_PROPERTY_DEVICE,
                                       brillo::Any(std::string(kDeviceId)));
        fake_properties->SetDictionaryForTesting(
            MM_DBUS_INTERFACE_MODEM_MODEM3GPP,
            test_->modem_3gpp_properties_.properties());
        fake_properties->SetDictionaryForTesting(
            MM_DBUS_INTERFACE_MODEM_SIGNAL,
            test_->modem_signal_properties_.properties());
      }
      return properties_proxy;
    }

   private:
    CellularCapability3gppTest* test_;
    KeyValueStore default_active_bearer_properties_;
    KeyValueStore dun_active_bearer_properties_;
    KeyValueStore default_inactive_bearer_properties_;
    KeyValueStore dun_inactive_bearer_properties_;
  };

  EventDispatcherForTest dispatcher_;
  TestControl control_interface_;
  NiceMock<MockMetrics> metrics_;
  NiceMock<MockManager> manager_;
  NiceMock<MockDeviceInfo> device_info_;
  MockModemInfo modem_info_;
  std::unique_ptr<NiceMock<mm1::MockModemModem3gppProxy>> modem_3gpp_proxy_;
  std::unique_ptr<NiceMock<mm1::MockModemModem3gppProfileManagerProxy>>
      modem_3gpp_profile_manager_proxy_;
  std::unique_ptr<mm1::MockModemProxy> modem_proxy_;
  std::unique_ptr<mm1::MockModemSignalProxy> modem_signal_proxy_;
  std::unique_ptr<mm1::MockModemSimpleProxy> modem_simple_proxy_;
  CellularCapability3gpp* capability_ = nullptr;  // Owned by |cellular_|.
  DeviceMockAdaptor* device_adaptor_ = nullptr;   // Owned by |cellular_|.
  CellularRefPtr cellular_;
  MockCellularService* service_ = nullptr;  // owned by cellular_
  CellularServiceProvider cellular_service_provider_{&manager_};
  FakeStore profile_storage_;
  scoped_refptr<NiceMock<MockProfile>> profile_;

  // Properties provided by TestControl::CreateDBusPropertiesProxy()
  KeyValueStore modem_properties_;
  KeyValueStore modem_3gpp_properties_;
  KeyValueStore modem_signal_properties_;

  // saved for testing connect operations.
  RpcIdentifierCallback connect_callback_;

  // Set when required and passed to |cellular_|. Owned by |cellular_|.
  MockMobileOperatorInfo* mock_mobile_operator_info_;

 private:
  std::vector<RpcIdentifier> sim_paths_;
  std::vector<KeyValueStore> sim_properties_;
};

TEST_F(CellularCapability3gppTest, StartModem) {
  ExpectModemAndModem3gppProperties();

  EXPECT_CALL(
      *modem_proxy_,
      Enable(true, _, CellularCapability3gpp::kTimeoutEnable.InMilliseconds()))
      .WillOnce(Invoke(this, &CellularCapability3gppTest::InvokeEnable));
  EXPECT_CALL(*modem_3gpp_profile_manager_proxy_, List(_, _))
      .WillOnce(Invoke(this, &CellularCapability3gppTest::InvokeList));

  Error error;
  StartModem(&error);

  EXPECT_TRUE(error.IsSuccess());
  EXPECT_EQ(kImei, cellular_->imei());
  EXPECT_EQ(kAccessTechnologies,
            capability_->access_technologies_for_testing());
}

TEST_F(CellularCapability3gppTest, StartModemFailure) {
  EXPECT_CALL(
      *modem_proxy_,
      Enable(true, _, CellularCapability3gpp::kTimeoutEnable.InMilliseconds()))
      .WillOnce(Invoke(this, &CellularCapability3gppTest::InvokeEnableFail));

  Error error;
  StartModem(&error);
  EXPECT_TRUE(error.IsFailure());
}

TEST_F(CellularCapability3gppTest, StartModemInWrongState) {
  ExpectModemAndModem3gppProperties();

  EXPECT_CALL(
      *modem_proxy_,
      Enable(true, _, CellularCapability3gpp::kTimeoutEnable.InMilliseconds()))
      .WillOnce(
          Invoke(this, &CellularCapability3gppTest::InvokeEnableInWrongState))
      .WillOnce(Invoke(this, &CellularCapability3gppTest::InvokeEnable));

  Error error;
  cellular_->set_state_for_testing(Cellular::State::kEnabled);
  StartModem(&error);
  EXPECT_TRUE(error.IsFailure());

  // Verify that modem properties have been read.
  EXPECT_EQ(kImei, cellular_->imei());

  // Change the state to kModemStateDisabling and verify that it still has not
  // been enabled.
  capability_->OnModemStateChanged(Cellular::kModemStateDisabling);
  capability_->OnModemStateChanged(Cellular::kModemStateDisabled);
}

TEST_F(CellularCapability3gppTest, StopModem) {
  // Save pointers to proxies before they are lost by the call to InitProxies
  mm1::MockModemProxy* modem_proxy = modem_proxy_.get();
  EXPECT_CALL(*modem_proxy, set_state_changed_callback(_));
  InitProxies();

  auto return_success = [](ResultCallback callback) {
    std::move(callback).Run(Error(Error::kSuccess));
  };

  EXPECT_CALL(
      *modem_proxy,
      Enable(false, _, CellularCapability3gpp::kTimeoutEnable.InMilliseconds()))
      .WillOnce(WithArg<1>(Invoke(return_success)));

  EXPECT_CALL(
      *modem_proxy,
      SetPowerState(
          MM_MODEM_POWER_STATE_LOW, _,
          CellularCapability3gpp::kTimeoutSetPowerState.InMilliseconds()))
      .WillOnce(WithArg<1>(Invoke(return_success)));

  Error error;
  StopModem(&error);
  EXPECT_TRUE(error.IsSuccess());
}

TEST_F(CellularCapability3gppTest, StopModemSetPowerStateFailure) {
  // Save pointers to proxies before they are lost by the call to InitProxies
  mm1::MockModemProxy* modem_proxy = modem_proxy_.get();
  EXPECT_CALL(*modem_proxy, set_state_changed_callback(_));
  InitProxies();

  EXPECT_CALL(
      *modem_proxy,
      Enable(false, _, CellularCapability3gpp::kTimeoutEnable.InMilliseconds()))
      .WillOnce(WithArg<1>(Invoke([](ResultCallback callback) {
        std::move(callback).Run(Error(Error::kSuccess));
      })));

  // Even if this returns false, we should still succeed in stopping the
  // modem.
  EXPECT_CALL(
      *modem_proxy,
      SetPowerState(
          MM_MODEM_POWER_STATE_LOW, _,
          CellularCapability3gpp::kTimeoutSetPowerState.InMilliseconds()))
      .WillOnce(WithArg<1>(Invoke(ReturnOperationFailed<ResultCallback>)));

  Error error;
  StopModem(&error);
  EXPECT_TRUE(error.IsSuccess());
}

TEST_F(CellularCapability3gppTest, TerminationAction) {
  ExpectModemAndModem3gppProperties();

  {
    InSequence seq;

    EXPECT_CALL(*modem_proxy_,
                Enable(true, _,
                       CellularCapability3gpp::kTimeoutEnable.InMilliseconds()))
        .WillOnce(Invoke(this, &CellularCapability3gppTest::InvokeEnable));
    EXPECT_CALL(*modem_proxy_,
                Enable(false, _,
                       CellularCapability3gpp::kTimeoutEnable.InMilliseconds()))
        .WillOnce(Invoke(this, &CellularCapability3gppTest::InvokeEnable));
    EXPECT_CALL(
        *modem_proxy_,
        SetPowerState(
            MM_MODEM_POWER_STATE_LOW, _,
            CellularCapability3gpp::kTimeoutSetPowerState.InMilliseconds()))
        .WillOnce(
            Invoke(this, &CellularCapability3gppTest::InvokeSetPowerState));
  }
  EXPECT_CALL(*this, TestCallback(IsSuccess())).Times(2);

  EXPECT_EQ(Cellular::State::kDisabled, cellular_->state());
  EXPECT_EQ(Cellular::kModemStateUnknown, cellular_->modem_state());
  EXPECT_TRUE(manager_.termination_actions_.IsEmpty());
  EXPECT_CALL(*modem_3gpp_profile_manager_proxy_, List(_, _))
      .WillOnce(Invoke(this, &CellularCapability3gppTest::InvokeList));

  // Here we mimic the modem state change from ModemManager. When the modem is
  // enabled, a termination action should be added.
  cellular_->OnModemStateChanged(Cellular::kModemStateEnabled);
  dispatcher_.DispatchPendingEvents();
  EXPECT_EQ(Cellular::State::kModemStarted, cellular_->state());
  EXPECT_EQ(Cellular::kModemStateEnabled, cellular_->modem_state());
  EXPECT_FALSE(manager_.termination_actions_.IsEmpty());

  // Running the termination action should disable the modem.
  manager_.RunTerminationActions(base::BindOnce(
      &CellularCapability3gppTest::TestCallback, base::Unretained(this)));
  dispatcher_.DispatchPendingEvents();
  // Here we mimic the modem state change from ModemManager. When the modem is
  // disabled, the termination action should be removed.
  cellular_->OnModemStateChanged(Cellular::kModemStateDisabled);
  dispatcher_.DispatchPendingEvents();
  EXPECT_EQ(Cellular::State::kDisabled, cellular_->state());
  EXPECT_EQ(Cellular::kModemStateDisabled, cellular_->modem_state());
  EXPECT_TRUE(manager_.termination_actions_.IsEmpty());

  // No termination action should be called here.
  manager_.RunTerminationActions(base::BindOnce(
      &CellularCapability3gppTest::TestCallback, base::Unretained(this)));
  dispatcher_.DispatchPendingEvents();
}

TEST_F(CellularCapability3gppTest, TerminationActionRemovedByStopModem) {
  ExpectModemAndModem3gppProperties();

  {
    InSequence seq;

    EXPECT_CALL(*modem_proxy_,
                Enable(true, _,
                       CellularCapability3gpp::kTimeoutEnable.InMilliseconds()))
        .WillOnce(Invoke(this, &CellularCapability3gppTest::InvokeEnable));
    EXPECT_CALL(*modem_proxy_,
                Enable(false, _,
                       CellularCapability3gpp::kTimeoutEnable.InMilliseconds()))
        .WillOnce(Invoke(this, &CellularCapability3gppTest::InvokeEnable));
    EXPECT_CALL(
        *modem_proxy_,
        SetPowerState(
            MM_MODEM_POWER_STATE_LOW, _,
            CellularCapability3gpp::kTimeoutSetPowerState.InMilliseconds()))
        .WillOnce(
            Invoke(this, &CellularCapability3gppTest::InvokeSetPowerState));
  }
  EXPECT_CALL(*this, TestCallback(IsSuccess())).Times(1);

  EXPECT_EQ(Cellular::State::kDisabled, cellular_->state());
  EXPECT_EQ(Cellular::kModemStateUnknown, cellular_->modem_state());
  EXPECT_TRUE(manager_.termination_actions_.IsEmpty());
  EXPECT_CALL(*modem_3gpp_profile_manager_proxy_, List(_, _))
      .WillOnce(Invoke(this, &CellularCapability3gppTest::InvokeList));

  // Here we mimic the modem state change from ModemManager. When the modem is
  // enabled, a termination action should be added.
  cellular_->OnModemStateChanged(Cellular::kModemStateEnabled);
  dispatcher_.DispatchPendingEvents();
  EXPECT_EQ(Cellular::State::kModemStarted, cellular_->state());
  EXPECT_EQ(Cellular::kModemStateEnabled, cellular_->modem_state());
  EXPECT_FALSE(manager_.termination_actions_.IsEmpty());

  // Verify that the termination action is removed when the modem is disabled
  // not due to a suspend request.
  cellular_->SetEnabled(false);
  dispatcher_.DispatchPendingEvents();
  EXPECT_EQ(Cellular::State::kDisabled, cellular_->state());
  EXPECT_TRUE(manager_.termination_actions_.IsEmpty());

  // No termination action should be called here.
  manager_.RunTerminationActions(base::BindOnce(
      &CellularCapability3gppTest::TestCallback, base::Unretained(this)));
  dispatcher_.DispatchPendingEvents();
}

TEST_F(CellularCapability3gppTest, DisconnectNoProxy) {
  mm1::MockModemSimpleProxy* modem_simple_proxy = modem_simple_proxy_.get();
  SetSimpleProxy();
  ResultCallback callback = base::BindOnce(
      &CellularCapability3gppTest::TestCallback, base::Unretained(this));
  EXPECT_CALL(*modem_simple_proxy, Disconnect(_, _, _)).Times(0);
  ReleaseCapabilityProxies();
  EXPECT_CALL(*this, TestCallback(IsFailure()));
  capability_->DisconnectAll(std::move(callback));
}

TEST_F(CellularCapability3gppTest, DisconnectAllBearers) {
  mm1::MockModemSimpleProxy* modem_simple_proxy = modem_simple_proxy_.get();
  SetSimpleProxy();

  auto return_success = [](ResultCallback callback) {
    std::move(callback).Run(Error(Error::kSuccess));
  };

  ResultCallback callback = base::BindOnce(
      &CellularCapability3gppTest::TestCallback, base::Unretained(this));
  EXPECT_CALL(
      *modem_simple_proxy,
      Disconnect(CellularCapability3gpp::kRootPath, _,
                 CellularCapability3gpp::kTimeoutDisconnect.InMilliseconds()))
      .WillOnce(WithArg<1>(Invoke(return_success)));

  EXPECT_CALL(*this, TestCallback(IsSuccess()));
  capability_->DisconnectAll(std::move(callback));
}

TEST_F(CellularCapability3gppTest, DisconnectSingleBearer) {
  mm1::MockModemSimpleProxy* modem_simple_proxy = modem_simple_proxy_.get();
  SetSimpleProxy();

  RpcIdentifier default_bearer_path =
      RpcIdentifier(base::StringPrintf("%s/0", kDefaultActiveBearerPathPrefix));
  RpcIdentifier dun_bearer_path =
      RpcIdentifier(base::StringPrintf("%s/1", kDunActiveBearerPathPrefix));
  capability_->OnBearersChanged({default_bearer_path, dun_bearer_path});
  capability_->UpdateActiveBearers();

  auto return_success = [](ResultCallback callback) {
    std::move(callback).Run(Error(Error::kSuccess));
  };

  ResultCallback callback = base::BindOnce(
      &CellularCapability3gppTest::TestCallback, base::Unretained(this));
  EXPECT_CALL(
      *modem_simple_proxy,
      Disconnect(dun_bearer_path, _,
                 CellularCapability3gpp::kTimeoutDisconnect.InMilliseconds()))
      .WillOnce(WithArg<1>(Invoke(return_success)));
  EXPECT_CALL(*modem_simple_proxy, Disconnect(default_bearer_path, _, _))
      .Times(0);
  EXPECT_CALL(*modem_simple_proxy,
              Disconnect(CellularCapability3gpp::kRootPath, _, _))
      .Times(0);
  EXPECT_CALL(*this, TestCallback(IsSuccess()));
  capability_->Disconnect(ApnList::ApnType::kDun, std::move(callback));
}

TEST_F(CellularCapability3gppTest, SimLockStatusChanged) {
  InitProxies();

  // Set up mock SIM properties
  const char kSimIdentifier[] = "9999888";
  const char kOperatorIdentifier[] = "310240";
  const char kOperatorName[] = "Custom SPN";
  KeyValueStore sim_properties;
  sim_properties.Set<std::string>(MM_SIM_PROPERTY_IMSI, kImsi);
  sim_properties.Set<std::string>(MM_SIM_PROPERTY_SIMIDENTIFIER,
                                  kSimIdentifier);
  sim_properties.Set<std::string>(MM_SIM_PROPERTY_OPERATORIDENTIFIER,
                                  kOperatorIdentifier);
  sim_properties.Set<std::string>(MM_SIM_PROPERTY_OPERATORNAME, kOperatorName);

  EXPECT_FALSE(cellular_->sim_present());
  EXPECT_EQ(nullptr, capability_->sim_proxy_);

  SetSimPropertiesAndPath(kSimPath1, sim_properties);

  EXPECT_TRUE(cellular_->sim_present());
  EXPECT_NE(nullptr, capability_->sim_proxy_);
  EXPECT_EQ(kSimPath1, capability_->sim_path_for_testing());

  ClearCellularSimProperties();

  // SIM is locked.
  capability_->sim_lock_status_.lock_type = MM_MODEM_LOCK_SIM_PIN;
  capability_->OnSimLockStatusChanged();
  VerifyAndSetActivationExpectations();

  EXPECT_EQ("", cellular_->imsi());
  EXPECT_EQ("", cellular_->iccid());

  // SIM is unlocked.
  SetSimPropertiesAndPath(kSimPath1, sim_properties);

  capability_->sim_lock_status_.lock_type = MM_MODEM_LOCK_NONE;
  capability_->OnSimLockStatusChanged();
  VerifyAndSetActivationExpectations();

  EXPECT_EQ(kImsi, cellular_->imsi());
  EXPECT_EQ(kSimIdentifier, cellular_->iccid());

  // SIM is missing and SIM path is "/".
  ClearCapabilitySimProperties();
  SetSimPath(CellularCapability3gpp::kRootPath);
  EXPECT_FALSE(cellular_->sim_present());
  EXPECT_EQ(nullptr, capability_->sim_proxy_);
  EXPECT_EQ(CellularCapability3gpp::kRootPath,
            capability_->sim_path_for_testing());

  EXPECT_CALL(*modem_info_.mock_pending_activation_store(),
              GetActivationState(_, _))
      .Times(0);

  capability_->OnSimLockStatusChanged();
  VerifyAndSetActivationExpectations();

  EXPECT_EQ("", cellular_->imsi());
  EXPECT_EQ("", cellular_->iccid());

  // SIM is missing and SIM path is empty.
  ClearCapabilitySimProperties();
  EXPECT_FALSE(cellular_->sim_present());
  EXPECT_EQ(nullptr, capability_->sim_proxy_);
  EXPECT_EQ(RpcIdentifier(""), capability_->sim_path_for_testing());

  EXPECT_CALL(*modem_info_.mock_pending_activation_store(),
              GetActivationState(_, _))
      .Times(0);
  capability_->OnSimLockStatusChanged();
  VerifyAndSetActivationExpectations();

  EXPECT_EQ("", cellular_->imsi());
  EXPECT_EQ("", cellular_->iccid());
}

TEST_F(CellularCapability3gppTest, PropertiesChanged) {
  InitProxies();

  // Set up mock modem properties
  KeyValueStore modem_properties;
  modem_properties.Set<uint32_t>(MM_MODEM_PROPERTY_ACCESSTECHNOLOGIES,
                                 kAccessTechnologies);
  modem_properties.Set<RpcIdentifier>(MM_MODEM_PROPERTY_SIM, kSimPath1);

  // Set up mock modem 3gpp properties
  KeyValueStore modem3gpp_properties;
  modem3gpp_properties.Set<uint32_t>(
      MM_MODEM_MODEM3GPP_PROPERTY_ENABLEDFACILITYLOCKS, 0);
  modem3gpp_properties.Set<std::string>(MM_MODEM_MODEM3GPP_PROPERTY_IMEI,
                                        kImei);

  // Set up mock modem sim properties
  SetSimPropertiesAndPath(CellularCapability3gpp::kRootPath, {});

  EXPECT_EQ("", cellular_->imei());
  EXPECT_EQ(MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN,
            capability_->access_technologies_for_testing());
  EXPECT_EQ(nullptr, capability_->sim_proxy_);
  // Cellular::SetPrimarySimProperties will emit Cellular properties.
  EXPECT_CALL(*device_adaptor_, EmitStringChanged(_, _)).Times(AnyNumber());
  // Ensure that Family and Imei are set properly.
  EXPECT_CALL(*device_adaptor_, EmitStringChanged(kTechnologyFamilyProperty,
                                                  kTechnologyFamilyGsm))
      .Times(1);
  EXPECT_CALL(*device_adaptor_, EmitStringChanged(kImeiProperty, kImei))
      .Times(1);

  SetSimPropertiesAndPath(kSimPath1, {});
  capability_->OnPropertiesChanged(MM_DBUS_INTERFACE_MODEM, modem_properties);
  dispatcher_.DispatchPendingEvents();

  EXPECT_EQ(kAccessTechnologies,
            capability_->access_technologies_for_testing());
  EXPECT_EQ(kSimPath1, capability_->sim_path_for_testing());
  EXPECT_NE(nullptr, capability_->sim_proxy_);

  // Changing properties on wrong interface will not have an effect
  capability_->OnPropertiesChanged(MM_DBUS_INTERFACE_MODEM,
                                   modem3gpp_properties);
  EXPECT_EQ("", cellular_->imei());

  // Changing properties on the right interface gets reflected in the
  // capabilities object
  capability_->OnPropertiesChanged(MM_DBUS_INTERFACE_MODEM_MODEM3GPP,
                                   modem3gpp_properties);
  EXPECT_EQ(kImei, cellular_->imei());
  Mock::VerifyAndClearExpectations(device_adaptor_);

  // LTE & CDMA - the device adaptor should not be called!
  modem_properties.Clear();
  modem_properties.Set<uint32_t>(
      MM_MODEM_PROPERTY_ACCESSTECHNOLOGIES,
      MM_MODEM_ACCESS_TECHNOLOGY_LTE | MM_MODEM_ACCESS_TECHNOLOGY_1XRTT);
  EXPECT_CALL(*device_adaptor_, EmitStringChanged(_, _)).Times(0);
  capability_->OnPropertiesChanged(MM_DBUS_INTERFACE_MODEM, modem_properties);
}

TEST_F(CellularCapability3gppTest, SignalPropertiesChanged) {
  modem_signal_properties_.Clear();

  KeyValueStore modem_signal_property_gsm;
  modem_signal_property_gsm.Set<double>(
      CellularCapability3gpp::kRssiProperty,
      CellularCapability3gpp::kRssiBounds.max_threshold);
  modem_signal_properties_.Set<KeyValueStore>(MM_MODEM_SIGNAL_PROPERTY_GSM,
                                              modem_signal_property_gsm);
  EXPECT_CALL(*service_, SetStrength(100)).Times(1);
  capability_->OnPropertiesChanged(MM_DBUS_INTERFACE_MODEM_SIGNAL,
                                   modem_signal_properties_);

  KeyValueStore modem_signal_property_umts;
  modem_signal_property_umts.Set<double>(
      CellularCapability3gpp::kRscpProperty,
      CellularCapability3gpp::kRscpBounds.min_threshold);
  modem_signal_properties_.Set<KeyValueStore>(MM_MODEM_SIGNAL_PROPERTY_UMTS,
                                              modem_signal_property_umts);
  EXPECT_CALL(*service_, SetStrength(0)).Times(1);
  capability_->OnPropertiesChanged(MM_DBUS_INTERFACE_MODEM_SIGNAL,
                                   modem_signal_properties_);

  modem_signal_property_umts.Set<double>(
      CellularCapability3gpp::kRscpProperty,
      CellularCapability3gpp::kRscpBounds.max_threshold);
  modem_signal_properties_.Set<KeyValueStore>(MM_MODEM_SIGNAL_PROPERTY_UMTS,
                                              modem_signal_property_umts);
  EXPECT_CALL(*service_, SetStrength(100)).Times(1);
  capability_->OnPropertiesChanged(MM_DBUS_INTERFACE_MODEM_SIGNAL,
                                   modem_signal_properties_);

  double rscp_midrange = (CellularCapability3gpp::kRscpBounds.min_threshold +
                          CellularCapability3gpp::kRscpBounds.max_threshold) /
                         2;
  modem_signal_property_umts.Set<double>(CellularCapability3gpp::kRscpProperty,
                                         rscp_midrange);
  modem_signal_properties_.Set<KeyValueStore>(MM_MODEM_SIGNAL_PROPERTY_UMTS,
                                              modem_signal_property_umts);
  uint32_t expected_strength_rscp =
      CellularCapability3gpp::kRscpBounds.GetAsPercentage(rscp_midrange);
  EXPECT_CALL(*service_, SetStrength(expected_strength_rscp)).Times(1);
  capability_->OnPropertiesChanged(MM_DBUS_INTERFACE_MODEM_SIGNAL,
                                   modem_signal_properties_);

  KeyValueStore modem_signal_property_lte;
  modem_signal_property_lte.Set<double>(
      CellularCapability3gpp::kRsrpProperty,
      CellularCapability3gpp::kRsrpBounds.min_threshold);
  modem_signal_properties_.Set<KeyValueStore>(MM_MODEM_SIGNAL_PROPERTY_LTE,
                                              modem_signal_property_lte);
  EXPECT_CALL(*service_, SetStrength(0)).Times(1);
  capability_->OnPropertiesChanged(MM_DBUS_INTERFACE_MODEM_SIGNAL,
                                   modem_signal_properties_);

  modem_signal_property_lte.Set<double>(
      CellularCapability3gpp::kRsrpProperty,
      CellularCapability3gpp::kRsrpBounds.max_threshold);
  modem_signal_properties_.Set<KeyValueStore>(MM_MODEM_SIGNAL_PROPERTY_LTE,
                                              modem_signal_property_lte);
  EXPECT_CALL(*service_, SetStrength(100)).Times(1);
  capability_->OnPropertiesChanged(MM_DBUS_INTERFACE_MODEM_SIGNAL,
                                   modem_signal_properties_);

  double rsrp_midrange = (CellularCapability3gpp::kRsrpBounds.min_threshold +
                          CellularCapability3gpp::kRsrpBounds.max_threshold) /
                         2;
  modem_signal_property_lte.Set<double>(CellularCapability3gpp::kRsrpProperty,
                                        rsrp_midrange);
  modem_signal_properties_.Set<KeyValueStore>(MM_MODEM_SIGNAL_PROPERTY_LTE,
                                              modem_signal_property_lte);
  uint32_t expected_strength =
      CellularCapability3gpp::kRsrpBounds.GetAsPercentage(rsrp_midrange);
  EXPECT_CALL(*service_, SetStrength(expected_strength)).Times(1);
  capability_->OnPropertiesChanged(MM_DBUS_INTERFACE_MODEM_SIGNAL,
                                   modem_signal_properties_);

  KeyValueStore modem_signal_property_nr5g;
  modem_signal_property_nr5g.Set<double>(
      CellularCapability3gpp::kRsrpProperty,
      CellularCapability3gpp::kRsrpBounds.min_threshold);
  modem_signal_properties_.Set<KeyValueStore>(MM_MODEM_SIGNAL_PROPERTY_NR5G,
                                              modem_signal_property_nr5g);
  EXPECT_CALL(*service_, SetStrength(0)).Times(1);
  capability_->OnPropertiesChanged(MM_DBUS_INTERFACE_MODEM_SIGNAL,
                                   modem_signal_properties_);

  modem_signal_property_nr5g.Set<double>(
      CellularCapability3gpp::kRsrpProperty,
      CellularCapability3gpp::kRsrpBounds.max_threshold);
  modem_signal_properties_.Set<KeyValueStore>(MM_MODEM_SIGNAL_PROPERTY_NR5G,
                                              modem_signal_property_nr5g);
  EXPECT_CALL(*service_, SetStrength(100)).Times(1);
  capability_->OnPropertiesChanged(MM_DBUS_INTERFACE_MODEM_SIGNAL,
                                   modem_signal_properties_);

  double rsrp_midrange_nr5g =
      (CellularCapability3gpp::kRsrpBounds.min_threshold +
       CellularCapability3gpp::kRsrpBounds.max_threshold) /
      2;
  modem_signal_property_nr5g.Set<double>(CellularCapability3gpp::kRsrpProperty,
                                         rsrp_midrange_nr5g);
  modem_signal_properties_.Set<KeyValueStore>(MM_MODEM_SIGNAL_PROPERTY_NR5G,
                                              modem_signal_property_nr5g);
  uint32_t expected_strength_nr5g =
      CellularCapability3gpp::kRsrpBounds.GetAsPercentage(rsrp_midrange_nr5g);
  EXPECT_CALL(*service_, SetStrength(expected_strength_nr5g)).Times(1);
  capability_->OnPropertiesChanged(MM_DBUS_INTERFACE_MODEM_SIGNAL,
                                   modem_signal_properties_);
}

TEST_F(CellularCapability3gppTest, UpdateRegistrationState) {
  InitProxies();

  CreateService();
  SetDefaultCellularSimProperties();
  cellular_->set_modem_state_for_testing(Cellular::kModemStateConnected);
  SetRegistrationDroppedUpdateTimeout(base::Milliseconds(0));

  const Stringmap& home_provider_map = cellular_->home_provider();
  ASSERT_NE(home_provider_map.end(), home_provider_map.find(kOperatorNameKey));
  std::string home_provider = home_provider_map.find(kOperatorNameKey)->second;
  std::string ota_name = cellular_->service()->friendly_name();

  // Home --> Roaming should be effective immediately.
  capability_->On3gppRegistrationChanged(MM_MODEM_3GPP_REGISTRATION_STATE_HOME,
                                         home_provider, ota_name);
  EXPECT_EQ(MM_MODEM_3GPP_REGISTRATION_STATE_HOME,
            capability_->registration_state_);
  capability_->On3gppRegistrationChanged(
      MM_MODEM_3GPP_REGISTRATION_STATE_ROAMING, home_provider, ota_name);
  EXPECT_EQ(MM_MODEM_3GPP_REGISTRATION_STATE_ROAMING,
            capability_->registration_state_);

  // Idle --> Roaming should be effective immediately.
  capability_->On3gppRegistrationChanged(MM_MODEM_3GPP_REGISTRATION_STATE_IDLE,
                                         home_provider, ota_name);
  dispatcher_.DispatchPendingEvents();
  EXPECT_EQ(MM_MODEM_3GPP_REGISTRATION_STATE_IDLE,
            capability_->registration_state_);
  capability_->On3gppRegistrationChanged(
      MM_MODEM_3GPP_REGISTRATION_STATE_ROAMING, home_provider, ota_name);
  EXPECT_EQ(MM_MODEM_3GPP_REGISTRATION_STATE_ROAMING,
            capability_->registration_state_);

  // Idle --> Searching should be effective immediately.
  capability_->On3gppRegistrationChanged(MM_MODEM_3GPP_REGISTRATION_STATE_IDLE,
                                         home_provider, ota_name);
  dispatcher_.DispatchPendingEvents();
  EXPECT_EQ(MM_MODEM_3GPP_REGISTRATION_STATE_IDLE,
            capability_->registration_state_);
  capability_->On3gppRegistrationChanged(
      MM_MODEM_3GPP_REGISTRATION_STATE_SEARCHING, home_provider, ota_name);
  EXPECT_EQ(MM_MODEM_3GPP_REGISTRATION_STATE_SEARCHING,
            capability_->registration_state_);

  // Home --> Searching --> Home should never see Searching.
  EXPECT_CALL(
      metrics_,
      SendEnumToUMA(Metrics::kMetricCellular3GPPRegistrationDelayedDrop,
                    Metrics::kCellular3GPPRegistrationDelayedDropPosted));
  EXPECT_CALL(
      metrics_,
      SendEnumToUMA(Metrics::kMetricCellular3GPPRegistrationDelayedDrop,
                    Metrics::kCellular3GPPRegistrationDelayedDropCanceled));

  capability_->On3gppRegistrationChanged(MM_MODEM_3GPP_REGISTRATION_STATE_HOME,
                                         home_provider, ota_name);
  EXPECT_EQ(MM_MODEM_3GPP_REGISTRATION_STATE_HOME,
            capability_->registration_state_);
  capability_->On3gppRegistrationChanged(
      MM_MODEM_3GPP_REGISTRATION_STATE_SEARCHING, home_provider, ota_name);
  EXPECT_EQ(MM_MODEM_3GPP_REGISTRATION_STATE_HOME,
            capability_->registration_state_);
  capability_->On3gppRegistrationChanged(MM_MODEM_3GPP_REGISTRATION_STATE_HOME,
                                         home_provider, ota_name);
  EXPECT_EQ(MM_MODEM_3GPP_REGISTRATION_STATE_HOME,
            capability_->registration_state_);
  dispatcher_.DispatchPendingEvents();
  EXPECT_EQ(MM_MODEM_3GPP_REGISTRATION_STATE_HOME,
            capability_->registration_state_);
  Mock::VerifyAndClearExpectations(&metrics_);

  // Home --> Searching --> wait till dispatch should see Searching
  EXPECT_CALL(
      metrics_,
      SendEnumToUMA(Metrics::kMetricCellular3GPPRegistrationDelayedDrop,
                    Metrics::kCellular3GPPRegistrationDelayedDropPosted));
  capability_->On3gppRegistrationChanged(MM_MODEM_3GPP_REGISTRATION_STATE_HOME,
                                         home_provider, ota_name);
  EXPECT_EQ(MM_MODEM_3GPP_REGISTRATION_STATE_HOME,
            capability_->registration_state_);
  capability_->On3gppRegistrationChanged(
      MM_MODEM_3GPP_REGISTRATION_STATE_SEARCHING, home_provider, ota_name);
  EXPECT_EQ(MM_MODEM_3GPP_REGISTRATION_STATE_HOME,
            capability_->registration_state_);
  dispatcher_.DispatchPendingEvents();
  EXPECT_EQ(MM_MODEM_3GPP_REGISTRATION_STATE_SEARCHING,
            capability_->registration_state_);
  Mock::VerifyAndClearExpectations(&metrics_);

  // Home --> Searching --> Searching --> wait till dispatch should see
  // Searching *and* the first callback should be cancelled.
  EXPECT_CALL(*this, FakeCallback()).Times(0);
  EXPECT_CALL(
      metrics_,
      SendEnumToUMA(Metrics::kMetricCellular3GPPRegistrationDelayedDrop,
                    Metrics::kCellular3GPPRegistrationDelayedDropPosted));

  capability_->On3gppRegistrationChanged(MM_MODEM_3GPP_REGISTRATION_STATE_HOME,
                                         home_provider, ota_name);
  EXPECT_EQ(MM_MODEM_3GPP_REGISTRATION_STATE_HOME,
            capability_->registration_state_);
  capability_->On3gppRegistrationChanged(
      MM_MODEM_3GPP_REGISTRATION_STATE_SEARCHING, home_provider, ota_name);
  SetMockRegistrationDroppedUpdateCallback();
  capability_->On3gppRegistrationChanged(
      MM_MODEM_3GPP_REGISTRATION_STATE_SEARCHING, home_provider, ota_name);
  EXPECT_EQ(MM_MODEM_3GPP_REGISTRATION_STATE_HOME,
            capability_->registration_state_);
  dispatcher_.DispatchPendingEvents();
  EXPECT_EQ(MM_MODEM_3GPP_REGISTRATION_STATE_SEARCHING,
            capability_->registration_state_);
}

TEST_F(CellularCapability3gppTest, IsRegistered) {
  capability_->registration_state_ = MM_MODEM_3GPP_REGISTRATION_STATE_IDLE;
  EXPECT_FALSE(capability_->IsRegistered());

  capability_->registration_state_ = MM_MODEM_3GPP_REGISTRATION_STATE_HOME;
  EXPECT_TRUE(capability_->IsRegistered());

  capability_->registration_state_ = MM_MODEM_3GPP_REGISTRATION_STATE_SEARCHING;
  EXPECT_FALSE(capability_->IsRegistered());

  capability_->registration_state_ = MM_MODEM_3GPP_REGISTRATION_STATE_DENIED;
  EXPECT_FALSE(capability_->IsRegistered());

  capability_->registration_state_ = MM_MODEM_3GPP_REGISTRATION_STATE_UNKNOWN;
  EXPECT_FALSE(capability_->IsRegistered());

  capability_->registration_state_ = MM_MODEM_3GPP_REGISTRATION_STATE_ROAMING;
  EXPECT_TRUE(capability_->IsRegistered());
}

TEST_F(CellularCapability3gppTest, UpdateRegistrationStateModemNotConnected) {
  InitProxies();
  CreateService();

  SetDefaultCellularSimProperties();
  cellular_->set_modem_state_for_testing(Cellular::kModemStateRegistered);
  SetRegistrationDroppedUpdateTimeout(base::Milliseconds(0));

  const Stringmap& home_provider_map = cellular_->home_provider();
  ASSERT_NE(home_provider_map.end(), home_provider_map.find(kOperatorNameKey));
  std::string home_provider = home_provider_map.find(kOperatorNameKey)->second;
  std::string ota_name = cellular_->service()->friendly_name();

  // Home --> Searching should be effective immediately.
  capability_->On3gppRegistrationChanged(MM_MODEM_3GPP_REGISTRATION_STATE_HOME,
                                         home_provider, ota_name);
  EXPECT_EQ(MM_MODEM_3GPP_REGISTRATION_STATE_HOME,
            capability_->registration_state_);
  capability_->On3gppRegistrationChanged(
      MM_MODEM_3GPP_REGISTRATION_STATE_SEARCHING, home_provider, ota_name);
  EXPECT_EQ(MM_MODEM_3GPP_REGISTRATION_STATE_SEARCHING,
            capability_->registration_state_);
}

TEST_F(CellularCapability3gppTest, IsValidSimPath) {
  // Invalid paths
  EXPECT_FALSE(capability_->IsValidSimPath(RpcIdentifier("")));
  EXPECT_FALSE(capability_->IsValidSimPath(RpcIdentifier("/")));

  // A valid path
  EXPECT_TRUE(capability_->IsValidSimPath(
      RpcIdentifier("/org/freedesktop/ModemManager1/SIM/0")));

  // Note that any string that is not one of the above invalid paths is
  // currently regarded as valid, since the ModemManager spec doesn't impose
  // a strict format on the path. The validity of this is subject to change.
  EXPECT_TRUE(capability_->IsValidSimPath(RpcIdentifier("path")));
}

TEST_F(CellularCapability3gppTest, NormalizeMdn) {
  EXPECT_EQ("", capability_->NormalizeMdn(""));
  EXPECT_EQ("12345678901", capability_->NormalizeMdn("12345678901"));
  EXPECT_EQ("+12345678901", capability_->NormalizeMdn("+1 234 567 8901"));
  EXPECT_EQ("+12345678901", capability_->NormalizeMdn("+1-234-567-8901"));
  EXPECT_EQ("+12345678901", capability_->NormalizeMdn("+1 (234) 567-8901"));
  EXPECT_EQ("12345678901", capability_->NormalizeMdn("1 234  567 8901 "));
  EXPECT_EQ("2345678901", capability_->NormalizeMdn("(234) 567-8901"));
}

TEST_F(CellularCapability3gppTest, SimPathChanged) {
  InitProxies();

  // Set up mock modem SIM properties
  const char kSimIdentifier[] = "9999888";
  const char kOperatorIdentifier[] = "310240";
  const char kOperatorName[] = "Custom SPN";
  KeyValueStore sim_properties;
  sim_properties.Set<std::string>(MM_SIM_PROPERTY_IMSI, kImsi);
  sim_properties.Set<std::string>(MM_SIM_PROPERTY_SIMIDENTIFIER,
                                  kSimIdentifier);
  sim_properties.Set<std::string>(MM_SIM_PROPERTY_OPERATORIDENTIFIER,
                                  kOperatorIdentifier);
  sim_properties.Set<std::string>(MM_SIM_PROPERTY_OPERATORNAME, kOperatorName);

  EXPECT_FALSE(cellular_->sim_present());
  EXPECT_EQ(nullptr, capability_->sim_proxy_);
  EXPECT_EQ(RpcIdentifier(""), capability_->sim_path_for_testing());
  EXPECT_EQ("", cellular_->imsi());
  EXPECT_EQ("", cellular_->iccid());

  SetSimPropertiesAndPath(kSimPath1, sim_properties);
  EXPECT_TRUE(cellular_->sim_present());
  EXPECT_NE(nullptr, capability_->sim_proxy_);
  EXPECT_EQ(kSimPath1, capability_->sim_path_for_testing());
  EXPECT_EQ(kImsi, cellular_->imsi());
  EXPECT_EQ(kSimIdentifier, cellular_->iccid());

  // Changing to the same SIM path should be a no-op.
  SetSimPath(kSimPath1);
  EXPECT_TRUE(cellular_->sim_present());
  EXPECT_NE(nullptr, capability_->sim_proxy_);
  EXPECT_EQ(kSimPath1, capability_->sim_path_for_testing());
  EXPECT_EQ(kImsi, cellular_->imsi());
  EXPECT_EQ(kSimIdentifier, cellular_->iccid());

  // SIM is removed, Modem.Sim path is empty.
  ClearCapabilitySimProperties();
  VerifyAndSetActivationExpectations();
  EXPECT_FALSE(cellular_->sim_present());
  EXPECT_EQ(nullptr, capability_->sim_proxy_);
  EXPECT_EQ(RpcIdentifier(""), capability_->sim_path_for_testing());
  EXPECT_EQ("", cellular_->imsi());
  EXPECT_EQ("", cellular_->iccid());

  // SIM is replaced.
  SetSimPropertiesAndPath(kSimPath1, sim_properties);
  EXPECT_TRUE(cellular_->sim_present());
  EXPECT_NE(nullptr, capability_->sim_proxy_);
  EXPECT_EQ(kSimPath1, capability_->sim_path_for_testing());
  EXPECT_EQ(kImsi, cellular_->imsi());
  EXPECT_EQ(kSimIdentifier, cellular_->iccid());

  // SIM is removed, Modem.Sim path is "/".
  ClearCapabilitySimProperties();
  SetSimPath(CellularCapability3gpp::kRootPath);
  EXPECT_FALSE(cellular_->sim_present());
  EXPECT_EQ(nullptr, capability_->sim_proxy_);
  EXPECT_EQ(CellularCapability3gpp::kRootPath,
            capability_->sim_path_for_testing());
  EXPECT_EQ("", cellular_->imsi());
  EXPECT_EQ("", cellular_->iccid());
}

TEST_F(CellularCapability3gppTest, Reset) {
  // Save pointers to proxies before they are lost by the call to InitProxies
  mm1::MockModemProxy* modem_proxy = modem_proxy_.get();
  EXPECT_CALL(*modem_proxy, set_state_changed_callback(_));
  InitProxies();

  // Simulate ModemProxy returning the error asynchronously.
  // This allows us to peek at the value of |resetting_| while the operation
  // is in progress.
  EXPECT_CALL(*modem_proxy, Reset(_, _))
      .WillOnce(WithArg<0>(Invoke([this](ResultCallback callback) {
        dispatcher_.PostTask(FROM_HERE, base::BindOnce(std::move(callback),
                                                       Error(Error::kSuccess)));
      })));

  base::test::TestFuture<Error> error;
  capability_->Reset(GetResultCallback(&error));
  EXPECT_TRUE(capability_->resetting_);
  EXPECT_TRUE(error.Wait());
  EXPECT_FALSE(capability_->resetting_);
}

TEST_F(CellularCapability3gppTest, UpdateActiveBearers) {
  // Common resources.
  const size_t kPathCount = 3;
  RpcIdentifier default_active_paths[kPathCount];
  RpcIdentifier default_inactive_paths[kPathCount];
  for (size_t i = 0; i < kPathCount; ++i) {
    default_active_paths[i] = RpcIdentifier(
        base::StringPrintf("%s/%zu", kDefaultActiveBearerPathPrefix, i));
    default_inactive_paths[i] = RpcIdentifier(
        base::StringPrintf("%s/%zu", kDefaultInactiveBearerPathPrefix, i));
  }
  RpcIdentifier dun_active_path =
      RpcIdentifier(base::StringPrintf("%s/%u", kDunActiveBearerPathPrefix, 0));
  RpcIdentifier dun_inactive_path = RpcIdentifier(
      base::StringPrintf("%s/%u", kDunInactiveBearerPathPrefix, 0));

  EXPECT_EQ(nullptr, capability_->GetActiveBearer(ApnList::ApnType::kDefault));
  EXPECT_EQ(nullptr, capability_->GetActiveBearer(ApnList::ApnType::kDun));
  EXPECT_EQ(nullptr, capability_->default_bearer_dbus_properties_proxy_.get());

  // Check that |active_bearers_| is set correctly when an active bearer is
  // returned.
  capability_->OnBearersChanged(
      {default_inactive_paths[0], default_inactive_paths[1],
       default_active_paths[2], default_inactive_paths[1],
       default_inactive_paths[2]});
  capability_->UpdateActiveBearers();
  ASSERT_NE(nullptr, capability_->GetActiveBearer(ApnList::ApnType::kDefault));
  EXPECT_EQ(
      default_active_paths[2],
      capability_->GetActiveBearer(ApnList::ApnType::kDefault)->dbus_path());
  EXPECT_EQ(nullptr, capability_->GetActiveBearer(ApnList::ApnType::kDun));
  EXPECT_NE(nullptr, capability_->default_bearer_dbus_properties_proxy_.get());

  // Check that |active_bearers_| doesn't contain a valid entry, no active
  // bearers are returned.
  capability_->OnBearersChanged(
      {default_inactive_paths[0], default_inactive_paths[1],
       default_inactive_paths[2], default_inactive_paths[1]});
  capability_->UpdateActiveBearers();
  EXPECT_EQ(nullptr, capability_->GetActiveBearer(ApnList::ApnType::kDefault));
  EXPECT_EQ(nullptr, capability_->GetActiveBearer(ApnList::ApnType::kDun));
  EXPECT_EQ(nullptr, capability_->default_bearer_dbus_properties_proxy_.get());

  // Check that returning multiple bearers of the same type doesn't crash, only
  // the first one is returned.
  capability_->OnBearersChanged(
      {default_active_paths[0], default_inactive_paths[1],
       default_inactive_paths[2], default_active_paths[1]});
  capability_->UpdateActiveBearers();
  ASSERT_NE(nullptr, capability_->GetActiveBearer(ApnList::ApnType::kDefault));
  EXPECT_EQ(
      default_active_paths[0],
      capability_->GetActiveBearer(ApnList::ApnType::kDefault)->dbus_path());
  EXPECT_EQ(nullptr, capability_->GetActiveBearer(ApnList::ApnType::kDun));
  EXPECT_NE(nullptr, capability_->default_bearer_dbus_properties_proxy_.get());

  // Check that returning multiple bearers of different types works.
  capability_->OnBearersChanged(
      {default_active_paths[0], default_inactive_paths[1],
       default_inactive_paths[2], dun_inactive_path, dun_active_path});
  capability_->UpdateActiveBearers();
  ASSERT_NE(nullptr, capability_->GetActiveBearer(ApnList::ApnType::kDefault));
  EXPECT_EQ(
      default_active_paths[0],
      capability_->GetActiveBearer(ApnList::ApnType::kDefault)->dbus_path());
  ASSERT_NE(nullptr, capability_->GetActiveBearer(ApnList::ApnType::kDun));
  EXPECT_EQ(dun_active_path,
            capability_->GetActiveBearer(ApnList::ApnType::kDun)->dbus_path());
  EXPECT_NE(nullptr, capability_->default_bearer_dbus_properties_proxy_.get());

  // Check that returning a dun bearer without default bearer works, and that
  // no DBus properties watcher is set in this case.
  capability_->OnBearersChanged(
      {default_inactive_paths[0], default_inactive_paths[1],
       default_inactive_paths[2], dun_inactive_path, dun_active_path});
  capability_->UpdateActiveBearers();
  ASSERT_EQ(nullptr, capability_->GetActiveBearer(ApnList::ApnType::kDefault));
  ASSERT_NE(nullptr, capability_->GetActiveBearer(ApnList::ApnType::kDun));
  EXPECT_EQ(dun_active_path,
            capability_->GetActiveBearer(ApnList::ApnType::kDun)->dbus_path());
  EXPECT_EQ(nullptr, capability_->default_bearer_dbus_properties_proxy_.get());

  // Check that empty list of bearers doesn't return any active bearer
  capability_->OnBearersChanged({});
  capability_->UpdateActiveBearers();
  EXPECT_EQ(nullptr, capability_->GetActiveBearer(ApnList::ApnType::kDefault));
  EXPECT_EQ(nullptr, capability_->GetActiveBearer(ApnList::ApnType::kDun));
  EXPECT_EQ(nullptr, capability_->default_bearer_dbus_properties_proxy_.get());
}

TEST_F(CellularCapability3gppTest, SetInitialEpsBearer) {
  constexpr char kTestApn[] = "test_apn";
  KeyValueStore properties;
  Error error;
  ResultCallback callback = base::BindOnce(
      &CellularCapability3gppTest::TestCallback, base::Unretained(this));

  ResultCallback set_callback;
  EXPECT_CALL(*modem_3gpp_proxy_, SetInitialEpsBearerSettings(_, _))
      .Times(1)
      .WillOnce(
          WithArg<1>([&](ResultCallback cb) { set_callback = std::move(cb); }));
  EXPECT_CALL(*this, TestCallback(IsSuccess()));
  properties.Set<std::string>(CellularBearer::kMMApnProperty, kTestApn);

  InitProxies();
  capability_->SetInitialEpsBearer(properties, std::move(callback));
  std::move(set_callback).Run(Error(Error::kSuccess));
}

// Validates FillConnectPropertyMap
TEST_F(CellularCapability3gppTest, FillConnectPropertyMap) {
  constexpr char kTestApn[] = "test_apn";
  constexpr char kTestUser[] = "test_user";
  constexpr char kTestPassword[] = "test_password";
  KeyValueStore properties;
  Stringmap apn;
  apn[kApnProperty] = kTestApn;

  // Empty APN try list.
  EXPECT_FALSE(ConnectionAttemptInitialize(ApnList::ApnType::kDefault, {},
                                           ResultCallback()));

  // Connection of same type already initialized.
  EXPECT_TRUE(ConnectionAttemptInitialize(ApnList::ApnType::kDefault, {apn},
                                          ResultCallback()));
  EXPECT_FALSE(ConnectionAttemptInitialize(ApnList::ApnType::kDefault, {apn},
                                           ResultCallback()));
  ConnectionAttemptComplete(ApnList::ApnType::kDefault, Error(Error::kSuccess));

  // Connection with APN only.
  EXPECT_TRUE(ConnectionAttemptInitialize(ApnList::ApnType::kDefault, {apn},
                                          ResultCallback()));
  properties = ConnectionAttemptNextProperties(ApnList::ApnType::kDefault);
  EXPECT_THAT(properties, HasApn(kTestApn));
  EXPECT_THAT(properties, HasNoUser());
  EXPECT_THAT(properties, HasNoPassword());
  EXPECT_THAT(properties, HasNoAllowedAuth());
  EXPECT_THAT(properties, HasNoIpType());
  ConnectionAttemptComplete(ApnList::ApnType::kDefault, Error(Error::kSuccess));

  // Connection with APN and username.
  apn[kApnUsernameProperty] = kTestUser;
  EXPECT_TRUE(ConnectionAttemptInitialize(ApnList::ApnType::kDefault, {apn},
                                          ResultCallback()));
  properties = ConnectionAttemptNextProperties(ApnList::ApnType::kDefault);
  EXPECT_THAT(properties, HasApn(kTestApn));
  EXPECT_THAT(properties, HasUser(kTestUser));
  EXPECT_THAT(properties, HasNoPassword());
  EXPECT_THAT(properties, HasNoAllowedAuth());
  EXPECT_THAT(properties, HasNoIpType());
  ConnectionAttemptComplete(ApnList::ApnType::kDefault, Error(Error::kSuccess));

  // Connection with APN, username and password.
  apn[kApnPasswordProperty] = kTestPassword;
  EXPECT_TRUE(ConnectionAttemptInitialize(ApnList::ApnType::kDefault, {apn},
                                          ResultCallback()));
  properties = ConnectionAttemptNextProperties(ApnList::ApnType::kDefault);
  EXPECT_THAT(properties, HasApn(kTestApn));
  EXPECT_THAT(properties, HasUser(kTestUser));
  EXPECT_THAT(properties, HasPassword(kTestPassword));
  EXPECT_THAT(properties, HasNoAllowedAuth());
  EXPECT_THAT(properties, HasNoIpType());
  ConnectionAttemptComplete(ApnList::ApnType::kDefault, Error(Error::kSuccess));

  // Connection with APN, username, password and PAP auth type.
  apn[kApnAuthenticationProperty] = kApnAuthenticationPap;
  EXPECT_TRUE(ConnectionAttemptInitialize(ApnList::ApnType::kDefault, {apn},
                                          ResultCallback()));
  properties = ConnectionAttemptNextProperties(ApnList::ApnType::kDefault);
  EXPECT_THAT(properties, HasApn(kTestApn));
  EXPECT_THAT(properties, HasUser(kTestUser));
  EXPECT_THAT(properties, HasPassword(kTestPassword));
  EXPECT_THAT(properties, HasAllowedAuth(MM_BEARER_ALLOWED_AUTH_PAP));
  EXPECT_THAT(properties, HasNoIpType());
  ConnectionAttemptComplete(ApnList::ApnType::kDefault, Error(Error::kSuccess));

  // Connection with APN, username, password and CHAP auth type.
  apn[kApnAuthenticationProperty] = kApnAuthenticationChap;
  EXPECT_TRUE(ConnectionAttemptInitialize(ApnList::ApnType::kDefault, {apn},
                                          ResultCallback()));
  properties = ConnectionAttemptNextProperties(ApnList::ApnType::kDefault);
  EXPECT_THAT(properties, HasApn(kTestApn));
  EXPECT_THAT(properties, HasUser(kTestUser));
  EXPECT_THAT(properties, HasPassword(kTestPassword));
  EXPECT_THAT(properties, HasAllowedAuth(MM_BEARER_ALLOWED_AUTH_CHAP));
  EXPECT_THAT(properties, HasNoIpType());
  ConnectionAttemptComplete(ApnList::ApnType::kDefault, Error(Error::kSuccess));

  // Connection with APN, username, password and unknown auth type.
  apn[kApnAuthenticationProperty] = "something";
  EXPECT_TRUE(ConnectionAttemptInitialize(ApnList::ApnType::kDefault, {apn},
                                          ResultCallback()));
  properties = ConnectionAttemptNextProperties(ApnList::ApnType::kDefault);
  EXPECT_THAT(properties, HasApn(kTestApn));
  EXPECT_THAT(properties, HasUser(kTestUser));
  EXPECT_THAT(properties, HasPassword(kTestPassword));
  EXPECT_THAT(properties, HasNoAllowedAuth());
  EXPECT_THAT(properties, HasNoIpType());
  ConnectionAttemptComplete(ApnList::ApnType::kDefault, Error(Error::kSuccess));

  // Connection with APN, username, password and empty auth type.
  apn[kApnAuthenticationProperty] = "";
  EXPECT_TRUE(ConnectionAttemptInitialize(ApnList::ApnType::kDefault, {apn},
                                          ResultCallback()));
  properties = ConnectionAttemptNextProperties(ApnList::ApnType::kDefault);
  EXPECT_THAT(properties, HasApn(kTestApn));
  EXPECT_THAT(properties, HasUser(kTestUser));
  EXPECT_THAT(properties, HasPassword(kTestPassword));
  EXPECT_THAT(properties, HasNoAllowedAuth());
  EXPECT_THAT(properties, HasNoIpType());
  ConnectionAttemptComplete(ApnList::ApnType::kDefault, Error(Error::kSuccess));

  // Connection with APN, username, password, empty auth type and IPv4.
  apn[kApnIpTypeProperty] = kApnIpTypeV4;
  EXPECT_TRUE(ConnectionAttemptInitialize(ApnList::ApnType::kDefault, {apn},
                                          ResultCallback()));
  properties = ConnectionAttemptNextProperties(ApnList::ApnType::kDefault);
  EXPECT_THAT(properties, HasApn(kTestApn));
  EXPECT_THAT(properties, HasUser(kTestUser));
  EXPECT_THAT(properties, HasPassword(kTestPassword));
  EXPECT_THAT(properties, HasNoAllowedAuth());
  EXPECT_THAT(properties, HasIpType(MM_BEARER_IP_FAMILY_IPV4));
  ConnectionAttemptComplete(ApnList::ApnType::kDefault, Error(Error::kSuccess));

  // Connection with APN, username, password, empty auth type and IPv6.
  apn[kApnIpTypeProperty] = kApnIpTypeV6;
  EXPECT_TRUE(ConnectionAttemptInitialize(ApnList::ApnType::kDefault, {apn},
                                          ResultCallback()));
  properties = ConnectionAttemptNextProperties(ApnList::ApnType::kDefault);
  EXPECT_THAT(properties, HasApn(kTestApn));
  EXPECT_THAT(properties, HasUser(kTestUser));
  EXPECT_THAT(properties, HasPassword(kTestPassword));
  EXPECT_THAT(properties, HasNoAllowedAuth());
  EXPECT_THAT(properties, HasIpType(MM_BEARER_IP_FAMILY_IPV6));
  ConnectionAttemptComplete(ApnList::ApnType::kDefault, Error(Error::kSuccess));

  // Connection with APN, username, password, empty auth type and IPv4v6.
  apn[kApnIpTypeProperty] = kApnIpTypeV4V6;
  EXPECT_TRUE(ConnectionAttemptInitialize(ApnList::ApnType::kDefault, {apn},
                                          ResultCallback()));
  properties = ConnectionAttemptNextProperties(ApnList::ApnType::kDefault);
  EXPECT_THAT(properties, HasApn(kTestApn));
  EXPECT_THAT(properties, HasUser(kTestUser));
  EXPECT_THAT(properties, HasPassword(kTestPassword));
  EXPECT_THAT(properties, HasNoAllowedAuth());
  EXPECT_THAT(properties, HasIpType(MM_BEARER_IP_FAMILY_IPV4V6));
  ConnectionAttemptComplete(ApnList::ApnType::kDefault, Error(Error::kSuccess));

  // IP type defaults to v4 if something unsupported is specified.
  apn[kApnIpTypeProperty] = "orekid";
  EXPECT_TRUE(ConnectionAttemptInitialize(ApnList::ApnType::kDefault, {apn},
                                          ResultCallback()));
  properties = ConnectionAttemptNextProperties(ApnList::ApnType::kDefault);
  EXPECT_THAT(properties, HasApn(kTestApn));
  EXPECT_THAT(properties, HasUser(kTestUser));
  EXPECT_THAT(properties, HasPassword(kTestPassword));
  EXPECT_THAT(properties, HasNoAllowedAuth());
  EXPECT_THAT(properties, HasIpType(MM_BEARER_IP_FAMILY_IPV4));
  ConnectionAttemptComplete(ApnList::ApnType::kDefault, Error(Error::kSuccess));
}

// Validates expected behavior of Connect function
TEST_F(CellularCapability3gppTest, Connect) {
  mm1::MockModemSimpleProxy* modem_simple_proxy = modem_simple_proxy_.get();
  SetSimpleProxy();
  RpcIdentifier bearer("/foo");

  const char apn_name_foo[] = "foo";
  Stringmap apn;
  apn[kApnProperty] = apn_name_foo;

  // Test connect failure
  ResultCallback callback = base::BindOnce(
      &CellularCapability3gppTest::TestCallback, base::Unretained(this));
  EXPECT_TRUE(ConnectionAttemptInitialize(ApnList::ApnType::kDefault, {apn},
                                          std::move(callback)));
  EXPECT_CALL(*modem_simple_proxy, Connect(_, _, _));
  ConnectionAttemptConnect(ApnList::ApnType::kDefault);
  EXPECT_CALL(*this, TestCallback(IsFailure()));
  EXPECT_CALL(*service_, ClearLastGoodApn());
  ConnectionAttemptOnConnectReply(ApnList::ApnType::kDefault, bearer,
                                  Error(Error::kOperationFailed));
  Mock::VerifyAndClearExpectations(this);

  // Test connect success
  callback = base::BindOnce(&CellularCapability3gppTest::TestCallback,
                            base::Unretained(this));
  EXPECT_TRUE(ConnectionAttemptInitialize(ApnList::ApnType::kDefault, {apn},
                                          std::move(callback)));
  EXPECT_CALL(*modem_simple_proxy, Connect(_, _, _));
  ConnectionAttemptConnect(ApnList::ApnType::kDefault);
  EXPECT_CALL(*this, TestCallback(IsSuccess()));
  ConnectionAttemptOnConnectReply(ApnList::ApnType::kDefault, bearer,
                                  Error(Error::kSuccess));
  Mock::VerifyAndClearExpectations(this);

  // Test connect failures without a service.  Make sure that shill
  // does not crash if the connect failed and there is no
  // CellularService object.  This can happen if the modem is enabled
  // and then quickly disabled.
  callback = base::BindOnce(&CellularCapability3gppTest::TestCallback,
                            base::Unretained(this));
  EXPECT_TRUE(ConnectionAttemptInitialize(ApnList::ApnType::kDefault, {apn},
                                          std::move(callback)));
  cellular_->SetServiceForTesting(nullptr);
  EXPECT_FALSE(capability_->cellular()->service());
  EXPECT_CALL(*modem_simple_proxy, Connect(_, _, _));
  ConnectionAttemptConnect(ApnList::ApnType::kDefault);
  EXPECT_CALL(*this, TestCallback(IsFailure()));
  ConnectionAttemptOnConnectReply(ApnList::ApnType::kDefault, bearer,
                                  Error(Error::kOperationFailed));
}

TEST_F(CellularCapability3gppTest, ConnectAbort) {
  mm1::MockModemSimpleProxy* modem_simple_proxy = modem_simple_proxy_.get();
  SetSimpleProxy();
  ResultCallback callback = base::BindOnce(
      &CellularCapability3gppTest::TestCallback, base::Unretained(this));
  RpcIdentifier bearer("/foo");

  const char apn_name_foo[] = "foo";
  Stringmap apn;
  apn[kApnProperty] = apn_name_foo;

  EXPECT_TRUE(ConnectionAttemptInitialize(ApnList::ApnType::kDefault, {apn},
                                          std::move(callback)));
  EXPECT_CALL(*modem_simple_proxy, Connect(_, _, _));
  ConnectionAttemptConnect(ApnList::ApnType::kDefault);
  EXPECT_CALL(*this, TestCallback(IsFailure()));
  ReleaseCapabilityProxies();
}

// Validates Connect iterates over APNs
TEST_F(CellularCapability3gppTest, ConnectApns) {
  mm1::MockModemSimpleProxy* modem_simple_proxy = modem_simple_proxy_.get();
  SetSimpleProxy();
  ResultCallback callback = base::BindOnce(
      &CellularCapability3gppTest::TestCallback, base::Unretained(this));
  RpcIdentifier bearer("/bearer0");

  const char apn_name_foo[] = "foo";
  const char apn_name_bar[] = "bar";
  const char apn_name_empty[] = "";
  Stringmap apn1;
  apn1[kApnProperty] = apn_name_foo;
  Stringmap apn2;
  apn2[kApnProperty] = apn_name_bar;
  Stringmap apn3;
  apn3[kApnProperty] = apn_name_empty;

  EXPECT_TRUE(ConnectionAttemptInitialize(
      ApnList::ApnType::kDefault, {apn1, apn2, apn3}, std::move(callback)));

  EXPECT_CALL(*modem_simple_proxy, Connect(HasApn(apn_name_foo), _, _));
  ConnectionAttemptConnect(ApnList::ApnType::kDefault);
  Mock::VerifyAndClearExpectations(modem_simple_proxy);

  EXPECT_CALL(*modem_simple_proxy, Connect(HasApn(apn_name_bar), _, _));
  EXPECT_CALL(*service_, ClearLastGoodApn());
  ConnectionAttemptOnConnectReply(ApnList::ApnType::kDefault, bearer,
                                  Error(Error::kInvalidApn));

  EXPECT_CALL(*modem_simple_proxy, Connect(HasApn(apn_name_empty), _, _));
  EXPECT_CALL(*service_, ClearLastGoodApn());
  ConnectionAttemptOnConnectReply(ApnList::ApnType::kDefault, bearer,
                                  Error(Error::kInvalidApn));

  EXPECT_CALL(*service_, SetLastGoodApn(apn3));
  EXPECT_CALL(*this, TestCallback(IsSuccess()));
  ConnectionAttemptOnConnectReply(ApnList::ApnType::kDefault, bearer,
                                  Error(Error::kSuccess));
}

// Validates GetTypeString and AccessTechnologyToTechnologyFamily
TEST_F(CellularCapability3gppTest, GetTypeString) {
  static const uint32_t kGsmTechnologies[] = {
      MM_MODEM_ACCESS_TECHNOLOGY_LTE,
      MM_MODEM_ACCESS_TECHNOLOGY_HSPA_PLUS,
      MM_MODEM_ACCESS_TECHNOLOGY_HSPA,
      MM_MODEM_ACCESS_TECHNOLOGY_HSUPA,
      MM_MODEM_ACCESS_TECHNOLOGY_HSDPA,
      MM_MODEM_ACCESS_TECHNOLOGY_UMTS,
      MM_MODEM_ACCESS_TECHNOLOGY_EDGE,
      MM_MODEM_ACCESS_TECHNOLOGY_GPRS,
      MM_MODEM_ACCESS_TECHNOLOGY_GSM_COMPACT,
      MM_MODEM_ACCESS_TECHNOLOGY_GSM,
      MM_MODEM_ACCESS_TECHNOLOGY_LTE | MM_MODEM_ACCESS_TECHNOLOGY_EVDO0,
      MM_MODEM_ACCESS_TECHNOLOGY_GSM | MM_MODEM_ACCESS_TECHNOLOGY_EVDO0,
      MM_MODEM_ACCESS_TECHNOLOGY_LTE | MM_MODEM_ACCESS_TECHNOLOGY_EVDOA,
      MM_MODEM_ACCESS_TECHNOLOGY_GSM | MM_MODEM_ACCESS_TECHNOLOGY_EVDOA,
      MM_MODEM_ACCESS_TECHNOLOGY_LTE | MM_MODEM_ACCESS_TECHNOLOGY_EVDOB,
      MM_MODEM_ACCESS_TECHNOLOGY_GSM | MM_MODEM_ACCESS_TECHNOLOGY_EVDOB,
      MM_MODEM_ACCESS_TECHNOLOGY_GSM | MM_MODEM_ACCESS_TECHNOLOGY_1XRTT,
  };
  for (auto gsm_technology : kGsmTechnologies) {
    capability_->access_technologies_ = gsm_technology;
    ASSERT_EQ(capability_->GetTypeString(), kTechnologyFamilyGsm);
  }
  capability_->access_technologies_ = MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN;
  ASSERT_EQ(capability_->GetTypeString(), "");
}

TEST_F(CellularCapability3gppTest, GetMdnForOLP) {
  const std::string kVzwUUID = "c83d6597-dc91-4d48-a3a7-d86b80123751";
  const std::string kFooUUID = "foo";
  MockMobileOperatorInfo mock_operator_info(&dispatcher_, "MobileOperatorInfo");

  EXPECT_CALL(mock_operator_info, IsMobileNetworkOperatorKnown())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(mock_operator_info, uuid()).WillRepeatedly(ReturnRef(kVzwUUID));
  capability_->subscription_state_ = SubscriptionState::kUnknown;

  cellular_->SetMdn("");
  EXPECT_EQ("0000000000", capability_->GetMdnForOLP(&mock_operator_info));
  cellular_->SetMdn("0123456789");
  EXPECT_EQ("0123456789", capability_->GetMdnForOLP(&mock_operator_info));
  cellular_->SetMdn("10123456789");
  EXPECT_EQ("0123456789", capability_->GetMdnForOLP(&mock_operator_info));

  cellular_->SetMdn("1021232333");
  capability_->subscription_state_ = SubscriptionState::kUnprovisioned;
  EXPECT_EQ("0000000000", capability_->GetMdnForOLP(&mock_operator_info));
  Mock::VerifyAndClearExpectations(&mock_operator_info);

  EXPECT_CALL(mock_operator_info, IsMobileNetworkOperatorKnown())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(mock_operator_info, uuid()).WillRepeatedly(ReturnRef(kFooUUID));

  cellular_->SetMdn("");
  EXPECT_EQ("", capability_->GetMdnForOLP(&mock_operator_info));
  cellular_->SetMdn("0123456789");
  EXPECT_EQ("0123456789", capability_->GetMdnForOLP(&mock_operator_info));
  cellular_->SetMdn("10123456789");
  EXPECT_EQ("10123456789", capability_->GetMdnForOLP(&mock_operator_info));
}

TEST_F(CellularCapability3gppTest, UpdateServiceOLP) {
  const MobileOperatorMapper::OnlinePortal kOlp{
      "http://testurl", "POST",
      "imei=${imei}&imsi=${imsi}&mdn=${mdn}&min=${min}&iccid=${iccid}"};
  const std::vector<MobileOperatorMapper::OnlinePortal> kOlpList{kOlp};
  const std::string kUuidVzw = "c83d6597-dc91-4d48-a3a7-d86b80123751";
  const std::string kUuidFoo = "foo";

  cellular_->SetImei("1");
  Cellular::SimProperties sim_properties;
  sim_properties.iccid = "6";
  sim_properties.imsi = "2";
  SetCellularSimProperties(sim_properties);
  cellular_->SetMdn("10123456789");
  cellular_->SetMin("5");

  EXPECT_CALL(*mock_mobile_operator_info_, IsMobileNetworkOperatorKnown())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*mock_mobile_operator_info_, olp_list())
      .WillRepeatedly(ReturnRef(kOlpList));
  EXPECT_CALL(*mock_mobile_operator_info_, uuid())
      .WillRepeatedly(ReturnRef(kUuidVzw));
  CreateService();
  capability_->UpdateServiceOLP();
  // Copy to simplify assertions below.
  Stringmap vzw_olp = cellular_->service()->olp();
  EXPECT_EQ("http://testurl", vzw_olp[kPaymentPortalURL]);
  EXPECT_EQ("POST", vzw_olp[kPaymentPortalMethod]);
  EXPECT_EQ("imei=1&imsi=2&mdn=0123456789&min=5&iccid=6",
            vzw_olp[kPaymentPortalPostData]);
  Mock::VerifyAndClearExpectations(mock_mobile_operator_info_);

  EXPECT_CALL(*mock_mobile_operator_info_, IsMobileNetworkOperatorKnown())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*mock_mobile_operator_info_, olp_list())
      .WillRepeatedly(ReturnRef(kOlpList));
  EXPECT_CALL(*mock_mobile_operator_info_, uuid())
      .WillRepeatedly(ReturnRef(kUuidFoo));
  capability_->UpdateServiceOLP();
  // Copy to simplify assertions below.
  Stringmap olp = cellular_->service()->olp();
  EXPECT_EQ("http://testurl", olp[kPaymentPortalURL]);
  EXPECT_EQ("POST", olp[kPaymentPortalMethod]);
  EXPECT_EQ("imei=1&imsi=2&mdn=10123456789&min=5&iccid=6",
            olp[kPaymentPortalPostData]);
}

TEST_F(CellularCapability3gppTest, IsMdnValid) {
  cellular_->SetMdn("");
  EXPECT_FALSE(capability_->IsMdnValid());
  cellular_->SetMdn("0000000");
  EXPECT_FALSE(capability_->IsMdnValid());
  cellular_->SetMdn("0000001");
  EXPECT_TRUE(capability_->IsMdnValid());
  cellular_->SetMdn("1231223");
  EXPECT_TRUE(capability_->IsMdnValid());
}

TEST_F(CellularCapability3gppTest, CompleteActivation) {
  SetDefaultCellularSimProperties();
  EXPECT_CALL(*modem_info_.mock_pending_activation_store(),
              SetActivationState(PendingActivationStore::kIdentifierICCID,
                                 kIccid, PendingActivationStore::kStatePending))
      .Times(1);
  EXPECT_CALL(
      *modem_info_.mock_pending_activation_store(),
      GetActivationState(PendingActivationStore::kIdentifierICCID, kIccid))
      .WillOnce(Return(PendingActivationStore::kStatePending));
  EXPECT_CALL(*service_, SetActivationState(kActivationStateActivating))
      .Times(1);
  EXPECT_CALL(*modem_proxy_, Reset(_, _)).Times(1);
  Error error;
  InitProxies();
  capability_->CompleteActivation(&error);
  VerifyAndSetActivationExpectations();
  Mock::VerifyAndClearExpectations(service_);
}

TEST_F(CellularCapability3gppTest, UpdateServiceActivationState) {
  const std::vector<MobileOperatorMapper::OnlinePortal> olp_list{
      {"some@url", "some_method", "some_post_data"}};

  EXPECT_CALL(*modem_info_.mock_pending_activation_store(),
              GetActivationState(PendingActivationStore::kIdentifierICCID, _))
      .WillRepeatedly(Return(PendingActivationStore::kStateUnknown));

  capability_->subscription_state_ = SubscriptionState::kUnprovisioned;
  ClearCellularSimProperties();
  cellular_->SetMdn("0000000000");
  EXPECT_CALL(*mock_mobile_operator_info_, IsMobileNetworkOperatorKnown())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*mock_mobile_operator_info_, olp_list())
      .WillRepeatedly(ReturnRef(olp_list));

  EXPECT_CALL(*service_, SetActivationState(kActivationStateNotActivated))
      .Times(1);
  capability_->UpdateServiceActivationState();
  Mock::VerifyAndClearExpectations(service_);

  cellular_->SetMdn("1231231122");
  capability_->subscription_state_ = SubscriptionState::kUnknown;
  EXPECT_CALL(*service_, SetActivationState(kActivationStateActivated))
      .Times(1);
  capability_->UpdateServiceActivationState();
  Mock::VerifyAndClearExpectations(service_);

  cellular_->SetMdn("0000000000");
  SetDefaultCellularSimProperties();
  EXPECT_CALL(
      *modem_info_.mock_pending_activation_store(),
      GetActivationState(PendingActivationStore::kIdentifierICCID, kIccid))
      .Times(1)
      .WillRepeatedly(Return(PendingActivationStore::kStatePending));
  EXPECT_CALL(*service_, SetActivationState(kActivationStateActivating))
      .Times(1);
  capability_->UpdateServiceActivationState();
  Mock::VerifyAndClearExpectations(service_);
  VerifyAndSetActivationExpectations();

  EXPECT_CALL(
      *modem_info_.mock_pending_activation_store(),
      GetActivationState(PendingActivationStore::kIdentifierICCID, kIccid))
      .Times(2)
      .WillRepeatedly(Return(PendingActivationStore::kStateActivated));
  EXPECT_CALL(*service_, SetActivationState(kActivationStateActivated))
      .Times(1);
  capability_->UpdateServiceActivationState();
  Mock::VerifyAndClearExpectations(service_);
  VerifyAndSetActivationExpectations();

  EXPECT_CALL(*modem_info_.mock_pending_activation_store(),
              GetActivationState(PendingActivationStore::kIdentifierICCID, _))
      .WillRepeatedly(Return(PendingActivationStore::kStateUnknown));

  // SubscriptionStateUnprovisioned overrides valid MDN.
  capability_->subscription_state_ = SubscriptionState::kUnprovisioned;
  cellular_->SetMdn("1231231122");
  ClearCellularSimProperties();
  EXPECT_CALL(*service_, SetActivationState(kActivationStateNotActivated))
      .Times(1);
  capability_->UpdateServiceActivationState();
  Mock::VerifyAndClearExpectations(service_);

  // SubscriptionStateProvisioned overrides invalid MDN.
  capability_->subscription_state_ = SubscriptionState::kProvisioned;
  cellular_->SetMdn("0000000000");
  ClearCellularSimProperties();
  EXPECT_CALL(*service_, SetActivationState(kActivationStateActivated))
      .Times(1);
  capability_->UpdateServiceActivationState();
  Mock::VerifyAndClearExpectations(service_);
}

TEST_F(CellularCapability3gppTest, UpdatePendingActivationState) {
  InitProxies();
  capability_->registration_state_ = MM_MODEM_3GPP_REGISTRATION_STATE_SEARCHING;

  // No MDN, no ICCID.
  cellular_->SetMdn("0000000");
  capability_->subscription_state_ = SubscriptionState::kUnknown;
  ClearCellularSimProperties();
  EXPECT_CALL(*modem_info_.mock_pending_activation_store(),
              GetActivationState(PendingActivationStore::kIdentifierICCID, _))
      .Times(0);
  capability_->UpdatePendingActivationState();
  VerifyAndSetActivationExpectations();

  // Valid MDN, but subsciption_state_ Unprovisioned
  cellular_->SetMdn("1234567");
  capability_->subscription_state_ = SubscriptionState::kUnprovisioned;
  ClearCellularSimProperties();
  EXPECT_CALL(*modem_info_.mock_pending_activation_store(),
              GetActivationState(PendingActivationStore::kIdentifierICCID, _))
      .Times(0);
  capability_->UpdatePendingActivationState();
  VerifyAndSetActivationExpectations();

  // ICCID known.
  SetDefaultCellularSimProperties();

  // After the modem has reset.
  capability_->reset_done_ = true;
  EXPECT_CALL(
      *modem_info_.mock_pending_activation_store(),
      GetActivationState(PendingActivationStore::kIdentifierICCID, kIccid))
      .Times(1)
      .WillOnce(Return(PendingActivationStore::kStatePending));
  EXPECT_CALL(
      *modem_info_.mock_pending_activation_store(),
      SetActivationState(PendingActivationStore::kIdentifierICCID, kIccid,
                         PendingActivationStore::kStateActivated))
      .Times(1);
  EXPECT_CALL(*service_, SetActivationState(kActivationStateActivating))
      .Times(1);
  EXPECT_CALL(*service_, activation_state())
      .Times(2)
      .WillRepeatedly(ReturnRef(kActivationStateUnknown));
  capability_->UpdatePendingActivationState();
  VerifyAndSetActivationExpectations();

  // Not registered.
  capability_->registration_state_ = MM_MODEM_3GPP_REGISTRATION_STATE_SEARCHING;
  EXPECT_CALL(
      *modem_info_.mock_pending_activation_store(),
      GetActivationState(PendingActivationStore::kIdentifierICCID, kIccid))
      .Times(2)
      .WillRepeatedly(Return(PendingActivationStore::kStateActivated));
  EXPECT_CALL(*service_, AutoConnect()).Times(0);
  capability_->UpdatePendingActivationState();
  Mock::VerifyAndClearExpectations(service_);

  // Service, registered.
  capability_->registration_state_ = MM_MODEM_3GPP_REGISTRATION_STATE_HOME;
  EXPECT_CALL(*service_, AutoConnect()).Times(1);
  EXPECT_CALL(*service_, activation_state())
      .WillOnce(ReturnRef(kActivationStateUnknown));
  capability_->UpdatePendingActivationState();

  service_->set_activation_state_for_testing(kActivationStateNotActivated);

  Mock::VerifyAndClearExpectations(service_);
  VerifyAndSetActivationExpectations();

  EXPECT_CALL(*service_, activation_state())
      .WillRepeatedly(ReturnRef(kActivationStateUnknown));
  EXPECT_CALL(
      *modem_info_.mock_pending_activation_store(),
      GetActivationState(PendingActivationStore::kIdentifierICCID, kIccid))
      .WillRepeatedly(Return(PendingActivationStore::kStateUnknown));

  // Device is connected.
  cellular_->set_state_for_testing(Cellular::State::kConnected);
  capability_->UpdatePendingActivationState();

  // Device is linked.
  cellular_->set_state_for_testing(Cellular::State::kLinked);
  capability_->UpdatePendingActivationState();

  // Got valid MDN, subscription_state_ is SubscriptionState::kUnknown
  EXPECT_CALL(*modem_info_.mock_pending_activation_store(),
              RemoveEntry(PendingActivationStore::kIdentifierICCID, kIccid));

  cellular_->set_state_for_testing(Cellular::State::kRegistered);
  cellular_->SetMdn("1020304");
  capability_->subscription_state_ = SubscriptionState::kUnknown;
  capability_->UpdatePendingActivationState();
  VerifyAndSetActivationExpectations();

  EXPECT_CALL(*service_, activation_state())
      .WillRepeatedly(ReturnRef(kActivationStateUnknown));
  EXPECT_CALL(
      *modem_info_.mock_pending_activation_store(),
      GetActivationState(PendingActivationStore::kIdentifierICCID, kIccid))
      .WillRepeatedly(Return(PendingActivationStore::kStateUnknown));

  // Got invalid MDN, subscription_state_ is SubscriptionState::kProvisioned
  EXPECT_CALL(*modem_info_.mock_pending_activation_store(),
              RemoveEntry(PendingActivationStore::kIdentifierICCID, kIccid));

  cellular_->set_state_for_testing(Cellular::State::kRegistered);
  cellular_->SetMdn("0000000");
  capability_->subscription_state_ = SubscriptionState::kProvisioned;
  capability_->UpdatePendingActivationState();
  VerifyAndSetActivationExpectations();
}

TEST_F(CellularCapability3gppTest, IsServiceActivationRequired) {
  const std::vector<MobileOperatorMapper::OnlinePortal> empty_list;
  const std::vector<MobileOperatorMapper::OnlinePortal> olp_list{
      {"some@url", "some_method", "some_post_data"}};

  capability_->subscription_state_ = SubscriptionState::kProvisioned;
  EXPECT_FALSE(capability_->IsServiceActivationRequired());

  capability_->subscription_state_ = SubscriptionState::kUnprovisioned;
  EXPECT_TRUE(capability_->IsServiceActivationRequired());

  capability_->subscription_state_ = SubscriptionState::kUnknown;
  cellular_->SetMdn("0000000000");
  EXPECT_FALSE(capability_->IsServiceActivationRequired());

  EXPECT_CALL(*mock_mobile_operator_info_, IsMobileNetworkOperatorKnown())
      .WillRepeatedly(Return(false));
  EXPECT_FALSE(capability_->IsServiceActivationRequired());
  Mock::VerifyAndClearExpectations(mock_mobile_operator_info_);

  EXPECT_CALL(*mock_mobile_operator_info_, IsMobileNetworkOperatorKnown())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*mock_mobile_operator_info_, olp_list())
      .WillRepeatedly(ReturnRef(empty_list));
  EXPECT_FALSE(capability_->IsServiceActivationRequired());
  Mock::VerifyAndClearExpectations(mock_mobile_operator_info_);

  // Set expectations for all subsequent cases.
  EXPECT_CALL(*mock_mobile_operator_info_, IsMobileNetworkOperatorKnown())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*mock_mobile_operator_info_, olp_list())
      .WillRepeatedly(ReturnRef(olp_list));

  cellular_->SetMdn("");
  EXPECT_TRUE(capability_->IsServiceActivationRequired());
  cellular_->SetMdn("1234567890");
  EXPECT_FALSE(capability_->IsServiceActivationRequired());
  cellular_->SetMdn("0000000000");
  EXPECT_TRUE(capability_->IsServiceActivationRequired());

  SetDefaultCellularSimProperties();
  EXPECT_CALL(
      *modem_info_.mock_pending_activation_store(),
      GetActivationState(PendingActivationStore::kIdentifierICCID, kIccid))
      .WillOnce(Return(PendingActivationStore::kStateActivated))
      .WillOnce(Return(PendingActivationStore::kStatePending))
      .WillOnce(Return(PendingActivationStore::kStateUnknown));
  EXPECT_FALSE(capability_->IsServiceActivationRequired());
  EXPECT_FALSE(capability_->IsServiceActivationRequired());
  EXPECT_TRUE(capability_->IsServiceActivationRequired());
  VerifyAndSetActivationExpectations();
}

TEST_F(CellularCapability3gppTest, OnModemCurrentCapabilitiesChanged) {
  EXPECT_FALSE(cellular_->scanning_supported());
  capability_->OnModemCurrentCapabilitiesChanged(MM_MODEM_CAPABILITY_LTE);
  EXPECT_FALSE(cellular_->scanning_supported());
  capability_->OnModemCurrentCapabilitiesChanged(MM_MODEM_CAPABILITY_GSM_UMTS);
  EXPECT_TRUE(cellular_->scanning_supported());
}

TEST_F(CellularCapability3gppTest, SimLockStatusToProperty) {
  Error error;
  KeyValueStore store = capability_->SimLockStatusToProperty(&error);
  EXPECT_FALSE(store.Get<bool>(kSIMLockEnabledProperty));
  EXPECT_TRUE(store.Get<std::string>(kSIMLockTypeProperty).empty());
  EXPECT_EQ(0, store.Get<int32_t>(kSIMLockRetriesLeftProperty));

  capability_->sim_lock_status_.enabled = true;
  capability_->sim_lock_status_.retries_left = 3;
  capability_->sim_lock_status_.lock_type = MM_MODEM_LOCK_SIM_PIN;
  store = capability_->SimLockStatusToProperty(&error);
  EXPECT_TRUE(store.Get<bool>(kSIMLockEnabledProperty));
  EXPECT_EQ("sim-pin", store.Get<std::string>(kSIMLockTypeProperty));
  EXPECT_EQ(3, store.Get<int32_t>(kSIMLockRetriesLeftProperty));

  capability_->sim_lock_status_.lock_type = MM_MODEM_LOCK_SIM_PUK;
  store = capability_->SimLockStatusToProperty(&error);
  EXPECT_EQ("sim-puk", store.Get<std::string>(kSIMLockTypeProperty));

  capability_->sim_lock_status_.lock_type = MM_MODEM_LOCK_SIM_PIN2;
  store = capability_->SimLockStatusToProperty(&error);
  EXPECT_TRUE(store.Get<std::string>(kSIMLockTypeProperty).empty());

  capability_->sim_lock_status_.lock_type = MM_MODEM_LOCK_SIM_PUK2;
  store = capability_->SimLockStatusToProperty(&error);
  EXPECT_TRUE(store.Get<std::string>(kSIMLockTypeProperty).empty());

  capability_->sim_lock_status_.lock_type = MM_MODEM_LOCK_PH_SP_PIN;
  store = capability_->SimLockStatusToProperty(&error);
  EXPECT_EQ("service-provider-pin",
            store.Get<std::string>(kSIMLockTypeProperty));

  capability_->sim_lock_status_.lock_type = MM_MODEM_LOCK_PH_SP_PUK;
  store = capability_->SimLockStatusToProperty(&error);
  EXPECT_EQ("service-provider-puk",
            store.Get<std::string>(kSIMLockTypeProperty));

  capability_->sim_lock_status_.lock_type = MM_MODEM_LOCK_PH_NET_PIN;
  store = capability_->SimLockStatusToProperty(&error);
  EXPECT_EQ("network-pin", store.Get<std::string>(kSIMLockTypeProperty));

  capability_->sim_lock_status_.lock_type = MM_MODEM_LOCK_PH_NET_PUK;
  store = capability_->SimLockStatusToProperty(&error);
  EXPECT_EQ("network-puk", store.Get<std::string>(kSIMLockTypeProperty));

  capability_->sim_lock_status_.lock_type = MM_MODEM_LOCK_PH_SIM_PIN;
  store = capability_->SimLockStatusToProperty(&error);
  EXPECT_EQ("dedicated-sim", store.Get<std::string>(kSIMLockTypeProperty));

  capability_->sim_lock_status_.lock_type = MM_MODEM_LOCK_PH_CORP_PIN;
  store = capability_->SimLockStatusToProperty(&error);
  EXPECT_EQ("corporate-pin", store.Get<std::string>(kSIMLockTypeProperty));

  capability_->sim_lock_status_.lock_type = MM_MODEM_LOCK_PH_CORP_PUK;
  store = capability_->SimLockStatusToProperty(&error);
  EXPECT_EQ("corporate-puk", store.Get<std::string>(kSIMLockTypeProperty));

  capability_->sim_lock_status_.lock_type = MM_MODEM_LOCK_PH_NETSUB_PIN;
  store = capability_->SimLockStatusToProperty(&error);
  EXPECT_EQ("network-subset-pin", store.Get<std::string>(kSIMLockTypeProperty));

  capability_->sim_lock_status_.lock_type = MM_MODEM_LOCK_PH_NETSUB_PUK;
  store = capability_->SimLockStatusToProperty(&error);
  EXPECT_EQ("network-subset-puk", store.Get<std::string>(kSIMLockTypeProperty));
}

TEST_F(CellularCapability3gppTest, OnLockRetriesChanged) {
  CellularCapability3gpp::LockRetryData data;

  capability_->OnLockRetriesChanged(data);
  EXPECT_EQ(CellularCapability3gpp::kUnknownLockRetriesLeft,
            capability_->sim_lock_status_.retries_left);

  data[MM_MODEM_LOCK_SIM_PIN] = 3;
  data[MM_MODEM_LOCK_SIM_PIN2] = 5;
  data[MM_MODEM_LOCK_SIM_PUK] = 10;
  data[MM_MODEM_LOCK_SIM_PUK2] = 10;

  capability_->OnLockRetriesChanged(data);
  EXPECT_EQ(3, capability_->sim_lock_status_.retries_left);

  capability_->sim_lock_status_.lock_type = MM_MODEM_LOCK_SIM_PUK;
  capability_->OnLockRetriesChanged(data);
  EXPECT_EQ(10, capability_->sim_lock_status_.retries_left);

  capability_->sim_lock_status_.lock_type = MM_MODEM_LOCK_SIM_PIN;
  capability_->OnLockRetriesChanged(data);
  EXPECT_EQ(3, capability_->sim_lock_status_.retries_left);

  // retries_left should indicate the number of SIM_PIN retries if the
  // lock is SIM_PIN2 or SIM_PUK2
  capability_->sim_lock_status_.lock_type = MM_MODEM_LOCK_SIM_PIN2;
  capability_->OnLockRetriesChanged(data);
  EXPECT_EQ(3, capability_->sim_lock_status_.retries_left);

  capability_->sim_lock_status_.lock_type = MM_MODEM_LOCK_SIM_PUK2;
  capability_->OnLockRetriesChanged(data);
  EXPECT_EQ(3, capability_->sim_lock_status_.retries_left);

  data.clear();
  capability_->OnLockRetriesChanged(data);
  EXPECT_EQ(CellularCapability3gpp::kUnknownLockRetriesLeft,
            capability_->sim_lock_status_.retries_left);
}

TEST_F(CellularCapability3gppTest, OnLockTypeChanged) {
  EXPECT_EQ(MM_MODEM_LOCK_UNKNOWN, capability_->sim_lock_status_.lock_type);

  capability_->OnLockTypeChanged(MM_MODEM_LOCK_NONE);
  EXPECT_EQ(MM_MODEM_LOCK_NONE, capability_->sim_lock_status_.lock_type);
  EXPECT_FALSE(capability_->sim_lock_status_.enabled);

  capability_->OnLockTypeChanged(MM_MODEM_LOCK_SIM_PIN);
  EXPECT_EQ(MM_MODEM_LOCK_SIM_PIN, capability_->sim_lock_status_.lock_type);
  EXPECT_TRUE(capability_->sim_lock_status_.enabled);

  capability_->sim_lock_status_.enabled = false;
  capability_->OnLockTypeChanged(MM_MODEM_LOCK_SIM_PUK);
  EXPECT_EQ(MM_MODEM_LOCK_SIM_PUK, capability_->sim_lock_status_.lock_type);
  EXPECT_TRUE(capability_->sim_lock_status_.enabled);
}

TEST_F(CellularCapability3gppTest, OnSimLockPropertiesChanged) {
  EXPECT_EQ(MM_MODEM_LOCK_UNKNOWN, capability_->sim_lock_status_.lock_type);
  EXPECT_EQ(0, capability_->sim_lock_status_.retries_left);

  KeyValueStore changed;

  capability_->OnModemPropertiesChanged(changed);
  EXPECT_EQ(MM_MODEM_LOCK_UNKNOWN, capability_->sim_lock_status_.lock_type);
  EXPECT_EQ(0, capability_->sim_lock_status_.retries_left);

  // Unlock retries changed, but the SIM wasn't locked.
  CellularCapability3gpp::LockRetryData retry_data;
  retry_data[MM_MODEM_LOCK_SIM_PIN] = 3;
  changed.SetVariant(MM_MODEM_PROPERTY_UNLOCKRETRIES, brillo::Any(retry_data));

  capability_->OnModemPropertiesChanged(changed);
  EXPECT_EQ(MM_MODEM_LOCK_UNKNOWN, capability_->sim_lock_status_.lock_type);
  EXPECT_EQ(3, capability_->sim_lock_status_.retries_left);

  // Unlock retries changed and the SIM got locked.
  changed.Set<uint32_t>(MM_MODEM_PROPERTY_UNLOCKREQUIRED,
                        static_cast<uint32_t>(MM_MODEM_LOCK_SIM_PIN));
  capability_->OnModemPropertiesChanged(changed);
  EXPECT_EQ(MM_MODEM_LOCK_SIM_PIN, capability_->sim_lock_status_.lock_type);
  EXPECT_EQ(3, capability_->sim_lock_status_.retries_left);

  // Only unlock retries changed.
  changed.Remove(MM_MODEM_PROPERTY_UNLOCKREQUIRED);
  retry_data[MM_MODEM_LOCK_SIM_PIN] = 2;
  changed.SetVariant(MM_MODEM_PROPERTY_UNLOCKRETRIES, brillo::Any(retry_data));
  capability_->OnModemPropertiesChanged(changed);
  EXPECT_EQ(MM_MODEM_LOCK_SIM_PIN, capability_->sim_lock_status_.lock_type);
  EXPECT_EQ(2, capability_->sim_lock_status_.retries_left);

  // Unlock retries changed with a value that doesn't match the current
  // lock type. Default to unknown if PIN1 is unavailable.
  retry_data.clear();
  retry_data[MM_MODEM_LOCK_SIM_PIN2] = 2;
  changed.SetVariant(MM_MODEM_PROPERTY_UNLOCKRETRIES, brillo::Any(retry_data));
  capability_->OnModemPropertiesChanged(changed);
  EXPECT_EQ(MM_MODEM_LOCK_SIM_PIN, capability_->sim_lock_status_.lock_type);
  EXPECT_EQ(CellularCapability3gpp::kUnknownLockRetriesLeft,
            capability_->sim_lock_status_.retries_left);
}

TEST_F(CellularCapability3gppTest, MultiSimProperties) {
  InitProxies();

  const char kIccid1[] = "110100000001";
  const char kEid1[] = "110100000002";
  KeyValueStore sim_properties1;
  sim_properties1.Set<std::string>(MM_SIM_PROPERTY_SIMIDENTIFIER, kIccid1);
  sim_properties1.Set<std::string>(MM_SIM_PROPERTY_EID, kEid1);
  SetSimProperties(kSimPath1, sim_properties1);

  const char kIccid2[] = "210100000001";
  const char kEid2[] = "210100000002";
  KeyValueStore sim_properties2;
  sim_properties2.Set<std::string>(MM_SIM_PROPERTY_SIMIDENTIFIER, kIccid2);
  sim_properties2.Set<std::string>(MM_SIM_PROPERTY_EID, kEid2);
  SetSimProperties(kSimPath2, sim_properties2);

  UpdateSims(kSimPath1);

  EXPECT_EQ(kSimPath1, capability_->sim_path_for_testing());
  EXPECT_TRUE(cellular_->sim_present());
  EXPECT_EQ(kIccid1, cellular_->iccid());
  EXPECT_EQ(kEid1, cellular_->eid());

  const KeyValueStores& sim_slot_info = cellular_->sim_slot_info_for_testing();
  ASSERT_EQ(2u, sim_slot_info.size());
  EXPECT_EQ(sim_slot_info[0].Get<std::string>(kSIMSlotInfoICCID), kIccid1);
  EXPECT_EQ(sim_slot_info[0].Get<std::string>(kSIMSlotInfoEID), kEid1);
  EXPECT_EQ(sim_slot_info[1].Get<std::string>(kSIMSlotInfoICCID), kIccid2);
  EXPECT_EQ(sim_slot_info[1].Get<std::string>(kSIMSlotInfoEID), kEid2);
  VerifyAndSetActivationExpectations();

  // Switch active slot to 2.
  KeyValueStore modem_properties;
  modem_properties.Set<RpcIdentifier>(MM_MODEM_PROPERTY_SIM, kSimPath2);
  capability_->OnPropertiesChanged(MM_DBUS_INTERFACE_MODEM, modem_properties);
  dispatcher_.DispatchPendingEvents();

  EXPECT_EQ(kSimPath2, capability_->sim_path_for_testing());
  EXPECT_TRUE(cellular_->sim_present());
  EXPECT_EQ(kIccid2, cellular_->iccid());
  EXPECT_EQ(kEid2, cellular_->eid());
  VerifyAndSetActivationExpectations();
}

// Test behavior when a SIM path is set but not SIMSLOTS.
TEST_F(CellularCapability3gppTest, SimPathOnly) {
  InitProxies();

  const char kIccid1[] = "110100000001";
  const char kEid1[] = "110100000002";
  KeyValueStore sim_properties;
  sim_properties.Set<std::string>(MM_SIM_PROPERTY_SIMIDENTIFIER, kIccid1);
  sim_properties.Set<std::string>(MM_SIM_PROPERTY_EID, kEid1);
  SetSimProperties(kSimPath1, sim_properties);

  KeyValueStore modem_properties;
  modem_properties.Set<RpcIdentifier>(MM_MODEM_PROPERTY_SIM, kSimPath1);
  capability_->OnPropertiesChanged(MM_DBUS_INTERFACE_MODEM, modem_properties);
  dispatcher_.DispatchPendingEvents();

  EXPECT_EQ(kSimPath1, capability_->sim_path_for_testing());
  EXPECT_TRUE(cellular_->sim_present());
  EXPECT_EQ(kIccid1, cellular_->iccid());
  EXPECT_EQ(kEid1, cellular_->eid());
  VerifyAndSetActivationExpectations();
}

TEST_F(CellularCapability3gppTest, EmptySimSlot) {
  InitProxies();

  const char kIccid1[] = "110100000001";
  const char kEid1[] = "110100000002";
  KeyValueStore sim_properties1;
  sim_properties1.Set<std::string>(MM_SIM_PROPERTY_SIMIDENTIFIER, kIccid1);
  sim_properties1.Set<std::string>(MM_SIM_PROPERTY_EID, kEid1);
  SetSimProperties(kSimPath1, sim_properties1);

  KeyValueStore sim_properties2;
  SetSimProperties(CellularCapability3gpp::kRootPath, sim_properties2);

  UpdateSims(kSimPath1);

  EXPECT_EQ(kSimPath1, capability_->sim_path_for_testing());
  EXPECT_TRUE(cellular_->sim_present());
  EXPECT_EQ(kIccid1, cellular_->iccid());
  EXPECT_EQ(kEid1, cellular_->eid());

  const KeyValueStores& sim_slot_info = cellular_->sim_slot_info_for_testing();
  ASSERT_EQ(2u, sim_slot_info.size());
  EXPECT_EQ(sim_slot_info[0].Get<std::string>(kSIMSlotInfoICCID), kIccid1);
  EXPECT_EQ(sim_slot_info[0].Get<std::string>(kSIMSlotInfoEID), kEid1);
  EXPECT_TRUE(sim_slot_info[1].Get<std::string>(kSIMSlotInfoICCID).empty());
  EXPECT_TRUE(sim_slot_info[1].Get<std::string>(kSIMSlotInfoEID).empty());
  VerifyAndSetActivationExpectations();
}

// Check that a pSIM with an empty iccid is reported to Cellular as a SIM with
// an "unknown-iccid".
TEST_F(CellularCapability3gppTest, UnknownIccid) {
  InitProxies();

  const char kIccid1[] = "";
  KeyValueStore sim_properties1;
  sim_properties1.Set<std::string>(MM_SIM_PROPERTY_SIMIDENTIFIER, kIccid1);
  SetSimProperties(kSimPath1, sim_properties1);
  UpdateSims(kSimPath1);

  KeyValueStore sim_properties2;
  sim_properties2.Set<uint32_t>(MM_SIM_PROPERTY_SIMTYPE,
                                MMSimType::MM_SIM_TYPE_ESIM);
  SetSimProperties(CellularCapability3gpp::kRootPath, sim_properties2);
  UpdateSims(kSimPath2);

  const KeyValueStores& sim_slot_info = cellular_->sim_slot_info_for_testing();
  ASSERT_EQ(2u, sim_slot_info.size());
  EXPECT_EQ(sim_slot_info[0].Get<std::string>(kSIMSlotInfoICCID),
            kUnknownIccid);
  EXPECT_TRUE(sim_slot_info[1].Get<std::string>(kSIMSlotInfoICCID).empty());
  VerifyAndSetActivationExpectations();
}

TEST_F(CellularCapability3gppTest, UpdateLinkSpeed) {
  InitProxies();

  constexpr char kPropertyUpLinkSpeed[] = "uplink-speed";
  constexpr char kPropertyDownLinkSpeed[] = "downlink-speed";
  KeyValueStore stats;
  stats.Set<uint64_t>(kPropertyUpLinkSpeed, 200000UL);
  stats.Set<uint64_t>(kPropertyDownLinkSpeed, 100000UL);

  KeyValueStore props;
  props.Set<KeyValueStore>(MM_BEARER_PROPERTY_STATS, stats);

  EXPECT_CALL(*service_, SetUplinkSpeedKbps(200)).Times(1);
  EXPECT_CALL(*service_, SetDownlinkSpeedKbps(100)).Times(1);
  capability_->OnPropertiesChanged(MM_DBUS_INTERFACE_BEARER, props);
}

TEST_F(CellularCapability3gppTest, UpdateLinkSpeedNoSelectedService) {
  InitProxies();
  cellular_->SetSelectedServiceForTesting(nullptr);

  constexpr char kPropertyUpLinkSpeed[] = "uplink-speed";
  constexpr char kPropertyDownLinkSpeed[] = "downlink-speed";
  KeyValueStore stats;
  stats.Set<uint64_t>(kPropertyUpLinkSpeed, 200000UL);
  stats.Set<uint64_t>(kPropertyDownLinkSpeed, 100000UL);

  KeyValueStore props;
  props.Set<KeyValueStore>(MM_BEARER_PROPERTY_STATS, stats);

  EXPECT_CALL(*service_, SetUplinkSpeedKbps(_)).Times(0);
  EXPECT_CALL(*service_, SetDownlinkSpeedKbps(_)).Times(0);
  capability_->OnPropertiesChanged(MM_DBUS_INTERFACE_BEARER, props);
}

}  // namespace shill
