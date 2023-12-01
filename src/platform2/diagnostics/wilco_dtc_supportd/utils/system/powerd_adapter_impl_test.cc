// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <unordered_map>

#include <base/check.h>
#include <base/functional/callback.h>
#include <base/memory/ref_counted.h>
#include <dbus/message.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <dbus/power_manager/dbus-constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/wilco_dtc_supportd/utils/system/powerd_adapter.h"
#include "diagnostics/wilco_dtc_supportd/utils/system/powerd_adapter_impl.h"

using ::testing::_;
using ::testing::SaveArg;
using ::testing::StrictMock;

namespace diagnostics {
namespace wilco {
namespace {

// Writes empty proto messate to |signal|. After this operation, empty proto
// message can be successfuly read from the |signal|.
void WriteEmptyProtoToSignal(dbus::Signal* signal) {
  ASSERT_TRUE(signal);
  const std::string kSerializedProto;
  dbus::MessageWriter writer(signal);
  writer.AppendArrayOfBytes(
      reinterpret_cast<const uint8_t*>(kSerializedProto.data()),
      kSerializedProto.size());
}

class MockPowerdAdapterPowerObserver : public PowerdAdapter::PowerObserver {
 public:
  enum PowerSignalType {
    POWER_SUPPLY,
    SUSPEND_IMMINENT,
    DARK_SUSPEND_IMMINENT,
    SUSPEND_DONE,
  };

  void OnPowerSupplyPollSignal(
      const power_manager::PowerSupplyProperties& power_supply) {
    OnPowerSignal(POWER_SUPPLY);
  }
  void OnSuspendImminentSignal(
      const power_manager::SuspendImminent& suspend_imminent) {
    OnPowerSignal(SUSPEND_IMMINENT);
  }
  void OnDarkSuspendImminentSignal(
      const power_manager::SuspendImminent& suspend_imminent) {
    OnPowerSignal(DARK_SUSPEND_IMMINENT);
  }
  void OnSuspendDoneSignal(const power_manager::SuspendDone& suspend_done) {
    OnPowerSignal(SUSPEND_DONE);
  }

  MOCK_METHOD(void, OnPowerSignal, (PowerSignalType));
};

class MockPowerdAdapterLidObserver : public PowerdAdapter::LidObserver {
 public:
  enum LidSignalType {
    LID_CLOSED,
    LID_OPENED,
  };

  void OnLidClosedSignal() { OnLidSignal(LID_CLOSED); }
  void OnLidOpenedSignal() { OnLidSignal(LID_OPENED); }

  MOCK_METHOD(void, OnLidSignal, (LidSignalType));
};

class BasePowerdAdapterImplTest : public ::testing::Test {
 public:
  BasePowerdAdapterImplTest()
      : dbus_bus_(new StrictMock<dbus::MockBus>(dbus::Bus::Options())),
        dbus_object_proxy_(new StrictMock<dbus::MockObjectProxy>(
            dbus_bus_.get(),
            power_manager::kPowerManagerServiceName,
            dbus::ObjectPath(power_manager::kPowerManagerServicePath))) {}
  BasePowerdAdapterImplTest(const BasePowerdAdapterImplTest&) = delete;
  BasePowerdAdapterImplTest& operator=(const BasePowerdAdapterImplTest&) =
      delete;

  void SetUp() override {
    EXPECT_CALL(*dbus_bus_,
                GetObjectProxy(
                    power_manager::kPowerManagerServiceName,
                    dbus::ObjectPath(power_manager::kPowerManagerServicePath)))
        .WillOnce(Return(dbus_object_proxy_.get()));

    EXPECT_CALL(*dbus_object_proxy_,
                DoConnectToSignal(power_manager::kPowerManagerInterface,
                                  power_manager::kPowerSupplyPollSignal, _, _))
        .WillOnce(SaveArg<2>(
            &on_signal_callbacks_[power_manager::kPowerSupplyPollSignal]));
    EXPECT_CALL(*dbus_object_proxy_,
                DoConnectToSignal(power_manager::kPowerManagerInterface,
                                  power_manager::kSuspendImminentSignal, _, _))
        .WillOnce(SaveArg<2>(
            &on_signal_callbacks_[power_manager::kSuspendImminentSignal]));
    EXPECT_CALL(
        *dbus_object_proxy_,
        DoConnectToSignal(power_manager::kPowerManagerInterface,
                          power_manager::kDarkSuspendImminentSignal, _, _))
        .WillOnce(SaveArg<2>(
            &on_signal_callbacks_[power_manager::kDarkSuspendImminentSignal]));
    EXPECT_CALL(*dbus_object_proxy_,
                DoConnectToSignal(power_manager::kPowerManagerInterface,
                                  power_manager::kSuspendDoneSignal, _, _))
        .WillOnce(SaveArg<2>(
            &on_signal_callbacks_[power_manager::kSuspendDoneSignal]));
    EXPECT_CALL(*dbus_object_proxy_,
                DoConnectToSignal(power_manager::kPowerManagerInterface,
                                  power_manager::kLidClosedSignal, _, _))
        .WillOnce(
            SaveArg<2>(&on_signal_callbacks_[power_manager::kLidClosedSignal]));
    EXPECT_CALL(*dbus_object_proxy_,
                DoConnectToSignal(power_manager::kPowerManagerInterface,
                                  power_manager::kLidOpenedSignal, _, _))
        .WillOnce(
            SaveArg<2>(&on_signal_callbacks_[power_manager::kLidOpenedSignal]));

    powerd_adapter_ = std::make_unique<PowerdAdapterImpl>(dbus_bus_);
  }

  void InvokeSignal(const std::string& method_name, dbus::Signal* signal) {
    ASSERT_TRUE(signal);
    auto callback_iter = on_signal_callbacks_.find(method_name);
    ASSERT_NE(callback_iter, on_signal_callbacks_.end());
    callback_iter->second.Run(signal);
  }

  PowerdAdapterImpl* powerd_adapter() const {
    DCHECK(powerd_adapter_);
    return powerd_adapter_.get();
  }

  dbus::MockObjectProxy* mock_dbus_object_proxy() const {
    DCHECK(dbus_object_proxy_);
    return dbus_object_proxy_.get();
  }

 private:
  scoped_refptr<StrictMock<dbus::MockBus>> dbus_bus_;

  scoped_refptr<StrictMock<dbus::MockObjectProxy>> dbus_object_proxy_;

  std::unique_ptr<PowerdAdapterImpl> powerd_adapter_;

  std::unordered_map<std::string,
                     base::RepeatingCallback<void(dbus::Signal* signal)>>
      on_signal_callbacks_;
};

TEST_F(BasePowerdAdapterImplTest, PowerSupplySuccess) {
  power_manager::PowerSupplyProperties power_supply_proto;
  EXPECT_CALL(*mock_dbus_object_proxy(), CallMethodAndBlock(_, _))
      .WillOnce([&power_supply_proto](dbus::MethodCall*, int) {
        std::unique_ptr<dbus::Response> power_manager_response =
            dbus::Response::CreateEmpty();
        dbus::MessageWriter power_manager_writer(power_manager_response.get());
        power_manager_writer.AppendProtoAsArrayOfBytes(power_supply_proto);
        return power_manager_response;
      });

  auto response = powerd_adapter()->GetPowerSupplyProperties();
  EXPECT_TRUE(response);
  // The proto structure is simple enough where it can be compared as a string.
  // If if becomes more complex this will need to change.
  EXPECT_EQ(response.value().SerializeAsString(),
            power_supply_proto.SerializeAsString());
}

TEST_F(BasePowerdAdapterImplTest, PowerSupplyFail) {
  power_manager::PowerSupplyProperties power_supply_proto;
  EXPECT_CALL(*mock_dbus_object_proxy(), CallMethodAndBlock(_, _))
      .WillOnce([](dbus::MethodCall*, int) { return nullptr; });

  ASSERT_EQ(powerd_adapter()->GetPowerSupplyProperties(), std::nullopt);
}

TEST_F(BasePowerdAdapterImplTest, PowerSupplyParseError) {
  power_manager::PowerSupplyProperties power_supply_proto;
  EXPECT_CALL(*mock_dbus_object_proxy(), CallMethodAndBlock(_, _))
      .WillOnce(
          [](dbus::MethodCall*, int) { return dbus::Response::CreateEmpty(); });

  ASSERT_EQ(powerd_adapter()->GetPowerSupplyProperties(), std::nullopt);
}

// This is a parameterized test with the following parameters:
// * |signal_name| - signal name which will be invoked;
// * |expected_received_signal_type| - expected received signal type.
class PowerdAdapterImplTest
    : public BasePowerdAdapterImplTest,
      public testing::WithParamInterface<
          std::tuple<std::string /* signal_name */,
                     MockPowerdAdapterPowerObserver::
                         PowerSignalType /* expected_received_signal_type */>> {
 public:
  PowerdAdapterImplTest() = default;
  PowerdAdapterImplTest(const PowerdAdapterImplTest&) = delete;
  PowerdAdapterImplTest& operator=(const PowerdAdapterImplTest&) = delete;

 protected:
  // Accessors to individual test parameters from the test parameter tuple
  // returned by gtest's GetParam():

  const std::string& signal_name() const { return std::get<0>(GetParam()); }

  MockPowerdAdapterPowerObserver::PowerSignalType
  expected_received_signal_type() const {
    return std::get<1>(GetParam());
  }
};

TEST_P(PowerdAdapterImplTest, OnPowerSignal) {
  StrictMock<MockPowerdAdapterPowerObserver> mock_observer;
  powerd_adapter()->AddPowerObserver(&mock_observer);

  dbus::Signal signal(power_manager::kPowerManagerInterface, signal_name());

  // Invoke signal without a valid proto message.
  InvokeSignal(signal_name(), &signal);

  // Invoke signal with a valid proto message.
  WriteEmptyProtoToSignal(&signal);
  EXPECT_CALL(mock_observer, OnPowerSignal(expected_received_signal_type()));
  InvokeSignal(signal_name(), &signal);

  // Expect that |mock_observer| will not receive further notifications once
  // |mock_observer| was removed from powerd adapter.
  powerd_adapter()->RemovePowerObserver(&mock_observer);
  WriteEmptyProtoToSignal(&signal);
  InvokeSignal(signal_name(), &signal);
}

INSTANTIATE_TEST_SUITE_P(
    ,
    PowerdAdapterImplTest,
    testing::Values(
        std::make_tuple(power_manager::kPowerSupplyPollSignal,
                        MockPowerdAdapterPowerObserver::POWER_SUPPLY),
        std::make_tuple(power_manager::kSuspendImminentSignal,
                        MockPowerdAdapterPowerObserver::SUSPEND_IMMINENT),
        std::make_tuple(power_manager::kDarkSuspendImminentSignal,
                        MockPowerdAdapterPowerObserver::DARK_SUSPEND_IMMINENT),
        std::make_tuple(power_manager::kSuspendDoneSignal,
                        MockPowerdAdapterPowerObserver::SUSPEND_DONE)));

// This is a parameterized test with the following parameters:
// * |signal_name| - signal name which will be invoked;
// * |expected_received_signal_type| - expected received signal type.
class PowerdAdapterImplLidTest
    : public BasePowerdAdapterImplTest,
      public testing::WithParamInterface<
          std::tuple<std::string /* signal_name */,
                     MockPowerdAdapterLidObserver::
                         LidSignalType /* expected_received_signal_type */>> {
 public:
  PowerdAdapterImplLidTest() = default;
  PowerdAdapterImplLidTest(const PowerdAdapterImplLidTest&) = delete;
  PowerdAdapterImplLidTest& operator=(const PowerdAdapterImplLidTest&) = delete;

 protected:
  // Accessors to individual test parameters from the test parameter tuple
  // returned by gtest's GetParam():

  const std::string& signal_name() const { return std::get<0>(GetParam()); }

  MockPowerdAdapterLidObserver::LidSignalType expected_received_signal_type()
      const {
    return std::get<1>(GetParam());
  }
};

TEST_P(PowerdAdapterImplLidTest, OnLidSignal) {
  StrictMock<MockPowerdAdapterLidObserver> mock_observer;
  powerd_adapter()->AddLidObserver(&mock_observer);

  dbus::Signal signal(power_manager::kPowerManagerInterface, signal_name());

  // Invoke signal.
  EXPECT_CALL(mock_observer, OnLidSignal(expected_received_signal_type()));
  InvokeSignal(signal_name(), &signal);

  // Expect that |mock_observer| will not receive further notifications once
  // |mock_observer| was removed from powerd adapter.
  powerd_adapter()->RemoveLidObserver(&mock_observer);
  InvokeSignal(signal_name(), &signal);
}

INSTANTIATE_TEST_SUITE_P(
    ,
    PowerdAdapterImplLidTest,
    testing::Values(std::make_tuple(power_manager::kLidClosedSignal,
                                    MockPowerdAdapterLidObserver::LID_CLOSED),
                    std::make_tuple(power_manager::kLidOpenedSignal,
                                    MockPowerdAdapterLidObserver::LID_OPENED)));

}  // namespace
}  // namespace wilco
}  // namespace diagnostics
