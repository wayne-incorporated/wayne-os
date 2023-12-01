// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/check.h>
#include <base/functional/callback.h>
#include <base/memory/ref_counted.h>
#include <brillo/variant_dictionary.h>
#include <dbus/message.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "federated/network_status_training_condition.h"

namespace federated {
namespace {

using ::shill::kFlimflamManagerInterface;
using ::shill::kMonitorPropertyChanged;
using ::testing::_;
using ::testing::ByMove;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::StrictMock;

class MockClient : public shill::Client {
 public:
  explicit MockClient(scoped_refptr<dbus::Bus> bus) : shill::Client(bus) {}
  ~MockClient() override = default;
  MOCK_METHOD(std::unique_ptr<brillo::VariantDictionary>,
              GetDefaultServiceProperties,
              (const base::TimeDelta& timeout),
              (const, override));
};
}  // namespace

class NetworkStatusTrainingConditionTest : public ::testing::Test {
 public:
  NetworkStatusTrainingConditionTest()
      : mock_dbus_(new StrictMock<dbus::MockBus>(dbus::Bus::Options())),
        dbus_object_proxy_(new StrictMock<dbus::MockObjectProxy>(
            mock_dbus_.get(),
            shill::kFlimflamServiceName,
            dbus::ObjectPath(shill::kFlimflamServicePath))) {
    EXPECT_CALL(*mock_dbus_,
                GetObjectProxy(shill::kFlimflamServiceName,
                               dbus::ObjectPath(shill::kFlimflamServicePath)))
        .WillRepeatedly(Return(dbus_object_proxy_.get()));

    EXPECT_CALL(*dbus_object_proxy_,
                DoConnectToSignal(shill::kFlimflamManagerInterface,
                                  shill::kMonitorPropertyChanged, _, _));

    EXPECT_CALL(*dbus_object_proxy_, SetNameOwnerChangedCallback(_));

    auto client = std::make_unique<StrictMock<MockClient>>(mock_dbus_.get());
    mock_dbus_client_ = client.get();
    network_status_training_condition_ =
        std::make_unique<NetworkStatusTrainingCondition>(std::move(client));
  }
  NetworkStatusTrainingConditionTest(
      const NetworkStatusTrainingConditionTest&) = delete;
  NetworkStatusTrainingConditionTest& operator=(
      const NetworkStatusTrainingConditionTest&) = delete;

  [[nodiscard]] NetworkStatusTrainingCondition*
  network_status_training_condition() const {
    DCHECK(network_status_training_condition_ != nullptr);
    return network_status_training_condition_.get();
  }

  [[nodiscard]] StrictMock<MockClient>* mock_dbus_client() const {
    DCHECK(mock_dbus_client_ != nullptr);
    return mock_dbus_client_;
  }

 private:
  scoped_refptr<StrictMock<dbus::MockBus>> mock_dbus_;

  scoped_refptr<StrictMock<dbus::MockObjectProxy>> dbus_object_proxy_;

  StrictMock<MockClient>* mock_dbus_client_;

  std::unique_ptr<NetworkStatusTrainingCondition>
      network_status_training_condition_;
};

TEST_F(NetworkStatusTrainingConditionTest, IsTrainingConditionSatisfied) {
  // No dictionary returned
  {
    EXPECT_CALL(*mock_dbus_client(), GetDefaultServiceProperties(_))
        .WillOnce(Return(ByMove(nullptr)));

    EXPECT_FALSE(
        network_status_training_condition()->IsTrainingConditionSatisfied());
  }

  // No Metered property
  {
    auto dict = std::make_unique<brillo::VariantDictionary>();
    EXPECT_CALL(*mock_dbus_client(), GetDefaultServiceProperties(_))
        .WillOnce(Return(ByMove(std::move(dict))));

    EXPECT_FALSE(
        network_status_training_condition()->IsTrainingConditionSatisfied());
  }

  // Network is metered
  {
    auto dict = std::make_unique<brillo::VariantDictionary>();
    dict->insert({shill::kMeteredProperty, true});
    EXPECT_CALL(*mock_dbus_client(), GetDefaultServiceProperties(_))
        .WillOnce(Return(ByMove(std::move(dict))));

    EXPECT_FALSE(
        network_status_training_condition()->IsTrainingConditionSatisfied());
  }

  // Network is not metered
  {
    auto dict = std::make_unique<brillo::VariantDictionary>();
    dict->insert({shill::kMeteredProperty, false});
    EXPECT_CALL(*mock_dbus_client(), GetDefaultServiceProperties(_))
        .WillOnce(Return(ByMove(std::move(dict))));

    EXPECT_TRUE(
        network_status_training_condition()->IsTrainingConditionSatisfied());
  }
}

}  // namespace federated
