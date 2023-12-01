// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/run_loop.h>
#include <dbus/mock_bus.h>
#include <google/protobuf/util/message_differencer.h>
#include <gtest/gtest.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "federated/federated_metadata.h"
#include "federated/federated_service_impl.h"
#include "federated/mock_scheduler.h"
#include "federated/mock_storage_manager.h"
#include "federated/mojom/federated_service.mojom.h"
#include "federated/protos/example.pb.h"
#include "federated/test_utils.h"
#include "federated/utils.h"

namespace federated {
namespace {

using chromeos::federated::mojom::FederatedService;
using testing::_;
using testing::NiceMock;
using testing::Return;
using testing::StrictMock;

class FederatedServiceImplTest : public testing::Test {
 public:
  FederatedServiceImplTest()
      : mock_dbus_(new NiceMock<dbus::MockBus>(dbus::Bus::Options())) {}
  FederatedServiceImplTest(const FederatedServiceImplTest&) = delete;
  FederatedServiceImplTest& operator=(const FederatedServiceImplTest&) = delete;

  void SetUp() override {
    storage_manager_ = std::make_unique<StrictMock<MockStorageManager>>();
    scheduler_ = std::make_unique<StrictMock<MockScheduler>>(
        storage_manager_.get(),
        std::make_unique<DeviceStatusMonitor>(
            std::vector<std::unique_ptr<TrainingCondition>>()),
        mock_dbus_.get());
    federated_service_impl_ = std::make_unique<FederatedServiceImpl>(
        federated_service_.BindNewPipeAndPassReceiver().PassPipe(),
        base::OnceClosure(), storage_manager_.get(), scheduler_.get());
  }

 protected:
  std::unique_ptr<MockStorageManager> storage_manager_;
  std::unique_ptr<MockScheduler> scheduler_;
  mojo::Remote<FederatedService> federated_service_;

 private:
  scoped_refptr<dbus::MockBus> mock_dbus_;
  std::unique_ptr<FederatedServiceImpl> federated_service_impl_;
};

TEST_F(FederatedServiceImplTest, TestReportExample) {
  const std::string registered_client_name = *GetClientNames().begin();
  EXPECT_CALL(*storage_manager_, OnExampleReceived(registered_client_name, _))
      .Times(1)
      .WillOnce(Return(true));

  // Reports examples with a registered client_name then an unknown client_name,
  // will trigger storage_manager->OnExampleReceived only once.
  federated_service_->ReportExample(registered_client_name, CreateExamplePtr());
  federated_service_->ReportExample("unknown_client", CreateExamplePtr());

  base::RunLoop().RunUntilIdle();
}

TEST_F(FederatedServiceImplTest, TestClone) {
  const std::string registered_client_name = *GetClientNames().begin();
  EXPECT_CALL(*storage_manager_, OnExampleReceived(registered_client_name, _))
      .Times(1)
      .WillOnce(Return(true));

  // Call Clone to bind another FederatedService.
  mojo::Remote<FederatedService> federated_service_2;
  federated_service_->Clone(federated_service_2.BindNewPipeAndPassReceiver());

  federated_service_2->ReportExample(registered_client_name,
                                     CreateExamplePtr());

  base::RunLoop().RunUntilIdle();
}

TEST_F(FederatedServiceImplTest, TestStartScheduling) {
  EXPECT_CALL(*scheduler_, Schedule(_)).Times(1);
  federated_service_->StartScheduling(/*client_launch_stage=*/std::nullopt);
  base::RunLoop().RunUntilIdle();
}

}  // namespace
}  // namespace federated
