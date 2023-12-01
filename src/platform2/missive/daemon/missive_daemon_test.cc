// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/daemon/missive_daemon.h"

#include <memory>
#include <utility>

#include <base/test/task_environment.h>
#include <brillo/dbus/dbus_method_response.h>
#include <brillo/dbus/mock_dbus_method_response.h>
#include <brillo/message_loops/base_message_loop.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_exported_object.h>
#include <dbus/mock_object_proxy.h>
#include <featured/feature_library.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "missive/dbus/dbus_adaptor.h"
#include "missive/missive/missive_service.h"
#include "missive/proto/interface.pb.h"
#include "missive/proto/record.pb.h"
#include "missive/proto/record_constants.pb.h"
#include "missive/storage/storage_uploader_interface.h"
#include "missive/util/status.h"
#include "missive/util/test_support_callbacks.h"
#include "missive/util/test_util.h"

using ::brillo::dbus_utils::AsyncEventSequencer;

using ::testing::_;
using ::testing::AllOf;
using ::testing::AnyNumber;
using ::testing::Eq;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::NotNull;
using ::testing::Property;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::StrictMock;
using ::testing::WithArg;

namespace reporting {
namespace {

class MockMissive : public MissiveService {
 public:
  MockMissive() = default;

  MOCK_METHOD(void,
              StartUp,
              (scoped_refptr<dbus::Bus> bus,
               feature::PlatformFeaturesInterface* feature_lib,
               base::OnceCallback<void(Status)> cb),
              (override));

  MOCK_METHOD(Status, ShutDown, (), (override));
  MOCK_METHOD(void, OnReady, (), (const override));

  MOCK_METHOD(void,
              EnqueueRecord,
              (const EnqueueRecordRequest& in_request,
               std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                   EnqueueRecordResponse>> out_response),
              (override));
  MOCK_METHOD(void,
              FlushPriority,
              (const FlushPriorityRequest& in_request,
               std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                   FlushPriorityResponse>> out_response),
              (override));
  MOCK_METHOD(void,
              ConfirmRecordUpload,
              (const ConfirmRecordUploadRequest& in_request,
               std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                   ConfirmRecordUploadResponse>> out_response),
              (override));
  MOCK_METHOD(void,
              UpdateEncryptionKey,
              (const UpdateEncryptionKeyRequest& in_request,
               std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                   UpdateEncryptionKeyResponse>> out_response),
              (override));
};

class MissiveDaemonTest : public ::testing::Test {
 public:
  MissiveDaemonTest() = default;

  void TearDown() override {
    if (missive_daemon_) {
      if (mock_missive_) {
        EXPECT_CALL(*mock_missive_, ShutDown()).Times(1);
        mock_missive_ = nullptr;
      }
      feature::PlatformFeatures::ShutdownForTesting();
      missive_daemon_->Shutdown();
      missive_daemon_.reset();
    }
  }

  void StartUp(
      Status status = Status::StatusOK(),
      base::OnceCallback<void(Status)> failure_cb = base::DoNothing()) {
    ASSERT_FALSE(mock_missive_) << "Can call StartUp only once";
    auto mock_missive = std::make_unique<StrictMock<MockMissive>>();
    mock_missive_ = mock_missive.get();

    dbus::Bus::Options options;
    mock_bus_ = base::MakeRefCounted<NiceMock<dbus::MockBus>>(options);
    dbus::ObjectPath path(missive::kMissiveServicePath);

    mock_exported_object_ =
        base::MakeRefCounted<StrictMock<dbus::MockExportedObject>>(
            mock_bus_.get(), path);

    ON_CALL(*mock_bus_, GetExportedObject(path))
        .WillByDefault(Return(mock_exported_object_.get()));

    ON_CALL(*mock_bus_, GetDBusTaskRunner())
        .WillByDefault(
            Return(task_environment_.GetMainThreadTaskRunner().get()));

    EXPECT_CALL(*mock_exported_object_, ExportMethod(_, _, _, _))
        .Times(AnyNumber());

    scoped_refptr<dbus::MockObjectProxy> mock_proxy_(
        base::MakeRefCounted<dbus::MockObjectProxy>(
            mock_bus_.get(), chromeos::kChromeFeaturesServiceName,
            dbus::ObjectPath(chromeos::kChromeFeaturesServicePath)));

    ON_CALL(*mock_bus_, GetObjectProxy(_, _))
        .WillByDefault(Return(mock_proxy_.get()));

    auto missive = std::make_unique<StrictMock<MockMissive>>();
    mock_missive_ = missive.get();
    EXPECT_CALL(*mock_missive_, StartUp(NotNull(), _, _))
        .WillOnce(WithArg<2>([&status](base::OnceCallback<void(Status)> cb) {
          std::move(cb).Run(status);
        }));

    missive_daemon_ = std::make_unique<DBusAdaptor>(
        mock_bus_, std::move(missive), std::move(failure_cb));
  }

  void WaitForReady() {
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(*mock_missive_, OnReady())
        .WillOnce(Invoke(&waiter, &test::TestCallbackWaiter::Signal));
  }

 protected:
  base::test::TaskEnvironment task_environment_;

  scoped_refptr<dbus::MockBus> mock_bus_;
  scoped_refptr<dbus::MockExportedObject> mock_exported_object_;
  // Necessary for feature::PlatformFeatures::Initialize in DbusAdaptor.
  scoped_refptr<dbus::MockObjectProxy> mock_proxy_;
  StrictMock<MockMissive>* mock_missive_ = nullptr;
  std::unique_ptr<DBusAdaptor> missive_daemon_;
};

TEST_F(MissiveDaemonTest, EnqueueRecordTest) {
  StartUp();
  WaitForReady();

  EnqueueRecordRequest request;
  request.mutable_record()->set_data("DATA");
  request.mutable_record()->set_destination(HEARTBEAT_EVENTS);
  request.set_priority(FAST_BATCH);

  EXPECT_CALL(*mock_missive_, EnqueueRecord(EqualsProto(request), _))
      .WillOnce([](const EnqueueRecordRequest& in_request,
                   std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                       EnqueueRecordResponse>> out_response) {
        EnqueueRecordResponse response;  // Success
        out_response->Return(response);
      });

  auto response = std::make_unique<
      brillo::dbus_utils::MockDBusMethodResponse<EnqueueRecordResponse>>();
  test::TestEvent<const EnqueueRecordResponse&> response_event;
  response->set_return_callback(response_event.cb());
  missive_daemon_->EnqueueRecord(std::move(response), request);
  const auto& response_result = response_event.ref_result();
  EXPECT_THAT(response_result.status().code(), Eq(error::OK));
}

TEST_F(MissiveDaemonTest, FlushPriorityTest) {
  StartUp();
  WaitForReady();

  FlushPriorityRequest request;
  request.set_priority(MANUAL_BATCH);

  EXPECT_CALL(*mock_missive_, FlushPriority(EqualsProto(request), _))
      .WillOnce([](const FlushPriorityRequest& in_request,
                   std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                       FlushPriorityResponse>> out_response) {
        FlushPriorityResponse response;  // Success
        out_response->Return(response);
      });

  auto response = std::make_unique<
      brillo::dbus_utils::MockDBusMethodResponse<FlushPriorityResponse>>();
  test::TestEvent<const FlushPriorityResponse&> response_event;
  response->set_return_callback(response_event.cb());
  missive_daemon_->FlushPriority(std::move(response), request);
  const auto& response_result = response_event.ref_result();
  EXPECT_THAT(response_result.status().code(), Eq(error::OK));
}

TEST_F(MissiveDaemonTest, ConfirmRecordUploadTest) {
  StartUp();
  WaitForReady();

  ConfirmRecordUploadRequest request;
  request.mutable_sequence_information()->set_sequencing_id(1234L);
  request.mutable_sequence_information()->set_generation_id(9876L);
  request.mutable_sequence_information()->set_priority(IMMEDIATE);
  request.set_force_confirm(true);

  EXPECT_CALL(*mock_missive_, ConfirmRecordUpload(EqualsProto(request), _))
      .WillOnce([](const ConfirmRecordUploadRequest& in_request,
                   std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                       ConfirmRecordUploadResponse>> out_response) {
        ConfirmRecordUploadResponse response;  // Success
        out_response->Return(response);
      });

  auto response = std::make_unique<brillo::dbus_utils::MockDBusMethodResponse<
      ConfirmRecordUploadResponse>>();
  test::TestEvent<const ConfirmRecordUploadResponse&> response_event;
  response->set_return_callback(response_event.cb());
  missive_daemon_->ConfirmRecordUpload(std::move(response), request);
  const auto& response_result = response_event.ref_result();
  EXPECT_THAT(response_result.status().code(), Eq(error::OK));
}

TEST_F(MissiveDaemonTest, UpdateEncryptionKeyTest) {
  StartUp();
  WaitForReady();

  UpdateEncryptionKeyRequest request;
  request.mutable_signed_encryption_info()->set_public_asymmetric_key(
      "PUBLIC_KEY");
  request.mutable_signed_encryption_info()->set_public_key_id(555666);
  request.mutable_signed_encryption_info()->set_signature("SIGNATURE");

  EXPECT_CALL(*mock_missive_, UpdateEncryptionKey(EqualsProto(request), _))
      .WillOnce([](const UpdateEncryptionKeyRequest& in_request,
                   std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                       UpdateEncryptionKeyResponse>> out_response) {
        UpdateEncryptionKeyResponse response;  // Success
        out_response->Return(response);
      });

  auto response = std::make_unique<brillo::dbus_utils::MockDBusMethodResponse<
      UpdateEncryptionKeyResponse>>();
  test::TestEvent<const UpdateEncryptionKeyResponse&> response_event;
  response->set_return_callback(response_event.cb());
  missive_daemon_->UpdateEncryptionKey(std::move(response), request);
  const auto& response_result = response_event.ref_result();
  EXPECT_THAT(response_result.status().code(), Eq(error::OK));
}

TEST_F(MissiveDaemonTest, ResponseWithErrorTest) {
  StartUp();
  WaitForReady();

  const Status error{error::INTERNAL, "Test generated error"};

  FlushPriorityRequest request;
  request.set_priority(SLOW_BATCH);

  EXPECT_CALL(*mock_missive_, FlushPriority(EqualsProto(request), _))
      .WillOnce([&error](const FlushPriorityRequest& in_request,
                         std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                             FlushPriorityResponse>> out_response) {
        FlushPriorityResponse response;
        error.SaveTo(response.mutable_status());
        out_response->Return(response);
      });

  auto response = std::make_unique<
      brillo::dbus_utils::MockDBusMethodResponse<FlushPriorityResponse>>();
  test::TestEvent<const FlushPriorityResponse&> response_event;
  response->set_return_callback(response_event.cb());
  missive_daemon_->FlushPriority(std::move(response), request);
  const auto& response_result = response_event.ref_result();
  EXPECT_THAT(response_result.status(),
              AllOf(Property(&StatusProto::code, Eq(error.error_code())),
                    Property(&StatusProto::error_message,
                             StrEq(std::string(error.error_message())))));
}

TEST_F(MissiveDaemonTest, UnavailableTest) {
  const Status failure_status =
      Status(error::UNAVAILABLE, "Test did not start daemon");
  test::TestEvent<Status> failure_event;
  StartUp(failure_status, failure_event.cb());
  const auto result = failure_event.result();
  ASSERT_THAT(
      result,
      AllOf(Property(&Status::error_code, Eq(error::UNAVAILABLE)),
            Property(&Status::error_message,
                     StrEq(std::string(failure_status.error_message())))))
      << result;

  FlushPriorityRequest request;
  request.set_priority(IMMEDIATE);

  EXPECT_CALL(*mock_missive_, FlushPriority(EqualsProto(request), _)).Times(0);

  auto response = std::make_unique<
      brillo::dbus_utils::MockDBusMethodResponse<FlushPriorityResponse>>();
  test::TestEvent<const FlushPriorityResponse&> response_event;
  response->set_return_callback(response_event.cb());
  missive_daemon_->FlushPriority(std::move(response), request);
  const auto& response_result = response_event.ref_result();
  EXPECT_THAT(response_result.status(),
              AllOf(Property(&StatusProto::code, Eq(error::UNAVAILABLE)),
                    Property(&StatusProto::error_message,
                             StrEq("The daemon is still starting."))));
}
}  // namespace
}  // namespace reporting
