// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits>
#include <memory>
#include <type_traits>

#include <base/check.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/grpc/async_grpc_client.h>
#include <gmock/gmock.h>
#include <google/protobuf/util/message_differencer.h>
#include <gtest/gtest.h>

#include "diagnostics/constants/grpc_constants.h"
#include "diagnostics/dpsl/internal/dpsl_global_context_impl.h"
#include "diagnostics/dpsl/internal/dpsl_rpc_server_impl.h"
#include "diagnostics/dpsl/internal/dpsl_thread_context_impl.h"
#include "diagnostics/dpsl/internal/protobuf_test_utils.h"
#include "diagnostics/dpsl/internal/test_dpsl_background_thread.h"
#include "diagnostics/dpsl/public/dpsl_global_context.h"
#include "diagnostics/dpsl/public/dpsl_rpc_handler.h"
#include "diagnostics/dpsl/public/dpsl_rpc_server.h"
#include "diagnostics/dpsl/public/dpsl_thread_context.h"
#include "diagnostics/dpsl/test_utils/common.h"

#include "wilco_dtc.grpc.pb.h"           // NOLINT(build/include_directory)
#include "wilco_dtc_supportd.grpc.pb.h"  // NOLINT(build/include_directory)

using testing::_;
using testing::ReturnRef;
using testing::StrictMock;

namespace diagnostics {
namespace {

constexpr DpslRpcServer::GrpcServerUri kGrpcServerUriInvalidValue =
    static_cast<DpslRpcServer::GrpcServerUri>(
        std::numeric_limits<
            std::underlying_type<DpslRpcServer::GrpcServerUri>::type>::max());

class MockDpslRpcHandler : public DpslRpcHandler {
 public:
  void HandleMessageFromUi(
      std::unique_ptr<grpc_api::HandleMessageFromUiRequest> request,
      HandleMessageFromUiCallback callback) override {
    DCHECK(request);
    callback(std::make_unique<grpc_api::HandleMessageFromUiResponse>(
        HandleMessageFromUiImpl(*request)));
  }

  void HandleEcNotification(
      std::unique_ptr<grpc_api::HandleEcNotificationRequest> request,
      HandleEcNotificationCallback callback) override {
    DCHECK(request);
    callback(std::make_unique<grpc_api::HandleEcNotificationResponse>(
        HandleEcNotificationImpl(*request)));
  }

  void HandlePowerNotification(
      std::unique_ptr<grpc_api::HandlePowerNotificationRequest> request,
      HandlePowerNotificationCallback callback) override {
    DCHECK(request);
    callback(std::make_unique<grpc_api::HandlePowerNotificationResponse>(
        HandlePowerNotificationImpl(*request)));
  }

  void HandleConfigurationDataChanged(
      std::unique_ptr<grpc_api::HandleConfigurationDataChangedRequest> request,
      HandleConfigurationDataChangedCallback callback) override {
    DCHECK(request);
    callback(std::make_unique<grpc_api::HandleConfigurationDataChangedResponse>(
        HandleConfigurationDataChangedImpl(*request)));
  }

  void HandleBluetoothDataChanged(
      std::unique_ptr<grpc_api::HandleBluetoothDataChangedRequest> request,
      HandleBluetoothDataChangedCallback callback) override {
    DCHECK(request);
    callback(std::make_unique<grpc_api::HandleBluetoothDataChangedResponse>(
        HandleBluetoothDataChangedImpl(*request)));
  }

  MOCK_METHOD(const grpc_api::HandleMessageFromUiResponse&,
              HandleMessageFromUiImpl,
              (const grpc_api::HandleMessageFromUiRequest& request));
  MOCK_METHOD(const grpc_api::HandleEcNotificationResponse&,
              HandleEcNotificationImpl,
              (const grpc_api::HandleEcNotificationRequest& request));
  MOCK_METHOD(const grpc_api::HandlePowerNotificationResponse&,
              HandlePowerNotificationImpl,
              (const grpc_api::HandlePowerNotificationRequest& request));
  MOCK_METHOD(const grpc_api::HandleConfigurationDataChangedResponse&,
              HandleConfigurationDataChangedImpl,
              (const grpc_api::HandleConfigurationDataChangedRequest& request));
  MOCK_METHOD(const grpc_api::HandleBluetoothDataChangedResponse&,
              HandleBluetoothDataChangedImpl,
              (const grpc_api::HandleBluetoothDataChangedRequest& request));
};

class DpslRpcServerImplBaseTest : public testing::Test {
 public:
  DpslRpcServerImplBaseTest() = default;
  DpslRpcServerImplBaseTest(const DpslRpcServerImplBaseTest&) = delete;
  DpslRpcServerImplBaseTest& operator=(const DpslRpcServerImplBaseTest&) =
      delete;

  ~DpslRpcServerImplBaseTest() override {
    DpslThreadContextImpl::CleanThreadCounterForTesting();
    DpslGlobalContextImpl::CleanGlobalCounterForTesting();
  }

  void SetUp() override {
    global_context_ = DpslGlobalContext::Create();
    ASSERT_TRUE(global_context_);
    thread_context_ = DpslThreadContext::Create(global_context_.get());
    ASSERT_TRUE(thread_context_);
  }

 protected:
  StrictMock<MockDpslRpcHandler> mock_handler_;

  std::unique_ptr<DpslGlobalContext> global_context_;
  std::unique_ptr<DpslThreadContext> thread_context_;
};

class DpslRpcServerImplBaseDeathTest : public DpslRpcServerImplBaseTest {
 public:
  DpslRpcServerImplBaseDeathTest() {
    // Using EXPECT_DEATH, gtest creates child process, which re-executes the
    // unit test binary just as it was originally invoked.
    // https://github.com/google/googletest/blob/HEAD/googletest/docs/advanced.md#how-it-works
    //
    // Otherwise, EXPECT_DEATH statement will be called in forked child
    // immediately. It means that at least
    // DpslThreadContextImpl::BelongsToCurrentThread does fail. But somehow
    // CHECK(sequence_checker_.CalledOnValidSequence()) does not.
    ::testing::FLAGS_gtest_death_test_style = "threadsafe";
  }
  DpslRpcServerImplBaseDeathTest(const DpslRpcServerImplBaseDeathTest&) =
      delete;
  DpslRpcServerImplBaseDeathTest& operator=(
      const DpslRpcServerImplBaseDeathTest&) = delete;
};

TEST_F(DpslRpcServerImplBaseDeathTest, CreateWithNullThreadContext) {
  EXPECT_DEATH(DpslRpcServer::Create(nullptr, &mock_handler_,
                                     DpslRpcServer::GrpcServerUri::kVmVsock),
               "Thread context is nullptr");
}

TEST_F(DpslRpcServerImplBaseDeathTest, CreateWithNullRpcHandler) {
  EXPECT_DEATH(DpslRpcServer::Create(thread_context_.get(), nullptr,
                                     DpslRpcServer::GrpcServerUri::kVmVsock),
               "Rpc handler is nullptr");
}

TEST_F(DpslRpcServerImplBaseDeathTest, CreateWithInvalidServerUri) {
#ifdef NDEBUG
  // In release builds the error is reported by returning null.
  EXPECT_FALSE(DpslRpcServer::Create(thread_context_.get(), &mock_handler_,
                                     kGrpcServerUriInvalidValue));
#else
  // In debug builds an assertion crash is expected.
  EXPECT_DEATH(DpslRpcServer::Create(thread_context_.get(), &mock_handler_,
                                     kGrpcServerUriInvalidValue),
               "Unexpected GrpcServerUri");
#endif
}

TEST_F(DpslRpcServerImplBaseDeathTest, MultiThreadInvalidThreadContext) {
  TestDpslBackgroundThread background_thread(
      "background", global_context_.get(), thread_context_.get());

  EXPECT_DEATH(
      DpslRpcServer::Create(background_thread.thread_context(), &mock_handler_,
                            kGrpcServerUriInvalidValue),
      "Called from wrong thread");
}

// This is a parameterized test with the following parameters:
// * |grpc_server_uri| - gRPC server URI.
class DpslRpcServerImplTest
    : public DpslRpcServerImplBaseTest,
      public testing::WithParamInterface<DpslRpcServer::GrpcServerUri> {
 public:
  DpslRpcServerImplTest() = default;
  DpslRpcServerImplTest(const DpslRpcServerImplTest&) = delete;
  DpslRpcServerImplTest& operator=(const DpslRpcServerImplTest&) = delete;

  DpslRpcServer::GrpcServerUri grpc_server_uri() const { return GetParam(); }
};

TEST_P(DpslRpcServerImplTest, CreateUsingVsock) {
  EXPECT_TRUE(DpslRpcServer::Create(thread_context_.get(), &mock_handler_,
                                    grpc_server_uri()));
}

TEST_P(DpslRpcServerImplTest, CreateUsingVsockTwiceOnAvailableAddress) {
  // DpslRpcServer will be destroyed before the next call.
  EXPECT_TRUE(DpslRpcServer::Create(thread_context_.get(), &mock_handler_,
                                    grpc_server_uri()));

  EXPECT_TRUE(DpslRpcServer::Create(thread_context_.get(), &mock_handler_,
                                    grpc_server_uri()));
}

TEST_P(DpslRpcServerImplTest, CreateUsingVsockTwiceOnInUseAddress) {
  auto dpsl_rpc_server = DpslRpcServer::Create(
      thread_context_.get(), &mock_handler_, grpc_server_uri());
  EXPECT_TRUE(dpsl_rpc_server);

  EXPECT_FALSE(DpslRpcServer::Create(thread_context_.get(), &mock_handler_,
                                     grpc_server_uri()));
}

INSTANTIATE_TEST_SUITE_P(
    ,
    DpslRpcServerImplTest,
    testing::Values(DpslRpcServer::GrpcServerUri::kVmVsock,
                    DpslRpcServer::GrpcServerUri::kUiMessageReceiverVmVsock));

// This is a parameterized test with the following parameters:
// * |grpc_server_uri| - gRPC server URI.
//
// Use UNIX socket for actual communication in tests between server(HOST) and
// client(HOST) since VSOCK can be used only for real HOST-VM communication.
//
// This class is still parameterized, because the behavior of DpslRpcServer
// depends on the URI.
class DpslRpcServerImplUnixSocketTest : public DpslRpcServerImplTest {
 public:
  DpslRpcServerImplUnixSocketTest() = default;
  DpslRpcServerImplUnixSocketTest(const DpslRpcServerImplUnixSocketTest&) =
      delete;
  DpslRpcServerImplUnixSocketTest& operator=(
      const DpslRpcServerImplUnixSocketTest&) = delete;

  ~DpslRpcServerImplUnixSocketTest() override = default;

  void SetUp() override {
    DpslRpcServerImplBaseTest::SetUp();

    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());

    dpsl_rpc_server_ = std::make_unique<DpslRpcServerImpl>(
        &mock_handler_, grpc_server_uri(), grpc_server_uri_string());
    ASSERT_TRUE(dpsl_rpc_server_->Init());

    wilco_dtc_grpc_client_ =
        std::make_unique<brillo::AsyncGrpcClient<grpc_api::WilcoDtc>>(
            base::SingleThreadTaskRunner::GetCurrentDefault(),
            grpc_server_uri_string());
  }

  void TearDown() override {
    wilco_dtc_grpc_client_->ShutDown(base::BindRepeating(
        [](DpslThreadContext* thread_context) {
          ASSERT_TRUE(thread_context);
          thread_context->QuitEventLoop();
        },
        thread_context_.get()));
    thread_context_->RunEventLoop();

    DpslRpcServerImplTest::TearDown();
  }

  std::string grpc_server_uri_string() const {
    return base::StringPrintf("unix:%s/test_wilco_dtc_socket",
                              temp_dir_.GetPath().value().c_str());
  }

  template <typename ClientRpcPtr,
            typename ProtoRequest,
            typename ProtoResponse>
  void SendGrpcRequestAndCheckResponse(const ClientRpcPtr client_rpc_ptr,
                                       const ProtoRequest& request,
                                       const ProtoResponse& response) {
    wilco_dtc_grpc_client_->CallRpc(
        client_rpc_ptr, request,
        base::BindOnce(
            [](DpslThreadContext* thread_context,
               const ProtoResponse& expected_response, grpc::Status status,
               std::unique_ptr<ProtoResponse> response) {
              ASSERT_TRUE(thread_context);
              EXPECT_TRUE(status.ok());
              ASSERT_TRUE(response);
              EXPECT_TRUE(google::protobuf::util::MessageDifferencer::Equals(
                  *response, expected_response));
              thread_context->QuitEventLoop();
            },
            thread_context_.get(), response));
    thread_context_->RunEventLoop();
  }

 protected:
  base::ScopedTempDir temp_dir_;

  std::unique_ptr<brillo::AsyncGrpcClient<grpc_api::WilcoDtc>>
      wilco_dtc_grpc_client_;
  std::unique_ptr<DpslRpcServerImpl> dpsl_rpc_server_;
};

TEST_P(DpslRpcServerImplUnixSocketTest, HandleMessageFromUi) {
  grpc_api::HandleMessageFromUiRequest request;
  request.set_json_message("{'message': 'ping'}");

  // Only RPC server which using kUiMessageReceiverVmVsock URI can receive
  // HandleMessageFromUiRequest messages.
  if (grpc_server_uri() !=
      DpslRpcServer::GrpcServerUri::kUiMessageReceiverVmVsock) {
    wilco_dtc_grpc_client_->CallRpc(
        &grpc_api::WilcoDtc::Stub::AsyncHandleMessageFromUi, request,
        base::BindOnce(
            [](DpslThreadContext* thread_context, grpc::Status status,
               std::unique_ptr<grpc_api::HandleMessageFromUiResponse>
                   response) {
              ASSERT_TRUE(thread_context);
              EXPECT_FALSE(status.ok());
              thread_context->QuitEventLoop();
            },
            thread_context_.get()));
    thread_context_->RunEventLoop();
    return;
  }

  grpc_api::HandleMessageFromUiResponse response;
  response.set_response_json_message("{'message': 'pong'}");

  EXPECT_CALL(mock_handler_, HandleMessageFromUiImpl(ProtobufEquals(request)))
      .WillOnce(ReturnRef(response));
  SendGrpcRequestAndCheckResponse(
      &grpc_api::WilcoDtc::Stub::AsyncHandleMessageFromUi, request, response);
}

TEST_P(DpslRpcServerImplUnixSocketTest, HandleEcNotification) {
  grpc_api::HandleEcNotificationRequest request;
  request.set_type(20);
  request.set_payload("abcdef");

  grpc_api::HandleEcNotificationResponse response;

  EXPECT_CALL(mock_handler_, HandleEcNotificationImpl(ProtobufEquals(request)))
      .WillOnce(ReturnRef(response));
  SendGrpcRequestAndCheckResponse(
      &grpc_api::WilcoDtc::Stub::AsyncHandleEcNotification, request, response);
}

TEST_P(DpslRpcServerImplUnixSocketTest, HandlePowerNotification) {
  grpc_api::HandlePowerNotificationRequest request;
  request.set_power_event(grpc_api::HandlePowerNotificationRequest::OS_SUSPEND);

  grpc_api::HandlePowerNotificationResponse response;

  EXPECT_CALL(mock_handler_,
              HandlePowerNotificationImpl(ProtobufEquals(request)))
      .WillOnce(ReturnRef(response));
  SendGrpcRequestAndCheckResponse(
      &grpc_api::WilcoDtc::Stub::AsyncHandlePowerNotification, request,
      response);
}

TEST_P(DpslRpcServerImplUnixSocketTest, HandleConfigurationDataChanged) {
  grpc_api::HandleConfigurationDataChangedRequest request;

  grpc_api::HandleConfigurationDataChangedResponse response;

  EXPECT_CALL(mock_handler_,
              HandleConfigurationDataChangedImpl(ProtobufEquals(request)))
      .WillOnce(ReturnRef(response));
  SendGrpcRequestAndCheckResponse(
      &grpc_api::WilcoDtc::Stub::AsyncHandleConfigurationDataChanged, request,
      response);
}

TEST_P(DpslRpcServerImplUnixSocketTest, HandleBluetoothDataChanged) {
  grpc_api::HandleBluetoothDataChangedRequest request;
  grpc_api::HandleBluetoothDataChangedRequest::AdapterData* adapter_data =
      request.add_adapters();

  adapter_data->set_adapter_name("sarien");
  adapter_data->set_adapter_mac_address("00:11:22:33:44:55");
  adapter_data->set_carrier_status(
      grpc_api::HandleBluetoothDataChangedRequest::AdapterData::STATUS_UP);
  adapter_data->set_connected_devices_count(1);

  grpc_api::HandleBluetoothDataChangedResponse response;

  EXPECT_CALL(mock_handler_,
              HandleBluetoothDataChangedImpl(ProtobufEquals(request)))
      .WillOnce(ReturnRef(response));
  SendGrpcRequestAndCheckResponse(
      &grpc_api::WilcoDtc::Stub::AsyncHandleBluetoothDataChanged, request,
      response);
}

INSTANTIATE_TEST_SUITE_P(
    ,
    DpslRpcServerImplUnixSocketTest,
    testing::Values(DpslRpcServer::GrpcServerUri::kVmVsock,
                    DpslRpcServer::GrpcServerUri::kUiMessageReceiverVmVsock));

}  // namespace
}  // namespace diagnostics
