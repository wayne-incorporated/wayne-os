// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <functional>
#include <limits>
#include <memory>
#include <string>
#include <utility>

#include <base/barrier_closure.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/sequence_checker.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/grpc/async_grpc_server.h>
#include <gmock/gmock.h>
#include <google/protobuf/util/message_differencer.h>
#include <gtest/gtest.h>

#include "diagnostics/constants/grpc_constants.h"
#include "diagnostics/dpsl/internal/dpsl_global_context_impl.h"
#include "diagnostics/dpsl/internal/dpsl_requester_impl.h"
#include "diagnostics/dpsl/internal/dpsl_thread_context_impl.h"
#include "diagnostics/dpsl/internal/protobuf_test_utils.h"
#include "diagnostics/dpsl/internal/test_dpsl_background_thread.h"
#include "diagnostics/dpsl/public/dpsl_global_context.h"
#include "diagnostics/dpsl/public/dpsl_requester.h"
#include "diagnostics/dpsl/public/dpsl_thread_context.h"

namespace diagnostics {
namespace {

TEST(GetWilcoDtcSupportdGrpcUriTestDeathTest, InvalidValue) {
  constexpr auto kInvalidUri = static_cast<DpslRequester::GrpcClientUri>(
      std::numeric_limits<
          std::underlying_type<DpslRequester::GrpcClientUri>::type>::max());
#ifdef NDEBUG
  // In release builds the error is signaled by returning an empty URI.
  EXPECT_EQ(DpslRequesterImpl::GetWilcoDtcSupportdGrpcUri(kInvalidUri), "");
#else
  // In debug builds an assertion crash is expected.
  ASSERT_DEATH(DpslRequesterImpl::GetWilcoDtcSupportdGrpcUri(kInvalidUri),
               "Unexpected GrpcClientUri");
#endif
}

TEST(GetWilcoDtcSupportdGrpcUriTest, Unix) {
  EXPECT_EQ(DpslRequesterImpl::GetWilcoDtcSupportdGrpcUri(
                DpslRequester::GrpcClientUri::kLocalDomainSocket),
            "unix:/run/wilco_dtc/grpc_sockets/wilco_dtc_supportd_socket");
}

TEST(GetWilcoDtcSupportdGrpcUriTest, Vsock) {
  EXPECT_EQ(DpslRequesterImpl::GetWilcoDtcSupportdGrpcUri(
                DpslRequester::GrpcClientUri::kVmVsock),
            "vsock:2:6666");  // VMADDR_CID_HOST:kWilcoDtcSupportdPort
}

class DpslRequesterImplTest : public testing::Test {
 public:
  DpslRequesterImplTest() = default;
  DpslRequesterImplTest(const DpslRequesterImplTest&) = delete;
  DpslRequesterImplTest& operator=(const DpslRequesterImplTest&) = delete;

  ~DpslRequesterImplTest() override {
    DpslThreadContextImpl::CleanThreadCounterForTesting();
    DpslGlobalContextImpl::CleanGlobalCounterForTesting();
  }

  void SetUp() override {
    global_context_ = DpslGlobalContext::Create();
    ASSERT_TRUE(global_context_);

    main_thread_context_ = DpslThreadContext::Create(global_context_.get());
    ASSERT_TRUE(main_thread_context_);
  }

 protected:
  std::unique_ptr<DpslGlobalContext> global_context_;
  std::unique_ptr<DpslThreadContext> main_thread_context_;
};

class DpslRequesterImplDeathTest : public DpslRequesterImplTest {
 public:
  DpslRequesterImplDeathTest() {
    ::testing::FLAGS_gtest_death_test_style = "threadsafe";
  }
  DpslRequesterImplDeathTest(const DpslRequesterImplDeathTest&) = delete;
  DpslRequesterImplDeathTest& operator=(const DpslRequesterImplDeathTest&) =
      delete;

  ~DpslRequesterImplDeathTest() override = default;
};

TEST_F(DpslRequesterImplDeathTest, CreateWithNullThreadContext) {
  ASSERT_DEATH(DpslRequester::Create(
                   nullptr, DpslRequester::GrpcClientUri::kLocalDomainSocket),
               "Thread context is nullptr");
}

TEST_F(DpslRequesterImplDeathTest, CreateWithInvalidThreadContext) {
  TestDpslBackgroundThread background_thread(
      "background", global_context_.get(), main_thread_context_.get());
  ASSERT_DEATH(
      DpslRequester::Create(background_thread.thread_context(),
                            DpslRequester::GrpcClientUri::kLocalDomainSocket),
      "Thread context does not belong to the current thread");
}

TEST_F(DpslRequesterImplDeathTest, CreateWithInvalidServerUri) {
  // Set the maximum possible value to make sure it isn't valid
  constexpr auto kInvalidUri = static_cast<DpslRequester::GrpcClientUri>(
      std::numeric_limits<
          std::underlying_type<DpslRequester::GrpcClientUri>::type>::max());
#ifdef NDEBUG
  // In release builds the error is signaled by returning null.
  EXPECT_FALSE(DpslRequester::Create(main_thread_context_.get(), kInvalidUri));
#else
  // In debug builds an assertion crash is expected.
  EXPECT_DEATH(DpslRequester::Create(main_thread_context_.get(), kInvalidUri),
               "Unexpected GrpcClientUri");
#endif
}

// Generic template for the type of a member function of DpslRequesterImpl
template <typename Request, typename Response>
using RequesterMethod = void (DpslRequesterImpl::*)(
    std::unique_ptr<Request>, std::function<void(std::unique_ptr<Response>)>);

// This structure is passed to the DpslRequesterImplServerTest typed test.
// RequestTemplate and ResponseTemplate are used to parametrize the test and
// the following functions.
// MethodTemplate (as a value) is the method to call on DpslRequesterImpl.
// RequestRpcFunctionTemplate (as a value) is the grpc server function
// that needs to be implemented in the test server to respond to the client
// request. Due to the way protobuf generates these methods, each has a
// different base class and there is no type they all share.
// RequestRpcFunctionType needs to be specified using decltype.
template <typename RequestTemplate,
          typename ResponseTemplate,
          RequesterMethod<RequestTemplate, ResponseTemplate> MethodTemplate,
          typename RequestRpcFunctionType,
          RequestRpcFunctionType RequestRpcFunctionTemplate>
struct DpslRequesterImplServerTestParam {
  using Request = RequestTemplate;
  using Response = ResponseTemplate;
  using Method = RequesterMethod<Request, Response>;

  static constexpr Method MethodValue = MethodTemplate;
  static constexpr RequestRpcFunctionType RequestRpcFunctionValue =
      RequestRpcFunctionTemplate;
};

void FillProtobufForTest(grpc_api::SendMessageToUiRequest* req) {
  req->set_json_message("{}");
}

void FillProtobufForTest(grpc_api::SendMessageToUiResponse* res) {
  res->set_response_json_message("{}");
}

using SendMessageToUiTestParam = DpslRequesterImplServerTestParam<
    grpc_api::SendMessageToUiRequest,
    grpc_api::SendMessageToUiResponse,
    &DpslRequesterImpl::SendMessageToUi,
    decltype(&grpc_api::WilcoDtcSupportd::AsyncService::RequestSendMessageToUi),
    &grpc_api::WilcoDtcSupportd::AsyncService::RequestSendMessageToUi>;

void FillProtobufForTest(grpc_api::GetProcDataRequest* req) {
  req->set_type(grpc_api::GetProcDataRequest_Type_FILE_STAT);
}

void FillProtobufForTest(grpc_api::GetProcDataResponse* res) {
  auto* file = res->mutable_file_dump()->Add();

  file->set_path("/path");
  file->set_canonical_path("/path");
  file->set_contents("content");
}

using GetProcDataTestParam = DpslRequesterImplServerTestParam<
    grpc_api::GetProcDataRequest,
    grpc_api::GetProcDataResponse,
    &DpslRequesterImpl::GetProcData,
    decltype(&grpc_api::WilcoDtcSupportd::AsyncService::RequestGetProcData),
    &grpc_api::WilcoDtcSupportd::AsyncService::RequestGetProcData>;

void FillProtobufForTest(grpc_api::GetSysfsDataRequest* req) {
  req->set_type(grpc_api::GetSysfsDataRequest_Type_CLASS_THERMAL);
}

void FillProtobufForTest(grpc_api::GetSysfsDataResponse* res) {
  auto* file = res->mutable_file_dump()->Add();

  file->set_path("/path");
  file->set_canonical_path("/path");
  file->set_contents("content");
}

using GetSysfsDataTestParam = DpslRequesterImplServerTestParam<
    grpc_api::GetSysfsDataRequest,
    grpc_api::GetSysfsDataResponse,
    &DpslRequesterImpl::GetSysfsData,
    decltype(&grpc_api::WilcoDtcSupportd::AsyncService::RequestGetSysfsData),
    &grpc_api::WilcoDtcSupportd::AsyncService::RequestGetSysfsData>;

void FillProtobufForTest(grpc_api::PerformWebRequestParameter* req) {
  req->set_url("https://www.google.com");
  req->set_http_method(
      grpc_api::PerformWebRequestParameter_HttpMethod_HTTP_METHOD_GET);
}

void FillProtobufForTest(grpc_api::PerformWebRequestResponse* res) {
  res->set_response_body("\0Fake response\n with body\n\0");
  res->set_http_status(200);
  res->set_status(grpc_api::PerformWebRequestResponse_Status_STATUS_OK);
}

using PerformWebRequestTestParam = DpslRequesterImplServerTestParam<
    grpc_api::PerformWebRequestParameter,
    grpc_api::PerformWebRequestResponse,
    &DpslRequesterImpl::PerformWebRequest,
    decltype(&grpc_api::WilcoDtcSupportd::AsyncService::
                 RequestPerformWebRequest),
    &grpc_api::WilcoDtcSupportd::AsyncService::RequestPerformWebRequest>;

void FillProtobufForTest(grpc_api::GetEcTelemetryRequest* req) {
  req->set_payload("req");
}

void FillProtobufForTest(grpc_api::GetEcTelemetryResponse* res) {
  res->set_status(grpc_api::GetEcTelemetryResponse_Status_STATUS_OK);
  res->set_payload("res");
}

using GetEcTelemetryTestParam = DpslRequesterImplServerTestParam<
    grpc_api::GetEcTelemetryRequest,
    grpc_api::GetEcTelemetryResponse,
    &DpslRequesterImpl::GetEcTelemetry,
    decltype(&grpc_api::WilcoDtcSupportd::AsyncService::RequestGetEcTelemetry),
    &grpc_api::WilcoDtcSupportd::AsyncService::RequestGetEcTelemetry>;

void FillProtobufForTest(grpc_api::GetAvailableRoutinesRequest* req) {
  // Message has no fields
}

void FillProtobufForTest(grpc_api::GetAvailableRoutinesResponse* res) {
  res->add_routines(grpc_api::ROUTINE_BATTERY);
  res->add_routines(grpc_api::ROUTINE_URANDOM);
}

using GetAvailableRoutinesTestParam = DpslRequesterImplServerTestParam<
    grpc_api::GetAvailableRoutinesRequest,
    grpc_api::GetAvailableRoutinesResponse,
    &DpslRequesterImpl::GetAvailableRoutines,
    decltype(&grpc_api::WilcoDtcSupportd::AsyncService::
                 RequestGetAvailableRoutines),
    &grpc_api::WilcoDtcSupportd::AsyncService::RequestGetAvailableRoutines>;

void FillProtobufForTest(grpc_api::RunRoutineRequest* req) {
  req->set_routine(grpc_api::ROUTINE_URANDOM);
  req->mutable_urandom_params()->set_length_seconds(5);
}

void FillProtobufForTest(grpc_api::RunRoutineResponse* res) {
  res->set_uuid(1234);
  res->set_status(grpc_api::ROUTINE_STATUS_RUNNING);
}

using RunRoutineTestParam = DpslRequesterImplServerTestParam<
    grpc_api::RunRoutineRequest,
    grpc_api::RunRoutineResponse,
    &DpslRequesterImpl::RunRoutine,
    decltype(&grpc_api::WilcoDtcSupportd::AsyncService::RequestRunRoutine),
    &grpc_api::WilcoDtcSupportd::AsyncService::RequestRunRoutine>;

void FillProtobufForTest(grpc_api::GetRoutineUpdateRequest* req) {
  req->set_uuid(423);
  req->set_command(grpc_api::GetRoutineUpdateRequest_Command_CANCEL);
}

void FillProtobufForTest(grpc_api::GetRoutineUpdateResponse* res) {
  res->set_uuid(423);
  res->set_status(grpc_api::ROUTINE_STATUS_CANCELLED);
  res->set_progress_percent(20);
  res->set_output("log");
}

using GetRoutineUpdateTestParam = DpslRequesterImplServerTestParam<
    grpc_api::GetRoutineUpdateRequest,
    grpc_api::GetRoutineUpdateResponse,
    &DpslRequesterImpl::GetRoutineUpdate,
    decltype(&grpc_api::WilcoDtcSupportd::AsyncService::
                 RequestGetRoutineUpdate),
    &grpc_api::WilcoDtcSupportd::AsyncService::RequestGetRoutineUpdate>;

void FillProtobufForTest(grpc_api::GetOsVersionRequest*) {
  // Message has no fields
}

void FillProtobufForTest(grpc_api::GetOsVersionResponse* res) {
  res->set_version("11932.0.0");
  res->set_milestone(59);
}

using GetOsVersionTestParam = DpslRequesterImplServerTestParam<
    grpc_api::GetOsVersionRequest,
    grpc_api::GetOsVersionResponse,
    &DpslRequesterImpl::GetOsVersion,
    decltype(&grpc_api::WilcoDtcSupportd::AsyncService::RequestGetOsVersion),
    &grpc_api::WilcoDtcSupportd::AsyncService::RequestGetOsVersion>;

void FillProtobufForTest(grpc_api::GetConfigurationDataRequest* req) {
  // Message has no fields
}

void FillProtobufForTest(grpc_api::GetConfigurationDataResponse* res) {
  res->set_json_configuration_data("{}");
}

using GetConfigurationDataTestParam = DpslRequesterImplServerTestParam<
    grpc_api::GetConfigurationDataRequest,
    grpc_api::GetConfigurationDataResponse,
    &DpslRequesterImpl::GetConfigurationData,
    decltype(&grpc_api::WilcoDtcSupportd::AsyncService::
                 RequestGetConfigurationData),
    &grpc_api::WilcoDtcSupportd::AsyncService::RequestGetConfigurationData>;

void FillProtobufForTest(grpc_api::GetVpdFieldRequest* req) {
  req->set_vpd_field(grpc_api::GetVpdFieldRequest_VpdField_FIELD_SERIAL_NUMBER);
}

void FillProtobufForTest(grpc_api::GetVpdFieldResponse* res) {
  res->set_status(grpc_api::GetVpdFieldResponse_Status_STATUS_OK);
  res->set_vpd_field_value("1122334455");
}

using GetVpdFieldTestParam = DpslRequesterImplServerTestParam<
    grpc_api::GetVpdFieldRequest,
    grpc_api::GetVpdFieldResponse,
    &DpslRequesterImpl::GetVpdField,
    decltype(&grpc_api::WilcoDtcSupportd::AsyncService::RequestGetVpdField),
    &grpc_api::WilcoDtcSupportd::AsyncService::RequestGetVpdField>;

void FillProtobufForTest(grpc_api::GetDriveSystemDataRequest* req) {
  req->set_type(grpc_api::GetDriveSystemDataRequest_Type_SMART_ATTRIBUTES);
}

void FillProtobufForTest(grpc_api::GetDriveSystemDataResponse* res) {
  res->set_status(grpc_api::GetDriveSystemDataResponse_Status_STATUS_OK);
  res->set_payload("bytes");
}

using GetDriveSystemDataTestParam = DpslRequesterImplServerTestParam<
    grpc_api::GetDriveSystemDataRequest,
    grpc_api::GetDriveSystemDataResponse,
    &DpslRequesterImpl::GetDriveSystemData,
    decltype(&grpc_api::WilcoDtcSupportd::AsyncService::
                 RequestGetDriveSystemData),
    &grpc_api::WilcoDtcSupportd::AsyncService::RequestGetDriveSystemData>;

void FillProtobufForTest(
    grpc_api::RequestBluetoothDataNotificationRequest* req) {
  // Message has no fields
}

void FillProtobufForTest(
    grpc_api::RequestBluetoothDataNotificationResponse* res) {
  // Message has no fields
}

using RequestBluetoothDataNotificationTestParam =
    DpslRequesterImplServerTestParam<
        grpc_api::RequestBluetoothDataNotificationRequest,
        grpc_api::RequestBluetoothDataNotificationResponse,
        &DpslRequesterImpl::RequestBluetoothDataNotification,
        decltype(&grpc_api::WilcoDtcSupportd::AsyncService::
                     RequestRequestBluetoothDataNotification),
        &grpc_api::WilcoDtcSupportd::AsyncService::
            RequestRequestBluetoothDataNotification>;

void FillProtobufForTest(
    grpc_api::GetStatefulPartitionAvailableCapacityRequest* req) {
  // Message has no fields
}

void FillProtobufForTest(
    grpc_api::GetStatefulPartitionAvailableCapacityResponse* res) {
  res->set_status(
      grpc_api::GetStatefulPartitionAvailableCapacityResponse_Status_STATUS_OK);
  res->set_available_capacity_mb(4200);
}

using GetStatefulPartitionAvailableCapacityTestParam =
    DpslRequesterImplServerTestParam<
        grpc_api::GetStatefulPartitionAvailableCapacityRequest,
        grpc_api::GetStatefulPartitionAvailableCapacityResponse,
        &DpslRequesterImpl::GetStatefulPartitionAvailableCapacity,
        decltype(&grpc_api::WilcoDtcSupportd::AsyncService::
                     RequestGetStatefulPartitionAvailableCapacity),
        &grpc_api::WilcoDtcSupportd::AsyncService::
            RequestGetStatefulPartitionAvailableCapacity>;

class TestDsplMultiRequesterServer {
 public:
  explicit TestDsplMultiRequesterServer(const std::string& uri)
      : async_grpc_server_(base::SingleThreadTaskRunner::GetCurrentDefault(),
                           {uri}) {
    async_grpc_server_.RegisterHandler(
        &grpc_api::WilcoDtcSupportd::AsyncService::RequestSendMessageToUi,
        base::BindRepeating(
            &TestDsplMultiRequesterServer::HandleSendMessageToUiCallbackCall,
            base::Unretained(this)));

    async_grpc_server_.RegisterHandler(
        &grpc_api::WilcoDtcSupportd::AsyncService::RequestPerformWebRequest,
        base::BindRepeating(
            &TestDsplMultiRequesterServer::HandlePerformWebRequest,
            base::Unretained(this)));
  }
  TestDsplMultiRequesterServer(const TestDsplMultiRequesterServer&) = delete;
  TestDsplMultiRequesterServer& operator=(const TestDsplMultiRequesterServer&) =
      delete;

  ~TestDsplMultiRequesterServer() {
    base::RunLoop run_loop;
    async_grpc_server_.ShutDown(run_loop.QuitClosure());
    run_loop.Run();
  }

  bool Start() { return async_grpc_server_.Start(); }

  void SetSendMessageToUiExpectedRequest(
      const grpc_api::SendMessageToUiRequest& request) {
    send_message_to_ui_expected_request_ = request;
  }

  void SetSendMessageToUiResponseToReplyWith(
      const grpc_api::SendMessageToUiResponse& response) {
    send_message_to_ui_response_to_reply_with_ = response;
  }

  void SetPerformWebRequestExpectedRequest(
      const grpc_api::PerformWebRequestParameter& request) {
    perform_web_request_expected_request_ = request;
  }

  void SetPerformWebRequestResponseToReplyWith(
      const grpc_api::PerformWebRequestResponse& response) {
    perform_web_request_response_to_reply_with_ = response;
  }

  int GetSendMessageToUiHandleCalled() const {
    return handle_send_message_to_ui_called_;
  }

  int GetPerformWebRequestHandleCalled() const {
    return handle_perform_web_request_called_;
  }

 private:
  using HandleSendMessageToUiCallback = base::OnceCallback<void(
      grpc::Status, std::unique_ptr<grpc_api::SendMessageToUiResponse>)>;

  using HandlePerformWebRequestCallback = base::OnceCallback<void(
      grpc::Status, std::unique_ptr<grpc_api::PerformWebRequestResponse>)>;

  void HandleSendMessageToUiCallbackCall(
      std::unique_ptr<grpc_api::SendMessageToUiRequest> request,
      HandleSendMessageToUiCallback callback) {
    EXPECT_THAT(*request, ProtobufEquals(send_message_to_ui_expected_request_));

    handle_send_message_to_ui_called_++;

    std::move(callback).Run(grpc::Status::OK,
                            std::make_unique<grpc_api::SendMessageToUiResponse>(
                                send_message_to_ui_response_to_reply_with_));
  }

  void HandlePerformWebRequest(
      std::unique_ptr<grpc_api::PerformWebRequestParameter> request,
      HandlePerformWebRequestCallback callback) {
    EXPECT_THAT(*request,
                ProtobufEquals(perform_web_request_expected_request_));

    handle_perform_web_request_called_++;

    std::move(callback).Run(
        grpc::Status::OK, std::make_unique<grpc_api::PerformWebRequestResponse>(
                              perform_web_request_response_to_reply_with_));
  }

  grpc_api::SendMessageToUiRequest send_message_to_ui_expected_request_;
  grpc_api::SendMessageToUiResponse send_message_to_ui_response_to_reply_with_;

  grpc_api::PerformWebRequestParameter perform_web_request_expected_request_;
  grpc_api::PerformWebRequestResponse
      perform_web_request_response_to_reply_with_;

  int handle_send_message_to_ui_called_ = 0;
  int handle_perform_web_request_called_ = 0;

  brillo::AsyncGrpcServer<grpc_api::WilcoDtcSupportd::AsyncService>
      async_grpc_server_;
};

class DpslRequesterImplWithRequesterTest : public DpslRequesterImplTest {
 public:
  DpslRequesterImplWithRequesterTest() = default;
  DpslRequesterImplWithRequesterTest(
      const DpslRequesterImplWithRequesterTest&) = delete;
  DpslRequesterImplWithRequesterTest& operator=(
      const DpslRequesterImplWithRequesterTest&) = delete;

  ~DpslRequesterImplWithRequesterTest() override = default;

  void SetUp() override {
    DpslRequesterImplTest::SetUp();

    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());

    requester_ = std::make_unique<DpslRequesterImpl>(GetUriString());
  }

 protected:
  std::string GetUriString() const {
    return base::StringPrintf("unix:%s/test_wilco_dtc_suportd_socket",
                              temp_dir_.GetPath().value().c_str());
  }

  base::ScopedTempDir temp_dir_;
  std::unique_ptr<DpslRequesterImpl> requester_;
};

TEST_F(DpslRequesterImplWithRequesterTest, MultiRequest) {
  grpc_api::SendMessageToUiRequest request1;
  grpc_api::SendMessageToUiResponse response1;

  grpc_api::PerformWebRequestParameter request2;
  grpc_api::PerformWebRequestResponse response2;

  FillProtobufForTest(&request1);
  FillProtobufForTest(&response1);
  FillProtobufForTest(&request2);
  FillProtobufForTest(&response2);

  TestDsplMultiRequesterServer server(GetUriString());
  ASSERT_TRUE(server.Start());

  server.SetSendMessageToUiExpectedRequest(request1);
  server.SetSendMessageToUiResponseToReplyWith(response1);
  server.SetPerformWebRequestExpectedRequest(request2);
  server.SetPerformWebRequestResponseToReplyWith(response2);

  auto quit_closure =
      base::BarrierClosure(2, base::BindOnce(
                                  [](DpslThreadContext* main_thread_context) {
                                    main_thread_context->QuitEventLoop();
                                  },
                                  main_thread_context_.get()));

  requester_->SendMessageToUi(
      std::make_unique<grpc_api::SendMessageToUiRequest>(request1),
      [&, response1](auto response_ptr) {
        ASSERT_TRUE(response_ptr);
        ASSERT_TRUE(main_thread_context_->BelongsToCurrentThread());
        EXPECT_THAT(*response_ptr, ProtobufEquals(response1));

        quit_closure.Run();
      });

  requester_->PerformWebRequest(
      std::make_unique<grpc_api::PerformWebRequestParameter>(request2),
      [&, response2](auto response_ptr) {
        ASSERT_TRUE(response_ptr);
        ASSERT_TRUE(main_thread_context_->BelongsToCurrentThread());
        EXPECT_THAT(*response_ptr, ProtobufEquals(response2));

        quit_closure.Run();
      });

  main_thread_context_->RunEventLoop();

  EXPECT_EQ(server.GetSendMessageToUiHandleCalled(), 1);
  EXPECT_EQ(server.GetPerformWebRequestHandleCalled(), 1);
}

namespace {

template <typename TestParam>
class TestDsplRequesterServer {
 public:
  using Request = typename TestParam::Request;
  using Response = typename TestParam::Response;

  explicit TestDsplRequesterServer(const std::string& uri)
      : async_grpc_server_(base::SingleThreadTaskRunner::GetCurrentDefault(),
                           {uri}) {
    async_grpc_server_.RegisterHandler(
        TestParam::RequestRpcFunctionValue,
        base::BindRepeating(&TestDsplRequesterServer::HandleCall,
                            base::Unretained(this)));
  }
  TestDsplRequesterServer(const TestDsplRequesterServer&) = delete;
  TestDsplRequesterServer& operator=(const TestDsplRequesterServer&) = delete;

  ~TestDsplRequesterServer() {
    base::RunLoop run_loop;
    async_grpc_server_.ShutDown(run_loop.QuitClosure());
    run_loop.Run();
  }

  bool Start() { return async_grpc_server_.Start(); }

  void SetExpectedRequest(const Request& request) {
    expected_request_ = request;
  }

  void SetResponseToReplyWith(const Response& response) {
    response_to_reply_with_ = response;
  }

  int GetHandleCallCalled() const { return handle_call_called_; }

 private:
  using HandleCallCallback =
      base::OnceCallback<void(grpc::Status, std::unique_ptr<Response>)>;

  void HandleCall(std::unique_ptr<Request> request,
                  HandleCallCallback callback) {
    EXPECT_THAT(*request, ProtobufEquals(expected_request_));

    handle_call_called_++;

    std::move(callback).Run(
        grpc::Status::OK, std::make_unique<Response>(response_to_reply_with_));
  }

  Request expected_request_;
  Response response_to_reply_with_;

  int handle_call_called_ = 0;

  brillo::AsyncGrpcServer<grpc_api::WilcoDtcSupportd::AsyncService>
      async_grpc_server_;
};

}  // namespace

template <typename TestParam>
class DpslRequesterImplServerTest : public DpslRequesterImplWithRequesterTest {
 public:
  using Request = typename TestParam::Request;
  using Response = typename TestParam::Response;

  DpslRequesterImplServerTest() = default;
  DpslRequesterImplServerTest(const DpslRequesterImplServerTest&) = delete;
  DpslRequesterImplServerTest& operator=(const DpslRequesterImplServerTest&) =
      delete;

  ~DpslRequesterImplServerTest() override = default;

  void SetUp() override {
    DpslRequesterImplWithRequesterTest::SetUp();

    server_ =
        std::make_unique<TestDsplRequesterServer<TestParam>>(GetUriString());
    ASSERT_TRUE(server_->Start());
  }

  void PerformRequest(const Request& request, const Response& response) {
    auto handler = [&, response](auto response_ptr) {
      // The handler should always run on the creation thread.
      ASSERT_TRUE(main_sequence_checker_.CalledOnValidSequence());

      ASSERT_TRUE(response_ptr);
      ASSERT_TRUE(main_thread_context_->BelongsToCurrentThread());
      ASSERT_THAT(*response_ptr, ProtobufEquals(response));

      // Note that this might be a no-op: in case we run before the test body
      // calls RunEventLoop(). This is possible, because some tests spin
      // additional run loops, like the one in
      // TestDpslBackgroundThread::DoSync().
      main_thread_context_->QuitEventLoop();
      ++responses_received_;
    };

    ((*requester_).*(TestParam::MethodValue))(
        std::make_unique<Request>(request), handler);
  }

 protected:
  base::SequenceChecker main_sequence_checker_;
  std::unique_ptr<TestDsplRequesterServer<TestParam>> server_;
  int responses_received_ = 0;
};

using DpslRequesterImplServerTestTypes =
    ::testing::Types<SendMessageToUiTestParam,
                     GetProcDataTestParam,
                     GetSysfsDataTestParam,
                     PerformWebRequestTestParam,
                     GetEcTelemetryTestParam,
                     GetAvailableRoutinesTestParam,
                     RunRoutineTestParam,
                     GetRoutineUpdateTestParam,
                     GetOsVersionTestParam,
                     GetConfigurationDataTestParam,
                     GetVpdFieldTestParam,
                     GetDriveSystemDataTestParam,
                     RequestBluetoothDataNotificationTestParam,
                     GetStatefulPartitionAvailableCapacityTestParam>;
TYPED_TEST_SUITE(DpslRequesterImplServerTest, DpslRequesterImplServerTestTypes);

TYPED_TEST(DpslRequesterImplServerTest, CallGrpcMethodFromMainThread) {
  typename TypeParam::Request request;
  FillProtobufForTest(&request);
  typename TypeParam::Response response;
  FillProtobufForTest(&response);

  this->server_->SetExpectedRequest(request);
  this->server_->SetResponseToReplyWith(response);
  this->PerformRequest(request, response);

  this->main_thread_context_->RunEventLoop();

  EXPECT_EQ(this->server_->GetHandleCallCalled(), 1);
}

TYPED_TEST(DpslRequesterImplServerTest, CallGrpcMethodFromBackgroundThread) {
  typename TypeParam::Request request;
  FillProtobufForTest(&request);
  typename TypeParam::Response response;
  FillProtobufForTest(&response);

  this->server_->SetExpectedRequest(request);
  this->server_->SetResponseToReplyWith(response);

  TestDpslBackgroundThread background_thread("background",
                                             this->global_context_.get(),
                                             this->main_thread_context_.get());
  background_thread.StartEventLoop();
  background_thread.DoSync(base::BindOnce(
      &TestFixture::PerformRequest, base::Unretained(this), request, response));

  // Only spin an event loop in case the response hasn't been handled yet, to
  // avoid hanging here: the handler might've been executed by the run loop that
  // DoSync() spins. The check of responses_received_ is not racy, because this
  // counter is updated on the main thread.
  if (!this->responses_received_)
    this->main_thread_context_->RunEventLoop();

  EXPECT_EQ(this->responses_received_, 1);
  EXPECT_EQ(this->server_->GetHandleCallCalled(), 1);
}

}  // namespace
}  // namespace diagnostics
