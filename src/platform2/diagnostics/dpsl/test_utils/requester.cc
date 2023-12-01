// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// See help usage message in main() for basic description.

#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <utility>

#include <brillo/flag_helper.h>
#include <google/protobuf/message.h>

#include "diagnostics/dpsl/public/dpsl_global_context.h"
#include "diagnostics/dpsl/public/dpsl_requester.h"
#include "diagnostics/dpsl/public/dpsl_thread_context.h"
#include "diagnostics/dpsl/test_utils/common.h"

#include "wilco_dtc_supportd.pb.h"  // NOLINT(build/include_directory)

namespace diagnostics {
namespace {

// A member function of DpslRequester, used to call a gRPC method which
// takes a |Request| as a parameter and returns a |Response| via a callback.
template <typename Request, typename Response>
using GrpcRequestFunction = void (DpslRequester::*)(
    std::unique_ptr<Request>, std::function<void(std::unique_ptr<Response>)>);

// Used to make gRPC requests to wilco_dtc_supportd.
// Parse the supplied |request_json| to a proto of type |Request|, and then
// call the provided |request_function| on the |requester| with that
// |Request| as the argument. The result proto of type |Response| is passed to
// the |callback| method.
template <typename Request, typename Response>
bool MakeRequest(
    DpslRequester* requester,
    GrpcRequestFunction<Request, Response> request_function,
    const std::string& request_json,
    std::function<void(std::unique_ptr<google::protobuf::Message>)> callback) {
  auto request = test_utils::JsonToProto<Request>(request_json);
  if (!request) {
    return false;
  }

  ((*requester).*request_function)(std::move(request), callback);
  return true;
}

}  // namespace
}  // namespace diagnostics

int main(int argc, char** argv) {
  DEFINE_string(message_name, "",
                "Name of gRPC request to make. Options are:"
                "GetAvailableRoutines,"
                "GetConfigurationData,"
                "GetDriveSystemData,"
                "GetEcTelemetry,"
                "GetOsVersion,"
                "GetProcData,"
                "GetRoutineUpdate,"
                "GetStatefulPartitionAvailableCapacity,"
                "GetSysfsData,"
                "GetVpdField,"
                "PerformWebRequest,"
                "RunRoutine,"
                "SendMessageToUi");
  DEFINE_string(message_body, "",
                "JSON-formatted body of proto to send as argument of request");
  constexpr char kUsageMessage[] =
      R"(DPSL Requester Utility
Command line utility to test DPSL communication into and out of a VM. The
utility sends an outgoing gRPC request to wilco_dtc_supportd and prints the
returned response. The response is printed as JSON, so you can see both the name
and the actual content of the proto.

EXAMPLE USAGE
(VM)$ diagnostics_dpsl_test_requester \
    --message_name=GetEcTelemetry --message_body='{"payload":"OAAE"}'
{
   "body": {
      "payload": "AABFcnIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      "status": "STATUS_OK"
   },
   "name": "GetEcTelemetryResponse"
})";
  brillo::FlagHelper::Init(argc, argv, kUsageMessage);

  if (FLAGS_message_name.empty() || FLAGS_message_body.empty()) {
    std::cerr << "Both --message_name and --message_body must be provided\n";
    return EXIT_FAILURE;
  }

  auto global_context = diagnostics::DpslGlobalContext::Create();
  auto thread_context =
      diagnostics::DpslThreadContext::Create(global_context.get());
  auto requester = diagnostics::DpslRequester::Create(
      thread_context.get(),
      diagnostics::DpslRequester::GrpcClientUri::kVmVsock);
  if (!requester) {
    std::cerr << "Failed to create DpslRequester\n";
    return EXIT_FAILURE;
  }

  // Set up our callback that will be called when the response is received.
  bool response_succeeded = false;
  auto callback = [&response_succeeded, &thread_context](
                      std::unique_ptr<google::protobuf::Message> response) {
    if (!response) {
      std::cerr << "DPSL reports that request failed\n";
      response_succeeded = false;
    } else {
      response_succeeded = diagnostics::test_utils::PrintProto(*response);
    }
    thread_context->QuitEventLoop();
  };

  bool request_succeeded = false;
  if (FLAGS_message_name == "GetAvailableRoutines") {
    request_succeeded = diagnostics::MakeRequest(
        requester.get(), &diagnostics::DpslRequester::GetAvailableRoutines,
        FLAGS_message_body, callback);
  } else if (FLAGS_message_name == "GetConfigurationData") {
    request_succeeded = diagnostics::MakeRequest(
        requester.get(), &diagnostics::DpslRequester::GetConfigurationData,
        FLAGS_message_body, callback);
  } else if (FLAGS_message_name == "GetDriveSystemData") {
    request_succeeded = diagnostics::MakeRequest(
        requester.get(), &diagnostics::DpslRequester::GetDriveSystemData,
        FLAGS_message_body, callback);
  } else if (FLAGS_message_name == "GetEcTelemetry") {
    request_succeeded = diagnostics::MakeRequest(
        requester.get(), &diagnostics::DpslRequester::GetEcTelemetry,
        FLAGS_message_body, callback);
  } else if (FLAGS_message_name == "GetOsVersion") {
    request_succeeded = diagnostics::MakeRequest(
        requester.get(), &diagnostics::DpslRequester::GetOsVersion,
        FLAGS_message_body, callback);
  } else if (FLAGS_message_name == "GetProcData") {
    request_succeeded = diagnostics::MakeRequest(
        requester.get(), &diagnostics::DpslRequester::GetProcData,
        FLAGS_message_body, callback);
  } else if (FLAGS_message_name == "GetRoutineUpdate") {
    request_succeeded = diagnostics::MakeRequest(
        requester.get(), &diagnostics::DpslRequester::GetRoutineUpdate,
        FLAGS_message_body, callback);
  } else if (FLAGS_message_name == "GetStatefulPartitionAvailableCapacity") {
    request_succeeded = diagnostics::MakeRequest(
        requester.get(),
        &diagnostics::DpslRequester::GetStatefulPartitionAvailableCapacity,
        FLAGS_message_body, callback);
  } else if (FLAGS_message_name == "GetSysfsData") {
    request_succeeded = diagnostics::MakeRequest(
        requester.get(), &diagnostics::DpslRequester::GetSysfsData,
        FLAGS_message_body, callback);
  } else if (FLAGS_message_name == "GetVpdField") {
    request_succeeded = diagnostics::MakeRequest(
        requester.get(), &diagnostics::DpslRequester::GetVpdField,
        FLAGS_message_body, callback);
  } else if (FLAGS_message_name == "PerformWebRequest") {
    request_succeeded = diagnostics::MakeRequest(
        requester.get(), &diagnostics::DpslRequester::PerformWebRequest,
        FLAGS_message_body, callback);
  } else if (FLAGS_message_name == "RequestBluetoothDataNotification") {
    request_succeeded = diagnostics::MakeRequest(
        requester.get(),
        &diagnostics::DpslRequester::RequestBluetoothDataNotification,
        FLAGS_message_body, callback);
  } else if (FLAGS_message_name == "RunRoutine") {
    request_succeeded = diagnostics::MakeRequest(
        requester.get(), &diagnostics::DpslRequester::RunRoutine,
        FLAGS_message_body, callback);
  } else if (FLAGS_message_name == "SendMessageToUi") {
    request_succeeded = diagnostics::MakeRequest(
        requester.get(), &diagnostics::DpslRequester::SendMessageToUi,
        FLAGS_message_body, callback);
  } else {
    std::cerr
        << "Provided --message_name did not match any available gRPC request\n";
    return EXIT_FAILURE;
  }
  if (!request_succeeded) {
    std::cerr << "Failed to send request\n";
    return EXIT_FAILURE;
  }

  // Blocks until |thread_context->QuitEventLoop()| in |callback| is called.
  thread_context->RunEventLoop();

  return response_succeeded ? EXIT_SUCCESS : EXIT_FAILURE;
}
