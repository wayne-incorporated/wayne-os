// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_DPSL_TEST_UTILS_COMMON_H_
#define DIAGNOSTICS_DPSL_TEST_UTILS_COMMON_H_

#include <iostream>
#include <memory>
#include <string>

#include <google/protobuf/message.h>
#include <google/protobuf/util/json_util.h>

namespace diagnostics {
namespace test_utils {

// Prints a proto to std::cout as JSON, including the proto name and the body.
// Returns whether printing was successful.
//
// For message
// message GetOsVersionResponse {
//    string version = "12440.0.2019_08_20_1256"
// }
// The following is printed:
// {
//    "body": {
//       "version": "12440.0.2019_08_20_1256"
//    },
//    "name": "GetOsVersionResponse"
// }
// This format was chosen so that it could be deserialized back to a proto.
bool PrintProto(const google::protobuf::Message& message);

// Converts a JSON string to it's protobuf representation.
template <typename Proto>
std::unique_ptr<Proto> JsonToProto(const std::string& request_json) {
  auto request = std::make_unique<Proto>();
  auto status =
      google::protobuf::util::JsonStringToMessage(request_json, request.get());
  if (!status.ok()) {
    std::cerr << "Failed to parse '" << request_json << "' to "
              << Proto::descriptor()->name() << " proto: " << status << "\n";
    return nullptr;
  }
  return request;
}

}  // namespace test_utils
}  // namespace diagnostics

#endif  // DIAGNOSTICS_DPSL_TEST_UTILS_COMMON_H_
