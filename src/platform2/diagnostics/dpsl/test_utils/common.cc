// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/dpsl/test_utils/common.h"

#include <iostream>
#include <memory>
#include <string>
#include <utility>

#include <base/json/json_reader.h>
#include <base/json/json_writer.h>
#include <base/values.h>
#include <google/protobuf/message.h>
#include <google/protobuf/util/json_util.h>

namespace diagnostics {
namespace test_utils {

bool PrintProto(const google::protobuf::Message& message) {
  // Convert the Proto to JSON.
  std::string body_json;
  auto status =
      google::protobuf::util::MessageToJsonString(message, &body_json);
  if (!status.ok()) {
    std::cerr << "Failed to convert proto to JSON: " << status << "\n";
    return false;
  }

  // Then convert the JSON back to a base::Value.
  auto body = base::JSONReader::Read(body_json);
  if (!body) {
    std::cerr << "Failed to parse JSON to base::Value: " << body_json << '\n';
    return false;
  }

  // Embed the body and name of the proto in a base::Value.
  base::Value::Dict value;
  value.Set("name", message.GetDescriptor()->name());
  value.Set("body", std::move(*body));

  // Serialize the base::Value back to JSON.
  std::string message_json;
  base::JSONWriter::WriteWithOptions(
      value, base::JSONWriter::OPTIONS_PRETTY_PRINT, &message_json);
  std::cout << message_json << std::endl;

  return true;
}

}  // namespace test_utils
}  // namespace diagnostics
