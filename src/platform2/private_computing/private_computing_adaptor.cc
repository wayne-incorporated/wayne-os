// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "private_computing/private_computing_adaptor.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/strings/strcat.h>
#include <brillo/dbus/dbus_object.h>
#include <brillo/errors/error.h>
#include <dbus/private_computing/dbus-constants.h>
#include <google/protobuf/message_lite.h>

#include "private_computing/proto_bindings/private_computing_service.pb.h"

namespace private_computing {

namespace {

// Path to preserved file used to read the last ping dates after powerwash.
const char kPrivateComputingLastActiveDatesReadPath[] =
    "/mnt/stateful_partition/unencrypted/preserve/last_active_dates";

// Path to file storing the last ping dates as serialized object
// private_computing_service::SaveStatusRequest.
const char kPrivateComputingLastActiveDatesWritePath[] =
    "/var/lib/private_computing/last_active_dates";

// Serializes |proto| to a vector of bytes.
std::vector<uint8_t> SerializeProto(
    const google::protobuf::MessageLite& proto) {
  std::vector<uint8_t> proto_blob(proto.ByteSizeLong());
  CHECK(proto.SerializeToArray(proto_blob.data(), proto_blob.size()));
  return proto_blob;
}

// Parses a proto from an array of bytes |proto_blob|. Returns
// error message or empty string if no error.
std::string ParseProto(const base::Location& from_here,
                       google::protobuf::MessageLite* proto,
                       const std::vector<uint8_t>& proto_blob) {
  if (!proto->ParseFromArray(proto_blob.data(), proto_blob.size())) {
    const std::string error_message = "Failed to parse proto message.";
    LOG(ERROR) << from_here.ToString() << " " << error_message;
    return error_message;
  }
  return "";
}

std::optional<std::string> ReadActiveStatusFile(
    const base::FilePath& filePath) {
  base::File file(filePath, base::File::FLAG_OPEN | base::File::FLAG_READ);

  if (!file.IsValid()) {
    return std::nullopt;
  }

  base::File::Info file_info;
  if (!file.GetInfo(&file_info) || file_info.size <= 0) {
    return std::nullopt;
  }

  std::string result;
  result.resize(file_info.size);
  const int read_result =
      file.Read(/* offset */ 0, result.data(), file_info.size);

  if (read_result != file_info.size) {
    return std::nullopt;
  }

  return result;
}

}  // namespace

PrivateComputingAdaptor::PrivateComputingAdaptor(
    std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object)
    : org::chromium::PrivateComputingAdaptor(this),
      dbus_object_(std::move(dbus_object)),
      var_lib_dir_(kPrivateComputingLastActiveDatesWritePath),
      preserve_dir_(kPrivateComputingLastActiveDatesReadPath) {}

void PrivateComputingAdaptor::RegisterAsync(
    brillo::dbus_utils::AsyncEventSequencer::CompletionAction
        completion_callback) {
  RegisterWithDBusObject(dbus_object_.get());
  dbus_object_->RegisterAsync(std::move(completion_callback));
}

std::vector<uint8_t> PrivateComputingAdaptor::SaveLastPingDatesStatus(
    const std::vector<uint8_t>& request_blob) {
  LOG(INFO) << "Save the last ping dates to file.";
  SaveStatusRequest request;
  std::string error_message = ParseProto(FROM_HERE, &request, request_blob);

  SaveStatusResponse response;
  if (!error_message.empty()) {
    response.set_error_message(error_message);
    return SerializeProto(response);
  }

  // Write serialized request to |kPrivateComputingLastActiveDatesWritePath|
  base::File file(var_lib_dir_,
                  base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);

  if (!file.IsValid()) {
    response.set_error_message(
        "Failed to retrieve last_active_dates file descriptor.");
    return SerializeProto(response);
  }

  std::string request_str = request.SerializeAsString();
  const int write_count =
      file.Write(0, request_str.c_str(), request_str.size());
  if (write_count < 0 ||
      static_cast<size_t>(write_count) < request_str.size()) {
    response.set_error_message(
        base::StrCat({"Failed to write data file ",
                      kPrivateComputingLastActiveDatesWritePath,
                      " write count=", std::to_string(write_count)}));
    return SerializeProto(response);
  }

  LOG(INFO)
      << "Successfully saved last ping date to /var/lib/private_computing.";
  return SerializeProto(response);
}

std::vector<uint8_t> PrivateComputingAdaptor::GetLastPingDatesStatus() {
  // First try to read from `/var/lib/private_computing` folder.
  // Because this file will be updated after every successfully ping.
  // If this file exists, then it will be the latest value.
  std::optional<std::string> result_string = ReadActiveStatusFile(var_lib_dir_);

  GetStatusResponse response;

  if (!result_string) {
    LOG(ERROR) << "PSM: Cannot read from "
               << kPrivateComputingLastActiveDatesWritePath;

    // Next try to read from preserved file if reading from var/lib failed,
    // which means the device was powerwashed/recovery/new device. If the
    // device was powerwashed, then the preserved file should be existed.
    // If the device was recovery/new device, reading from preserved file
    // should be failed as well.
    result_string = ReadActiveStatusFile(preserve_dir_);

    if (!result_string) {
      LOG(ERROR) << "PSM: Cannot read from "
                 << kPrivateComputingLastActiveDatesReadPath;

      // Cannot read neither from /var/lib or preserved file, then return
      // the response with error message.
      response.set_error_message(
          "PSM: Neither from /var/lib or the preserved file");
      return SerializeProto(response);
    }
  }

  LOG(INFO) << "PSM: Successfully read from /var/lib or /preserved file.";

  // Successfully read file into |result_string|.
  SaveStatusRequest request;

  if (!request.ParseFromString(result_string.value())) {
    response.set_error_message(
        base::StrCat({"Failed to parse result string as a SaveStatusRequest ",
                      kPrivateComputingLastActiveDatesReadPath}));
    return SerializeProto(response);
  }

  *response.mutable_active_status() = request.active_status();

  return SerializeProto(response);
}

}  // namespace private_computing
