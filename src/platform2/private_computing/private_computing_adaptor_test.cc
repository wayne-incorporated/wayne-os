// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "private_computing/private_computing_adaptor.h"

#include <memory>
#include <string>
#include <vector>

#include <base/logging.h>

#include <gtest/gtest.h>
#include <dbus/object_path.h>
#include <brillo/dbus/dbus_object.h>
#include <base/files/scoped_temp_dir.h>
#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include <dbus/private_computing/dbus-constants.h>
#include <google/protobuf/message_lite.h>

#include "private_computing/proto_bindings/private_computing_service.pb.h"

namespace private_computing {

namespace {

constexpr char kObjectPath[] = "/object/path";

// Copy from private_computing_adaptor.cc for testing.
// Serializes |proto| to a vector of bytes.
std::vector<uint8_t> SerializeProto(
    const google::protobuf::MessageLite& proto) {
  std::vector<uint8_t> proto_blob(proto.ByteSizeLong());
  CHECK(proto.SerializeToArray(proto_blob.data(), proto_blob.size()));
  return proto_blob;
}

SaveStatusRequest GenerateSaveStatusRequest() {
  private_computing::ActiveStatus status;

  status.set_use_case(
      private_computing::PrivateComputingUseCase::CROS_FRESNEL_DAILY);

  std::string last_ping_pt_date = "2023-01-01";
  status.set_last_ping_date(last_ping_pt_date);

  SaveStatusRequest request;
  *request.add_active_status() = status;

  return request;
}
}  // namespace

class PrivateComputingAdaptorTest : public testing::Test {
 public:
  PrivateComputingAdaptorTest() {
    const dbus::ObjectPath object_path(kObjectPath);
    adaptor_ = std::make_unique<PrivateComputingAdaptor>(
        std::make_unique<brillo::dbus_utils::DBusObject>(nullptr, nullptr,
                                                         object_path));
  }

  explicit PrivateComputingAdaptorTest(const PrivateComputingAdaptor&) = delete;
  PrivateComputingAdaptorTest& operator=(const PrivateComputingAdaptorTest&) =
      delete;
  ~PrivateComputingAdaptorTest() override = default;

  PrivateComputingAdaptor* GetAdaptor() { return adaptor_.get(); }

 protected:
  std::unique_ptr<PrivateComputingAdaptor> adaptor_;
};

TEST_F(PrivateComputingAdaptorTest, WriteActiveStatusSuccessful) {
  base::FilePath file_path("/tmp/test");
  adaptor_->SetVarLibDirForTest(file_path);

  // Prepare the input test case.
  SaveStatusRequest request = GenerateSaveStatusRequest();
  std::string request_str = request.SerializeAsString();
  std::vector<uint8_t> request_blob = SerializeProto(request);

  std::vector<uint8_t> actual_blob =
      adaptor_->SaveLastPingDatesStatus(request_blob);

  SaveStatusResponse response;
  std::vector<uint8_t> expected_blob = SerializeProto(response);

  // If call SaveLastPingDatesStatus successfully, it will return
  // an empty SaveStatusResponse proto, which blob size is 0..
  EXPECT_EQ(actual_blob.size(), 0);
  EXPECT_EQ(actual_blob.size(), expected_blob.size());

  base::DeleteFile(file_path);
}

TEST_F(PrivateComputingAdaptorTest, ReadFromVarLibDir) {
  base::FilePath var_lib_path("/tmp/test1");
  adaptor_->SetVarLibDirForTest(var_lib_path);

  // Prepare the input test case.
  SaveStatusRequest request = GenerateSaveStatusRequest();
  std::string request_str = request.SerializeAsString();
  std::vector<uint8_t> request_blob = SerializeProto(request);

  adaptor_->SaveLastPingDatesStatus(request_blob);
  std::vector<uint8_t> actual_response_blob =
      adaptor_->GetLastPingDatesStatus();

  GetStatusResponse expect_response;
  *expect_response.mutable_active_status() = request.active_status();
  std::vector<uint8_t> expect_response_blob = SerializeProto(expect_response);

  // GetStatusResponse shouldn't empty.
  EXPECT_GT(actual_response_blob.size(), 0);
  EXPECT_EQ(actual_response_blob.size(), expect_response_blob.size());
  base::DeleteFile(var_lib_path);
}

TEST_F(PrivateComputingAdaptorTest, ReadFromPreserveDir) {
  base::FilePath preserve_path("/tmp/test2");
  adaptor_->SetPreserveDirForTest(preserve_path);
  base::File file(preserve_path,
                  base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);

  // Prepare the input test case.
  SaveStatusRequest request = GenerateSaveStatusRequest();
  std::string request_str = request.SerializeAsString();
  const int write_count =
      file.Write(0, request_str.c_str(), request_str.size());
  EXPECT_GT(write_count, 0);

  std::vector<uint8_t> actual_response_blob =
      adaptor_->GetLastPingDatesStatus();

  GetStatusResponse expect_response;
  *expect_response.mutable_active_status() = request.active_status();
  std::vector<uint8_t> expect_response_blob = SerializeProto(expect_response);

  EXPECT_GT(actual_response_blob.size(), 0);
  EXPECT_EQ(actual_response_blob.size(), expect_response_blob.size());
  base::DeleteFile(preserve_path);
}

TEST_F(PrivateComputingAdaptorTest, ReadActiveStatusFailed) {
  std::vector<uint8_t> actual_response_blob =
      adaptor_->GetLastPingDatesStatus();

  GetStatusResponse expect_response;
  expect_response.set_error_message(
      "PSM: Neither from /var/lib or the preserved file");
  std::vector<uint8_t> expect_response_blob = SerializeProto(expect_response);

  EXPECT_TRUE(actual_response_blob.size() == expect_response_blob.size());
}
}  // namespace private_computing
