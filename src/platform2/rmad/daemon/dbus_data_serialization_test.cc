// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/daemon/dbus_data_serialization.h"

#include <memory>

#include <gtest/gtest.h>

namespace {

using dbus::MessageReader;
using dbus::MessageWriter;
using dbus::Response;

using rmad::CalibrationComponentStatus;
using rmad::CalibrationOverallStatus;
using rmad::FinalizeStatus;
using rmad::HardwareVerificationResult;
using rmad::ProvisionStatus;
using rmad::RmadComponent;
using rmad::RmadErrorCode;
using rmad::UpdateRoFirmwareStatus;

struct TestStruct {
  int i;
};

}  // namespace

namespace brillo {
namespace dbus_utils {

template <>
struct DBusType<TestStruct> {
  static void Write(MessageWriter* writer, const TestStruct& value) {
    MessageWriter struct_writer(nullptr);
    writer->OpenStruct(&struct_writer);
    AppendValueToWriter(&struct_writer, value.i);
    writer->CloseContainer(&struct_writer);
  }
};

class DBusDataSerializationTest : public testing::Test {
 public:
  DBusDataSerializationTest() {}
};

TEST_F(DBusDataSerializationTest, RmadErrorCode_GetSignature) {
  EXPECT_EQ("i", DBusType<RmadErrorCode>::GetSignature());
}

TEST_F(DBusDataSerializationTest, RmadErrorCode_Write_Read_Success) {
  std::unique_ptr<Response> message = Response::CreateEmpty();

  MessageWriter writer(message.get());
  DBusType<RmadErrorCode>::Write(&writer, rmad::RMAD_ERROR_ABORT_FAILED);

  RmadErrorCode error_code;
  MessageReader reader(message.get());
  EXPECT_TRUE(DBusType<RmadErrorCode>::Read(&reader, &error_code));
  EXPECT_EQ(rmad::RMAD_ERROR_ABORT_FAILED, error_code);
}

TEST_F(DBusDataSerializationTest, RmadErrorCode_Read_NoData) {
  std::unique_ptr<Response> message = Response::CreateEmpty();

  RmadErrorCode error_code;
  MessageReader reader(message.get());
  EXPECT_FALSE(DBusType<RmadErrorCode>::Read(&reader, &error_code));
}

TEST_F(DBusDataSerializationTest, RmadErrorCode_Read_WrongData) {
  std::unique_ptr<Response> message = Response::CreateEmpty();

  MessageWriter writer(message.get());
  DBusType<TestStruct>::Write(&writer, {-1});

  RmadErrorCode error_code;
  MessageReader reader(message.get());
  EXPECT_FALSE(DBusType<RmadErrorCode>::Read(&reader, &error_code));
}

TEST_F(DBusDataSerializationTest, HardwareVerificationResult_GetSignature) {
  EXPECT_EQ("(bs)", DBusType<HardwareVerificationResult>::GetSignature());
}

TEST_F(DBusDataSerializationTest,
       HardwareVerificationResult_Write_Read_Success) {
  const bool is_compliant = true;
  const std::string error_str = "test_error_string";

  std::unique_ptr<Response> message = Response::CreateEmpty();
  HardwareVerificationResult result;
  result.set_is_compliant(is_compliant);
  result.set_error_str(error_str);

  MessageWriter writer(message.get());
  DBusType<HardwareVerificationResult>::Write(&writer, result);

  HardwareVerificationResult result_read;
  MessageReader reader(message.get());
  EXPECT_TRUE(
      DBusType<HardwareVerificationResult>::Read(&reader, &result_read));
  EXPECT_EQ(is_compliant, result_read.is_compliant());
  EXPECT_EQ(error_str, result_read.error_str());
}

TEST_F(DBusDataSerializationTest, HardwareVerificationResult_Read_NoData) {
  std::unique_ptr<Response> message = Response::CreateEmpty();

  HardwareVerificationResult result_read;
  MessageReader reader(message.get());
  EXPECT_FALSE(
      DBusType<HardwareVerificationResult>::Read(&reader, &result_read));
}

TEST_F(DBusDataSerializationTest, HardwareVerificationResult_Read_WrongData) {
  std::unique_ptr<Response> message = Response::CreateEmpty();

  MessageWriter writer(message.get());
  DBusType<TestStruct>::Write(&writer, {-1});

  HardwareVerificationResult result_read;
  MessageReader reader(message.get());
  EXPECT_FALSE(
      DBusType<HardwareVerificationResult>::Read(&reader, &result_read));
}

TEST_F(DBusDataSerializationTest, UpdateRoFirmwareStatus_GetSignature) {
  EXPECT_EQ("i", DBusType<UpdateRoFirmwareStatus>::GetSignature());
}

TEST_F(DBusDataSerializationTest, UpdateRoFirmwareStatus_Write_Read_Success) {
  std::unique_ptr<Response> message = Response::CreateEmpty();

  MessageWriter writer(message.get());
  DBusType<UpdateRoFirmwareStatus>::Write(
      &writer, rmad::RMAD_UPDATE_RO_FIRMWARE_COMPLETE);

  UpdateRoFirmwareStatus status_read;
  MessageReader reader(message.get());
  EXPECT_TRUE(DBusType<UpdateRoFirmwareStatus>::Read(&reader, &status_read));
  EXPECT_EQ(rmad::RMAD_UPDATE_RO_FIRMWARE_COMPLETE, status_read);
}

TEST_F(DBusDataSerializationTest, UpdateRoFirmwareStatus_Read_NoData) {
  std::unique_ptr<Response> message = Response::CreateEmpty();

  UpdateRoFirmwareStatus status_read;
  MessageReader reader(message.get());
  EXPECT_FALSE(DBusType<UpdateRoFirmwareStatus>::Read(&reader, &status_read));
}

TEST_F(DBusDataSerializationTest, UpdateRoFirmwareStatus_Read_WrongData) {
  std::unique_ptr<Response> message = Response::CreateEmpty();

  MessageWriter writer(message.get());
  DBusType<TestStruct>::Write(&writer, {-1});

  UpdateRoFirmwareStatus status_read;
  MessageReader reader(message.get());
  EXPECT_FALSE(DBusType<UpdateRoFirmwareStatus>::Read(&reader, &status_read));
}

TEST_F(DBusDataSerializationTest, CalibrationOverallStatus_GetSignature) {
  EXPECT_EQ("i", DBusType<CalibrationOverallStatus>::GetSignature());
}

TEST_F(DBusDataSerializationTest, CalibrationOverallStatus_Write_Read_Success) {
  std::unique_ptr<Response> message = Response::CreateEmpty();
  MessageWriter writer(message.get());
  DBusType<CalibrationOverallStatus>::Write(
      &writer, rmad::RMAD_CALIBRATION_OVERALL_COMPLETE);

  CalibrationOverallStatus status_read;
  MessageReader reader(message.get());
  EXPECT_TRUE(DBusType<CalibrationOverallStatus>::Read(&reader, &status_read));
  EXPECT_EQ(rmad::RMAD_CALIBRATION_OVERALL_COMPLETE, status_read);
}

TEST_F(DBusDataSerializationTest, CalibrationOverallStatus_Read_NoData) {
  std::unique_ptr<Response> message = Response::CreateEmpty();

  CalibrationOverallStatus status_read;
  MessageReader reader(message.get());
  EXPECT_FALSE(DBusType<CalibrationOverallStatus>::Read(&reader, &status_read));
}

TEST_F(DBusDataSerializationTest, CalibrationOverallStatus_Read_WrongData) {
  std::unique_ptr<Response> message = Response::CreateEmpty();

  MessageWriter writer(message.get());
  DBusType<TestStruct>::Write(&writer, {-1});

  CalibrationOverallStatus status_read;
  MessageReader reader(message.get());
  EXPECT_FALSE(DBusType<CalibrationOverallStatus>::Read(&reader, &status_read));
}

TEST_F(DBusDataSerializationTest, CalibrationComponentStatus_GetSignature) {
  EXPECT_EQ("(iid)", DBusType<CalibrationComponentStatus>::GetSignature());
}

TEST_F(DBusDataSerializationTest,
       CalibrationComponentStatus_Write_Read_Success) {
  const auto component = RmadComponent::RMAD_COMPONENT_BASE_ACCELEROMETER;
  const auto status = CalibrationComponentStatus::RMAD_CALIBRATION_IN_PROGRESS;
  const double progress = 0.3;

  std::unique_ptr<Response> message = Response::CreateEmpty();

  CalibrationComponentStatus component_status;
  component_status.set_component(component);
  component_status.set_status(status);
  component_status.set_progress(progress);

  MessageWriter writer(message.get());
  DBusType<CalibrationComponentStatus>::Write(&writer, component_status);

  CalibrationComponentStatus component_status_read;
  MessageReader reader(message.get());
  EXPECT_TRUE(DBusType<CalibrationComponentStatus>::Read(
      &reader, &component_status_read));
  EXPECT_EQ(component, component_status_read.component());
  EXPECT_EQ(status, component_status_read.status());
  EXPECT_EQ(progress, component_status_read.progress());
}

TEST_F(DBusDataSerializationTest, CalibrationComponentStatus_Read_NoData) {
  std::unique_ptr<Response> message = Response::CreateEmpty();

  CalibrationComponentStatus component_status_read;
  MessageReader reader(message.get());
  EXPECT_FALSE(DBusType<CalibrationComponentStatus>::Read(
      &reader, &component_status_read));
}

TEST_F(DBusDataSerializationTest, CalibrationComponentStatus_Read_WrongData) {
  std::unique_ptr<Response> message = Response::CreateEmpty();

  MessageWriter writer(message.get());
  DBusType<TestStruct>::Write(&writer, {-1});

  CalibrationComponentStatus component_status_read;
  MessageReader reader(message.get());
  EXPECT_FALSE(DBusType<CalibrationComponentStatus>::Read(
      &reader, &component_status_read));
}

TEST_F(DBusDataSerializationTest, ProvisionStatus_GetSignature) {
  EXPECT_EQ("(idi)", DBusType<ProvisionStatus>::GetSignature());
}

TEST_F(DBusDataSerializationTest, ProvisionStatus_Write_Read_Success) {
  const auto status = ProvisionStatus::RMAD_PROVISION_STATUS_IN_PROGRESS;
  const double progress = 0.5;
  const auto error = ProvisionStatus::RMAD_PROVISION_ERROR_INTERNAL;

  std::unique_ptr<Response> message = Response::CreateEmpty();
  ProvisionStatus provision_status;
  provision_status.set_status(status);
  provision_status.set_progress(0.5);
  provision_status.set_error(error);

  MessageWriter writer(message.get());
  DBusType<ProvisionStatus>::Write(&writer, provision_status);

  ProvisionStatus provision_status_read;
  MessageReader reader(message.get());
  EXPECT_TRUE(DBusType<ProvisionStatus>::Read(&reader, &provision_status_read));
  EXPECT_EQ(status, provision_status_read.status());
  EXPECT_EQ(progress, provision_status_read.progress());
  EXPECT_EQ(error, provision_status_read.error());
}

TEST_F(DBusDataSerializationTest, ProvisionStatus_Read_NoData) {
  std::unique_ptr<Response> message = Response::CreateEmpty();

  ProvisionStatus provision_status_read;
  MessageReader reader(message.get());
  EXPECT_FALSE(
      DBusType<ProvisionStatus>::Read(&reader, &provision_status_read));
}

TEST_F(DBusDataSerializationTest, ProvisionStatus_Read_WrongData) {
  std::unique_ptr<Response> message = Response::CreateEmpty();

  MessageWriter writer(message.get());
  DBusType<TestStruct>::Write(&writer, {-1});

  ProvisionStatus provision_status_read;
  MessageReader reader(message.get());
  EXPECT_FALSE(
      DBusType<ProvisionStatus>::Read(&reader, &provision_status_read));
}

TEST_F(DBusDataSerializationTest, FinalizeStatus_GetSignature) {
  EXPECT_EQ("(idi)", DBusType<FinalizeStatus>::GetSignature());
}

TEST_F(DBusDataSerializationTest, FinalizeStatus_Write_Read_Success) {
  const auto status = FinalizeStatus::RMAD_FINALIZE_STATUS_IN_PROGRESS;
  const double progress = 0.5;
  const auto error = FinalizeStatus::RMAD_FINALIZE_ERROR_INTERNAL;

  std::unique_ptr<Response> message = Response::CreateEmpty();
  FinalizeStatus finalize_status;
  finalize_status.set_status(status);
  finalize_status.set_progress(progress);
  finalize_status.set_error(error);

  MessageWriter writer(message.get());
  DBusType<FinalizeStatus>::Write(&writer, finalize_status);

  FinalizeStatus finalize_status_read;
  MessageReader reader(message.get());
  EXPECT_TRUE(DBusType<FinalizeStatus>::Read(&reader, &finalize_status_read));
  EXPECT_EQ(status, finalize_status_read.status());
  EXPECT_EQ(progress, finalize_status_read.progress());
  EXPECT_EQ(error, finalize_status_read.error());
}

TEST_F(DBusDataSerializationTest, FinalizeStatus_Read_NoData) {
  std::unique_ptr<Response> message = Response::CreateEmpty();

  FinalizeStatus finalize_status_read;
  MessageReader reader(message.get());
  EXPECT_FALSE(DBusType<FinalizeStatus>::Read(&reader, &finalize_status_read));
}

TEST_F(DBusDataSerializationTest, FinalizeStatus_Read_WrongData) {
  std::unique_ptr<Response> message = Response::CreateEmpty();

  MessageWriter writer(message.get());
  DBusType<TestStruct>::Write(&writer, {-1});

  FinalizeStatus finalize_status_read;
  MessageReader reader(message.get());
  EXPECT_FALSE(DBusType<FinalizeStatus>::Read(&reader, &finalize_status_read));
}

}  // namespace dbus_utils
}  // namespace brillo
