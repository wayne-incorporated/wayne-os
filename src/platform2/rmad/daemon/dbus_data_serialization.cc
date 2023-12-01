// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/daemon/dbus_data_serialization.h"

namespace brillo {
namespace dbus_utils {

using dbus::MessageReader;
using dbus::MessageWriter;

using rmad::CalibrationComponentStatus;
using rmad::CalibrationOverallStatus;
using rmad::FinalizeStatus;
using rmad::HardwareVerificationResult;
using rmad::ProvisionStatus;
using rmad::RmadComponent;
using rmad::RmadErrorCode;
using rmad::UpdateRoFirmwareStatus;

// Overload AppendValueToWriter() for |HardwareVerificationResult|,
// |CalibrationComponentStatus|, |ProvisionStatus| and |FinalizeStatus|
// structures.
void AppendValueToWriter(MessageWriter* writer,
                         const HardwareVerificationResult& value) {
  MessageWriter struct_writer(nullptr);
  writer->OpenStruct(&struct_writer);
  AppendValueToWriter(&struct_writer, value.is_compliant());
  AppendValueToWriter(&struct_writer, value.error_str());
  writer->CloseContainer(&struct_writer);
}

void AppendValueToWriter(MessageWriter* writer,
                         const CalibrationComponentStatus& value) {
  MessageWriter struct_writer(nullptr);
  writer->OpenStruct(&struct_writer);
  AppendValueToWriter(&struct_writer, static_cast<int>(value.component()));
  AppendValueToWriter(&struct_writer, static_cast<int>(value.status()));
  AppendValueToWriter(&struct_writer, value.progress());
  writer->CloseContainer(&struct_writer);
}

void AppendValueToWriter(MessageWriter* writer, const ProvisionStatus& value) {
  MessageWriter struct_writer(nullptr);
  writer->OpenStruct(&struct_writer);
  AppendValueToWriter(&struct_writer, static_cast<int>(value.status()));
  AppendValueToWriter(&struct_writer, value.progress());
  AppendValueToWriter(&struct_writer, static_cast<int>(value.error()));
  writer->CloseContainer(&struct_writer);
}

void AppendValueToWriter(MessageWriter* writer, const FinalizeStatus& value) {
  MessageWriter struct_writer(nullptr);
  writer->OpenStruct(&struct_writer);
  AppendValueToWriter(&struct_writer, static_cast<int>(value.status()));
  AppendValueToWriter(&struct_writer, value.progress());
  AppendValueToWriter(&struct_writer, static_cast<int>(value.error()));
  writer->CloseContainer(&struct_writer);
}

// Overload PopValueFromReader() for |HardwareVerificationResult|,
// |CalibrationComponentStatus|, |ProvisionStatus| and |FinalizeStatus|
// structures.
bool PopValueFromReader(MessageReader* reader,
                        HardwareVerificationResult* value) {
  MessageReader struct_reader(nullptr);
  if (!reader->PopStruct(&struct_reader)) {
    return false;
  }

  bool is_compliant;
  std::string error_str;
  if (!PopValueFromReader(&struct_reader, &is_compliant) ||
      !PopValueFromReader(&struct_reader, &error_str)) {
    return false;
  }
  value->set_is_compliant(is_compliant);
  value->set_error_str(error_str);
  return true;
}

bool PopValueFromReader(MessageReader* reader,
                        CalibrationComponentStatus* value) {
  MessageReader struct_reader(nullptr);
  if (!reader->PopStruct(&struct_reader)) {
    return false;
  }

  int component, status;
  double progress;
  if (!PopValueFromReader(&struct_reader, &component) ||
      !PopValueFromReader(&struct_reader, &status) ||
      !PopValueFromReader(&struct_reader, &progress)) {
    return false;
  }
  value->set_component(static_cast<RmadComponent>(component));
  value->set_status(
      static_cast<CalibrationComponentStatus::CalibrationStatus>(status));
  value->set_progress(progress);
  return true;
}

bool PopValueFromReader(MessageReader* reader, ProvisionStatus* value) {
  MessageReader struct_reader(nullptr);
  if (!reader->PopStruct(&struct_reader)) {
    return false;
  }

  int status;
  double progress;
  int error;
  if (!PopValueFromReader(&struct_reader, &status) ||
      !PopValueFromReader(&struct_reader, &progress) ||
      !PopValueFromReader(&struct_reader, &error)) {
    return false;
  }
  value->set_status(static_cast<ProvisionStatus::Status>(status));
  value->set_progress(progress);
  value->set_error(static_cast<ProvisionStatus::Error>(error));
  return true;
}

bool PopValueFromReader(MessageReader* reader, FinalizeStatus* value) {
  MessageReader struct_reader(nullptr);
  if (!reader->PopStruct(&struct_reader)) {
    return false;
  }

  int status;
  double progress;
  int error;
  if (!PopValueFromReader(&struct_reader, &status) ||
      !PopValueFromReader(&struct_reader, &progress) ||
      !PopValueFromReader(&struct_reader, &error)) {
    return false;
  }
  value->set_status(static_cast<FinalizeStatus::Status>(status));
  value->set_progress(progress);
  value->set_error(static_cast<FinalizeStatus::Error>(error));
  return true;
}

// DBusType<RmadErrorCode> specialization.
std::string DBusType<RmadErrorCode>::GetSignature() {
  return DBusType<int>::GetSignature();
}

void DBusType<RmadErrorCode>::Write(MessageWriter* writer,
                                    const RmadErrorCode value) {
  DBusType<int>::Write(writer, static_cast<int>(value));
}

bool DBusType<RmadErrorCode>::Read(MessageReader* reader,
                                   RmadErrorCode* value) {
  int v;
  if (DBusType<int>::Read(reader, &v)) {
    *value = static_cast<RmadErrorCode>(v);
    return true;
  } else {
    return false;
  }
}

// DBusType<HardwareVerificationResult> specialization.
std::string DBusType<HardwareVerificationResult>::GetSignature() {
  return GetStructDBusSignature<bool, std::string>();
}

void DBusType<HardwareVerificationResult>::Write(
    MessageWriter* writer, const HardwareVerificationResult& value) {
  AppendValueToWriter(writer, value);
}

bool DBusType<HardwareVerificationResult>::Read(
    MessageReader* reader, HardwareVerificationResult* value) {
  return PopValueFromReader(reader, value);
}

// DBusType<UpdateRoFirmwareStatus> specialization.
std::string DBusType<UpdateRoFirmwareStatus>::GetSignature() {
  return DBusType<int>::GetSignature();
}

void DBusType<UpdateRoFirmwareStatus>::Write(
    MessageWriter* writer, const UpdateRoFirmwareStatus status) {
  DBusType<int>::Write(writer, static_cast<int>(status));
}

bool DBusType<UpdateRoFirmwareStatus>::Read(MessageReader* reader,
                                            UpdateRoFirmwareStatus* status) {
  int v;
  if (DBusType<int>::Read(reader, &v)) {
    *status = static_cast<UpdateRoFirmwareStatus>(v);
    return true;
  } else {
    return false;
  }
}

// DBusType<CalibrationOverallStatus> specialization.
std::string DBusType<CalibrationOverallStatus>::GetSignature() {
  return DBusType<int>::GetSignature();
}

void DBusType<CalibrationOverallStatus>::Write(
    MessageWriter* writer, const CalibrationOverallStatus value) {
  DBusType<int>::Write(writer, static_cast<int>(value));
}

bool DBusType<CalibrationOverallStatus>::Read(MessageReader* reader,
                                              CalibrationOverallStatus* value) {
  int v;
  if (DBusType<int>::Read(reader, &v)) {
    *value = static_cast<CalibrationOverallStatus>(v);
    return true;
  } else {
    return false;
  }
}

// DBusType<CalibrationComponentStatus> specialization.
std::string DBusType<CalibrationComponentStatus>::GetSignature() {
  return GetStructDBusSignature<int, int, double>();
}

void DBusType<CalibrationComponentStatus>::Write(
    MessageWriter* writer, const CalibrationComponentStatus& value) {
  AppendValueToWriter(writer, value);
}

bool DBusType<CalibrationComponentStatus>::Read(
    MessageReader* reader, CalibrationComponentStatus* value) {
  return PopValueFromReader(reader, value);
}

// DBusType<ProvisionStatus> specialization.
std::string DBusType<ProvisionStatus>::GetSignature() {
  return GetStructDBusSignature<int, double, int>();
}

void DBusType<ProvisionStatus>::Write(MessageWriter* writer,
                                      const ProvisionStatus& value) {
  AppendValueToWriter(writer, value);
}

bool DBusType<ProvisionStatus>::Read(MessageReader* reader,
                                     ProvisionStatus* value) {
  return PopValueFromReader(reader, value);
}

// DBusType<FinalizeStatus> specialization.
std::string DBusType<FinalizeStatus>::GetSignature() {
  return GetStructDBusSignature<int, double, int>();
}

void DBusType<FinalizeStatus>::Write(MessageWriter* writer,
                                     const FinalizeStatus& value) {
  AppendValueToWriter(writer, value);
}

bool DBusType<FinalizeStatus>::Read(MessageReader* reader,
                                    FinalizeStatus* value) {
  return PopValueFromReader(reader, value);
}

}  // namespace dbus_utils
}  // namespace brillo
