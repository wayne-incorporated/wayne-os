// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_DAEMON_DBUS_DATA_SERIALIZATION_H_
#define RMAD_DAEMON_DBUS_DATA_SERIALIZATION_H_

#include <string>

#include <brillo/dbus/data_serialization.h>

#include "rmad/proto_bindings/rmad.pb.h"

namespace brillo {
namespace dbus_utils {

void AppendValueToWriter(dbus::MessageWriter* writer,
                         const rmad::HardwareVerificationResult& value);
void AppendValueToWriter(dbus::MessageWriter* writer,
                         const rmad::CalibrationComponentStatus& value);
void AppendValueToWriter(dbus::MessageWriter* writer,
                         const rmad::ProvisionStatus& value);
void AppendValueToWriter(dbus::MessageWriter* writer,
                         const rmad::FinalizeStatus& value);
bool PopValueFromReader(dbus::MessageReader* reader,
                        rmad::HardwareVerificationResult* value);
bool PopValueFromReader(dbus::MessageReader* reader,
                        rmad::CalibrationComponentStatus* value);
bool PopValueFromReader(dbus::MessageReader* reader,
                        rmad::ProvisionStatus* value);
bool PopValueFromReader(dbus::MessageReader* reader,
                        rmad::FinalizeStatus* value);

// DBusType definition for signals.
template <>
struct DBusType<rmad::RmadErrorCode> {
  static std::string GetSignature();
  static void Write(dbus::MessageWriter* writer,
                    const rmad::RmadErrorCode value);
  static bool Read(dbus::MessageReader* reader, rmad::RmadErrorCode* value);
};

template <>
struct DBusType<rmad::HardwareVerificationResult> {
  static std::string GetSignature();
  static void Write(dbus::MessageWriter* writer,
                    const rmad::HardwareVerificationResult& value);
  static bool Read(dbus::MessageReader* reader,
                   rmad::HardwareVerificationResult* value);
};

template <>
struct DBusType<rmad::UpdateRoFirmwareStatus> {
  static std::string GetSignature();
  static void Write(dbus::MessageWriter* writer,
                    const rmad::UpdateRoFirmwareStatus status);
  static bool Read(dbus::MessageReader* reader,
                   rmad::UpdateRoFirmwareStatus* status);
};

template <>
struct DBusType<rmad::CalibrationOverallStatus> {
  static std::string GetSignature();
  static void Write(dbus::MessageWriter* writer,
                    const rmad::CalibrationOverallStatus value);
  static bool Read(dbus::MessageReader* reader,
                   rmad::CalibrationOverallStatus* value);
};

template <>
struct DBusType<rmad::CalibrationComponentStatus> {
  static std::string GetSignature();
  static void Write(dbus::MessageWriter* writer,
                    const rmad::CalibrationComponentStatus& value);
  static bool Read(dbus::MessageReader* reader,
                   rmad::CalibrationComponentStatus* value);
};

template <>
struct DBusType<rmad::ProvisionStatus> {
  static std::string GetSignature();
  static void Write(dbus::MessageWriter* writer,
                    const rmad::ProvisionStatus& value);
  static bool Read(dbus::MessageReader* reader, rmad::ProvisionStatus* value);
};

template <>
struct DBusType<rmad::FinalizeStatus> {
  static std::string GetSignature();
  static void Write(dbus::MessageWriter* writer,
                    const rmad::FinalizeStatus& value);
  static bool Read(dbus::MessageReader* reader, rmad::FinalizeStatus* value);
};

}  // namespace dbus_utils
}  // namespace brillo

#endif  // RMAD_DAEMON_DBUS_DATA_SERIALIZATION_H_
