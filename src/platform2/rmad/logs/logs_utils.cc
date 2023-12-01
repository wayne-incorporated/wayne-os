// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/logs/logs_utils.h"

#include <functional>
#include <map>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/json/json_string_value_serializer.h>
#include <base/memory/scoped_refptr.h>
#include <base/strings/strcat.h>
#include <base/strings/stringprintf.h>
#include <base/strings/string_util.h>
#include <base/time/time.h>
#include <base/values.h>

#include "rmad/constants.h"
#include "rmad/logs/logs_constants.h"
#include "rmad/proto_bindings/rmad.pb.h"
#include "rmad/utils/json_store.h"
#include "rmad/utils/type_conversions.h"

namespace rmad {

namespace {

const char* GetStateName(RmadState::StateCase state) {
  auto it = kStateNames.find(state);
  CHECK(it != kStateNames.end());
  return it->second.data();
}

std::string JoinValueList(
    const base::Value::List* list,
    const std::function<std::string(const base::Value&)>& function,
    const std::string& separator) {
  auto begin = list->begin();
  auto end = list->end();
  std::ostringstream list_stream;
  if (begin != end) {
    list_stream << function(*begin);
    while (++begin != end) {
      list_stream << separator << function(*begin);
    }
  }
  return list_stream.str();
}

bool AddEventToJson(scoped_refptr<JsonStore> json_store,
                    RmadState::StateCase state,
                    LogEventType event_type,
                    base::Value::Dict&& details) {
  base::Value::Dict event;
  event.Set(kTimestamp, base::Time::Now().ToDoubleT());
  event.Set(kStateId, static_cast<int>(state));
  event.Set(kType, static_cast<int>(event_type));
  event.Set(kDetails, std::move(details));

  base::Value logs(base::Value::Type::DICT);
  if (json_store->GetValue(kLogs, &logs)) {
    CHECK(logs.is_dict());
  }

  // EnsureList() returns a pointer to the `events` JSON so no need to add it
  // back to `logs`.
  base::Value::List* events = logs.GetDict().EnsureList(kEvents);
  events->Append(std::move(event));

  return json_store->SetValue(kLogs, std::move(logs));
}

std::string GetCalibrationStatusString(const base::Value::Dict& component) {
  const std::string component_name = *component.FindString(kLogComponent);
  const LogCalibrationStatus status = static_cast<LogCalibrationStatus>(
      component.FindInt(kLogCalibrationStatus).value());
  auto it = kLogCalibrationStatusMap.find(status);
  CHECK(it != kLogCalibrationStatusMap.end());
  return base::StrCat({component_name, " - ", it->second});
}

std::string GenerateTextLogString(scoped_refptr<JsonStore> json_store) {
  std::string generated_text_log;

  base::Value logs(base::Value::Type::DICT);
  json_store->GetValue(kLogs, &logs);
  const base::Value::List* events = logs.GetDict().FindList(kEvents);

  for (const base::Value& event : *events) {
    const base::Value::Dict& event_dict = event.GetDict();
    const int type = event_dict.FindInt(kType).value();
    const int current_state_id = event_dict.FindInt(kStateId).value();

    // Append the timestamp prefix.
    base::Time::Exploded exploded;
    base::Time::FromDoubleT(event_dict.FindDouble(kTimestamp).value())
        .LocalExplode(&exploded);
    generated_text_log.append(
        base::StringPrintf(kLogTimestampFormat, exploded.year, exploded.month,
                           exploded.day_of_month, exploded.hour,
                           exploded.minute, exploded.second));

    const base::Value::Dict* details = event_dict.FindDict(kDetails);
    switch (static_cast<LogEventType>(type)) {
      case LogEventType::kTransition: {
        const RmadState::StateCase from_state =
            static_cast<RmadState::StateCase>(
                details->FindInt(kFromStateId).value());
        const RmadState::StateCase to_state = static_cast<RmadState::StateCase>(
            details->FindInt(kToStateId).value());
        generated_text_log.append(base::StringPrintf(kLogTransitionFormat,
                                                     GetStateName(from_state),
                                                     GetStateName(to_state)));
        break;
      }
      case LogEventType::kError: {
        const RmadErrorCode error_code = static_cast<RmadErrorCode>(
            details->FindInt(kOccurredError).value());
        generated_text_log.append(base::StringPrintf(
            kLogErrorFormat,
            GetStateName(static_cast<RmadState::StateCase>(current_state_id)),
            RmadErrorCode_Name(error_code).c_str()));
        break;
      }
      case LogEventType::kData: {
        const RmadState::StateCase current_state =
            static_cast<RmadState::StateCase>(current_state_id);
        generated_text_log.append(base::StringPrintf(
            kLogDetailPrefixFormat, GetStateName(current_state)));

        switch (current_state) {
          case RmadState::kWelcome: {
            const std::optional<bool> is_compliant =
                details->FindBool(kLogIsCompliant);

            // `is_compliant` only has a value from the hardware verifier
            // event.
            if (is_compliant.has_value()) {
              if (is_compliant.value()) {
                generated_text_log.append(kLogNoUnqualifiedComponentsString);
              } else {
                const std::string unqualified_components =
                    *details->FindString(kLogUnqualifiedComponents);
                generated_text_log.append(
                    base::StringPrintf(kLogUnqualifiedComponentsDetectedFormat,
                                       unqualified_components.c_str()));
              }
            } else {
              generated_text_log.append(kLogRepairStartString);
            }
            break;
          }
          case RmadState::kComponentsRepair: {
            const bool is_mlb_repair =
                details->FindBool(kLogReworkSelected).value();
            if (is_mlb_repair) {
              generated_text_log.append(kLogSelectComponentsReworkString);
            } else {
              const base::Value::List* components =
                  details->FindList(kLogReplacedComponents);
              const std::string component_list = JoinValueList(
                  components,
                  [](const base::Value& value) { return value.GetString(); },
                  ", ");
              generated_text_log.append(base::StringPrintf(
                  kLogSelectComponentsFormat, component_list.c_str()));
            }
            break;
          }
          case RmadState::kDeviceDestination: {
            generated_text_log.append(base::StringPrintf(
                kLogChooseDeviceDestinationFormat,
                (*details->FindString(kLogDestination)).c_str()));
            break;
          }
          case RmadState::kWipeSelection: {
            const std::string wipe_device =
                details->FindBool(kLogWipeDevice).value() ? "wipe" : "keep";
            generated_text_log.append(base::StringPrintf(
                kLogWipeSelectionFormat, wipe_device.c_str()));
            break;
          }
          case RmadState::kWpDisableMethod: {
            generated_text_log.append(base::StringPrintf(
                kLogWpDisableFormat,
                (*details->FindString(kLogWpDisableMethod)).c_str()));
            break;
          }
          case RmadState::kWpDisableRsu: {
            generated_text_log.append(base::StringPrintf(
                kLogRsuChallengeFormat,
                (*details->FindString(kLogRsuChallengeCode)).c_str()));
            break;
          }
          case RmadState::kRestock: {
            generated_text_log.append(
                details->FindBool(kLogRestockOption).value()
                    ? kLogRestockShutdownString
                    : kLogRestockContinueString);
            break;
          }
          case RmadState::kSetupCalibration: {
            std::string instruction_string;
            const CalibrationSetupInstruction setup_instruction =
                static_cast<CalibrationSetupInstruction>(
                    details->FindInt(kLogCalibrationSetupInstruction).value());
            switch (setup_instruction) {
              case RMAD_CALIBRATION_INSTRUCTION_PLACE_BASE_ON_FLAT_SURFACE: {
                instruction_string = kLogCalibrationSetupBaseString;
                break;
              }
              case RMAD_CALIBRATION_INSTRUCTION_PLACE_LID_ON_FLAT_SURFACE: {
                instruction_string = kLogCalibrationSetupLidString;
                break;
              }
              default: {
                instruction_string = kLogCalibrationSetupUnknownString;
                break;
              }
            }
            generated_text_log.append(instruction_string);
            break;
          }
          case RmadState::kCheckCalibration: {
            const base::Value::List* components =
                details->FindList(kLogCalibrationComponents);
            const std::string component_list = JoinValueList(
                components,
                [](const base::Value& value) {
                  return GetCalibrationStatusString(value.GetDict());
                },
                ", ");
            generated_text_log.append(base::StringPrintf(
                kLogCalibrationFormat, component_list.c_str()));
            break;
          }
          case RmadState::kUpdateRoFirmware: {
            const FirmwareUpdateStatus status =
                static_cast<FirmwareUpdateStatus>(
                    details->FindInt(kFirmwareStatus).value());
            auto it = kFirmwareUpdateStatusMap.find(status);
            CHECK(it != kFirmwareUpdateStatusMap.end());
            generated_text_log.append(it->second.data());
            break;
          }
          default:
            break;
        }
      }
    }
    generated_text_log.append("\n");
  }

  return generated_text_log;
}

}  // namespace

std::string GenerateLogsText(scoped_refptr<JsonStore> json_store) {
  return GenerateTextLogString(json_store);
}

std::string GenerateLogsJson(scoped_refptr<JsonStore> json_store) {
  base::Value logs(base::Value::Type::DICT);
  json_store->GetValue(kLogs, &logs);
  if (!logs.is_dict()) {
    return "";
  }

  std::string output;
  JSONStringValueSerializer serializer(&output);
  serializer.set_pretty_print(true);
  serializer.Serialize(logs);
  return output;
}

bool RecordStateTransitionToLogs(scoped_refptr<JsonStore> json_store,
                                 RmadState::StateCase from_state,
                                 RmadState::StateCase to_state) {
  base::Value::Dict details;
  details.Set(kFromStateId, static_cast<int>(from_state));
  details.Set(kToStateId, static_cast<int>(to_state));

  return AddEventToJson(json_store, from_state, LogEventType::kTransition,
                        std::move(details));
}

bool RecordOccurredErrorToLogs(scoped_refptr<JsonStore> json_store,
                               RmadState::StateCase current_state,
                               RmadErrorCode error) {
  base::Value::Dict details;
  details.Set(kOccurredError, static_cast<int>(error));

  return AddEventToJson(json_store, current_state, LogEventType::kError,
                        std::move(details));
}

bool RecordRepairStartToLogs(scoped_refptr<JsonStore> json_store) {
  // Check to make sure the repair start was not already recorded.
  base::Value logs(base::Value::Type::DICT);
  json_store->GetValue(kLogs, &logs);
  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  if (events) {
    for (const base::Value& value : *events) {
      const base::Value::Dict& event = value.GetDict();
      if (event.FindInt(kType) == static_cast<int>(LogEventType::kData) &&
          event.FindInt(kStateId) == static_cast<int>(RmadState::kWelcome)) {
        return false;
      }
    }
  }

  base::Value::Dict details;
  return AddEventToJson(json_store, RmadState::kWelcome, LogEventType::kData,
                        std::move(details));
}

bool RecordUnqualifiedComponentsToLogs(
    scoped_refptr<JsonStore> json_store,
    bool is_compliant,
    const std::string& unqualified_components) {
  base::Value::Dict details;
  details.Set(kLogIsCompliant, is_compliant);
  details.Set(kLogUnqualifiedComponents, unqualified_components);

  return AddEventToJson(json_store, RmadState::kWelcome, LogEventType::kData,
                        std::move(details));
}

bool RecordSelectedComponentsToLogs(
    scoped_refptr<JsonStore> json_store,
    const std::vector<std::string>& replaced_components,
    bool is_mlb_repair) {
  base::Value::Dict details;
  details.Set(kLogReplacedComponents, ConvertToValue(replaced_components));
  details.Set(kLogReworkSelected, is_mlb_repair);

  return AddEventToJson(json_store, RmadState::kComponentsRepair,
                        LogEventType::kData, std::move(details));
}

bool RecordDeviceDestinationToLogs(scoped_refptr<JsonStore> json_store,
                                   const std::string& device_destination) {
  base::Value::Dict details;
  details.Set(kLogDestination, device_destination);

  return AddEventToJson(json_store, RmadState::kDeviceDestination,
                        LogEventType::kData, std::move(details));
}

bool RecordWipeDeviceToLogs(scoped_refptr<JsonStore> json_store,
                            bool wipe_device) {
  base::Value::Dict details;
  details.Set(kLogWipeDevice, wipe_device);

  return AddEventToJson(json_store, RmadState::kWipeSelection,
                        LogEventType::kData, std::move(details));
}

bool RecordWpDisableMethodToLogs(scoped_refptr<JsonStore> json_store,
                                 const std::string& wp_disable_method) {
  base::Value::Dict details;
  details.Set(kLogWpDisableMethod, wp_disable_method);

  return AddEventToJson(json_store, RmadState::kWpDisableMethod,
                        LogEventType::kData, std::move(details));
}

bool RecordRsuChallengeCodeToLogs(scoped_refptr<JsonStore> json_store,
                                  const std::string& challenge_code,
                                  const std::string& hwid) {
  base::Value::Dict details;
  details.Set(kLogRsuChallengeCode, challenge_code);
  details.Set(kLogRsuHwid, hwid);

  return AddEventToJson(json_store, RmadState::kWpDisableRsu,
                        LogEventType::kData, std::move(details));
}

bool RecordRestockOptionToLogs(scoped_refptr<JsonStore> json_store,
                               bool restock) {
  base::Value::Dict details;
  details.Set(kLogRestockOption, restock);

  return AddEventToJson(json_store, RmadState::kRestock, LogEventType::kData,
                        std::move(details));
}

bool RecordCalibrationSetupInstructionToLogs(
    scoped_refptr<JsonStore> json_store,
    CalibrationSetupInstruction instruction) {
  base::Value::Dict details;
  details.Set(kLogCalibrationSetupInstruction, static_cast<int>(instruction));

  return AddEventToJson(json_store, RmadState::kSetupCalibration,
                        LogEventType::kData, std::move(details));
}

bool RecordComponentCalibrationStatusToLogs(
    scoped_refptr<JsonStore> json_store,
    const std::vector<std::pair<std::string, LogCalibrationStatus>>&
        component_statuses) {
  base::Value::List components;
  for (auto& component_status : component_statuses) {
    base::Value::Dict component;
    component.Set(kLogComponent, component_status.first);
    component.Set(kLogCalibrationStatus,
                  static_cast<int>(component_status.second));
    components.Append(std::move(component));
  }

  base::Value::Dict details;
  details.Set(kLogCalibrationComponents, std::move(components));

  return AddEventToJson(json_store, RmadState::kCheckCalibration,
                        LogEventType::kData, std::move(details));
}

bool RecordFirmwareUpdateStatusToLogs(scoped_refptr<JsonStore> json_store,
                                      FirmwareUpdateStatus status) {
  // Check to make sure the firmware complete was not already recorded.
  if (status == FirmwareUpdateStatus::kFirmwareComplete) {
    base::Value logs(base::Value::Type::DICT);
    json_store->GetValue(kLogs, &logs);
    const base::Value::List* events = logs.GetDict().FindList(kEvents);
    if (events) {
      for (const base::Value& value : *events) {
        const base::Value::Dict& event = value.GetDict();
        if (event.FindInt(kType) == static_cast<int>(LogEventType::kData) &&
            event.FindInt(kStateId) ==
                static_cast<int>(RmadState::kUpdateRoFirmware) &&
            event.FindDict(kDetails)->FindInt(kFirmwareStatus) ==
                static_cast<int>(FirmwareUpdateStatus::kFirmwareComplete)) {
          return false;
        }
      }
    }
  }

  base::Value::Dict details;
  details.Set(kFirmwareStatus, static_cast<int>(status));

  return AddEventToJson(json_store, RmadState::kUpdateRoFirmware,
                        LogEventType::kData, std::move(details));
}

}  // namespace rmad
