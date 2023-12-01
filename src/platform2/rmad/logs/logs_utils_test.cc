// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/logs/logs_utils.h"

#include <string>
#include <utility>
#include <vector>

#include <base/containers/contains.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/json/json_writer.h>
#include <base/memory/scoped_refptr.h>
#include <base/values.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "rmad/logs/logs_constants.h"
#include "rmad/utils/json_store.h"

using testing::_;
using testing::Return;

namespace {

constexpr char kTestJsonStoreFilename[] = "test.json";
constexpr char kDefaultJson[] = R"(
{
  "metrics": {},
  "other": {},
  "running_time": 446.1482148170471,
  "setup_timestamp": 1663970456.867931
}
)";
constexpr char kSampleLogsJson[] = R"(
{
  "logs": {
    "events": [
      {
        "details": {
        },
        "state_id": 1,
        "timestamp": 1668635055.687762,
        "type": 1
      },
      {
        "details": {
          "is_compliant": false,
          "unqualified_components": "Display"
        },
        "state_id": 1,
        "timestamp": 1668635055.687762,
        "type": 1
      },
      {
        "details": {
           "from_state_id": 1,
           "to_state_id": 10
        },
        "state_id": 1,
        "timestamp": 1668635055.687762,
        "type": 0
      },
      {
        "details": {
          "replaced_components": [
            "RMAD_COMPONENT_KEYBOARD",
            "RMAD_COMPONENT_CAMERA"
          ],
          "rework_selected": false
        },
        "state_id": 2,
        "timestamp": 1668810230.12951,
        "type": 1
      },
      {
        "details": {
            "occurred_error": 41
        },
        "state_id": 15,
        "timestamp": 1668635055.687762,
        "type": 2
      },
      {
        "details": {
           "from_state_id": 10,
           "to_state_id": 14
        },
        "state_id": 10,
        "timestamp": 1668635055.688008,
        "type": 0
      },
      {
        "details": {
          "wp_disable_method": "RMAD_WP_DISABLE_RSU"
        },
        "state_id": 4,
        "timestamp": 1668812821.203501,
        "type": 1
      },
      {
        "details": {
          "challenge_code": "ABC123",
          "hwid": "FLEEX"
        },
        "state_id": 5,
        "timestamp": 1668812821.417402,
        "type": 1
      },
      {
        "details": {
          "firmware_status": 3
        },
        "state_id": 9,
        "timestamp": 1668812972.125672,
        "type": 1
      },
      {
        "details": {
          "restock_option": false
        },
        "state_id": 10,
        "timestamp": 1668812984.62641,
        "type": 1
      },
      {
        "details": {
          "calibration_components": [
            {
              "calibration_status": 0,
              "component": "RMAD_COMPONENT_BASE_ACCELEROMETER"
            },
            {
              "calibration_status": 1,
              "component": "RMAD_COMPONENT_BASE_GYROSCOPE"
            },
            {
              "calibration_status": 2,
              "component": "RMAD_COMPONENT_LID_ACCELEROMETER"
            }
          ]
        },
        "state_id": 12,
        "timestamp": 1668813225.410572,
        "type": 1
      },
      {
        "details": {
          "calibration_instruction": 2
        },
        "state_id": 13,
        "timestamp": 1668813225.410572,
        "type": 1
      }
    ]
  }
}
)";
constexpr char kExpectedLogText[] =
    "[2022-11-16 21:44:15] Welcome: Shimless RMA Started\n"
    "[2022-11-16 21:44:15] Welcome: Unqualified components detected - Display\n"
    "[2022-11-16 21:44:15] Transitioned from Welcome to Restock\n"
    "[2022-11-18 22:23:50] ComponentsRepair: Selected RMAD_COMPONENT_KEYBOARD,"
    " RMAD_COMPONENT_CAMERA\n"
    "[2022-11-16 21:44:15] ERROR in ProvisionDevice: RMAD_ERROR_WP_ENABLED\n"
    "[2022-11-16 21:44:15] Transitioned from Restock to RunCalibration\n"
    "[2022-11-18 23:07:01] WpDisableMethod: Selected to disable write protect"
    " via RMAD_WP_DISABLE_RSU\n"
    "[2022-11-18 23:07:01] WpDisableRsu: The RSU challenge code is ABC123\n"
    "[2022-11-18 23:09:32] UpdateRoFirmware: Firmware update complete\n"
    "[2022-11-18 23:09:44] Restock: Continuing\n"
    "[2022-11-18 23:13:45] CheckCalibration: Calibration for"
    " RMAD_COMPONENT_BASE_ACCELEROMETER - Failed, RMAD_COMPONENT_BASE_GYROSCOPE"
    " - Skipped, RMAD_COMPONENT_LID_ACCELEROMETER - Retried\n"
    "[2022-11-18 23:13:45] SetupCalibration: Place lid on flat surface\n";

}  // namespace

namespace rmad {

class LogsUtilsTest : public testing::Test {
 public:
  LogsUtilsTest() = default;

 protected:
  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    file_path_ = temp_dir_.GetPath().AppendASCII(kTestJsonStoreFilename);
  }

  bool CreateInputFile(const char* str, int size) {
    if (base::WriteFile(file_path_, str, size) == size) {
      json_store_ = base::MakeRefCounted<JsonStore>(file_path_);
      return true;
    }
    return false;
  }

  base::ScopedTempDir temp_dir_;
  scoped_refptr<JsonStore> json_store_;
  base::FilePath file_path_;
};

// Simulates adding two events to an empty `logs` json.
TEST_F(LogsUtilsTest, RecordStateTransition) {
  const RmadState::StateCase state1 = RmadState::kWelcome;
  const RmadState::StateCase state2 = RmadState::kRestock;
  const RmadState::StateCase state3 = RmadState::kRunCalibration;

  EXPECT_TRUE(CreateInputFile(kDefaultJson, std::size(kDefaultJson) - 1));

  EXPECT_TRUE(RecordStateTransitionToLogs(json_store_, state1, state2));
  base::Value logs(base::Value::Type::DICT);
  json_store_->GetValue(kLogs, &logs);

  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  EXPECT_EQ(1, events->size());
  const base::Value::Dict& event1 = (*events)[0].GetDict();
  EXPECT_EQ(static_cast<int>(state1),
            event1.FindDict(kDetails)->FindInt(kFromStateId));
  EXPECT_EQ(static_cast<int>(state2),
            event1.FindDict(kDetails)->FindInt(kToStateId));

  EXPECT_TRUE(RecordStateTransitionToLogs(json_store_, state2, state3));
  json_store_->GetValue(kLogs, &logs);

  events = logs.GetDict().FindList(kEvents);
  EXPECT_EQ(2, events->size());
  const base::Value::Dict& event2 = (*events)[1].GetDict();
  EXPECT_EQ(static_cast<int>(state2),
            event2.FindDict(kDetails)->FindInt(kFromStateId));
  EXPECT_EQ(static_cast<int>(state3),
            event2.FindDict(kDetails)->FindInt(kToStateId));
}

// Simulates adding the repair start to an empty `logs` json.
TEST_F(LogsUtilsTest, RecordRepairStart) {
  EXPECT_TRUE(CreateInputFile(kDefaultJson, std::size(kDefaultJson) - 1));

  EXPECT_TRUE(RecordRepairStartToLogs(json_store_));
  base::Value logs(base::Value::Type::DICT);
  json_store_->GetValue(kLogs, &logs);

  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  EXPECT_EQ(1, events->size());
  const base::Value::Dict& event = (*events)[0].GetDict();
  EXPECT_EQ(static_cast<int>(RmadState::kWelcome), event.FindInt(kStateId));
  EXPECT_EQ(static_cast<int>(LogEventType::kData), event.FindInt(kType));

  // Attempt to record again and verify it's not added.
  EXPECT_FALSE(RecordRepairStartToLogs(json_store_));
}

// Simulates adding unqualified components to an empty `logs` json.
TEST_F(LogsUtilsTest, RecordUnqualifiedComponents) {
  EXPECT_TRUE(CreateInputFile(kDefaultJson, std::size(kDefaultJson) - 1));

  const bool is_compliant = true;
  const std::string battery = RmadComponent_Name(RMAD_COMPONENT_BATTERY);

  EXPECT_TRUE(
      RecordUnqualifiedComponentsToLogs(json_store_, is_compliant, battery));
  base::Value logs(base::Value::Type::DICT);
  json_store_->GetValue(kLogs, &logs);

  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  EXPECT_EQ(1, events->size());
  const base::Value::Dict& event = (*events)[0].GetDict();
  EXPECT_EQ(static_cast<int>(RmadState::kWelcome), event.FindInt(kStateId));
  EXPECT_EQ(static_cast<int>(LogEventType::kData), event.FindInt(kType));

  EXPECT_EQ(is_compliant,
            event.FindDict(kDetails)->FindBool(kLogIsCompliant).value());
  EXPECT_EQ(battery,
            *event.FindDict(kDetails)->FindString(kLogUnqualifiedComponents));
}

// Simulates adding replaced components to an empty `logs` json.
TEST_F(LogsUtilsTest, RecordSelectedComponents) {
  EXPECT_TRUE(CreateInputFile(kDefaultJson, std::size(kDefaultJson) - 1));

  const bool rework_selected_expected_value = true;
  const std::string audio_codec =
      RmadComponent_Name(RMAD_COMPONENT_AUDIO_CODEC);
  const std::string battery = RmadComponent_Name(RMAD_COMPONENT_BATTERY);

  EXPECT_TRUE(RecordSelectedComponentsToLogs(
      json_store_, std::vector<std::string>({audio_codec, battery}),
      rework_selected_expected_value));
  base::Value logs(base::Value::Type::DICT);
  json_store_->GetValue(kLogs, &logs);

  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  EXPECT_EQ(1, events->size());
  const base::Value::Dict& event = (*events)[0].GetDict();
  EXPECT_EQ(static_cast<int>(RmadState::kComponentsRepair),
            event.FindInt(kStateId));
  EXPECT_EQ(static_cast<int>(LogEventType::kData), event.FindInt(kType));

  const base::Value::List* components =
      event.FindDict(kDetails)->FindList(kLogReplacedComponents);
  EXPECT_EQ(2, components->size());
  EXPECT_EQ(audio_codec, (*components)[0].GetString());
  EXPECT_EQ(battery, (*components)[1].GetString());
  EXPECT_TRUE(event.FindDict(kDetails)->FindBool(kLogReworkSelected).value());
}

// Simulates adding the device destination to an empty `logs` json.
TEST_F(LogsUtilsTest, RecordDeviceDestination) {
  EXPECT_TRUE(CreateInputFile(kDefaultJson, std::size(kDefaultJson) - 1));

  const std::string device_destination =
      ReturningOwner_Name(ReturningOwner::RMAD_RETURNING_OWNER_DIFFERENT_OWNER);

  EXPECT_TRUE(RecordDeviceDestinationToLogs(json_store_, device_destination));
  base::Value logs(base::Value::Type::DICT);
  json_store_->GetValue(kLogs, &logs);

  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  EXPECT_EQ(1, events->size());
  const base::Value::Dict& event = (*events)[0].GetDict();
  EXPECT_EQ(static_cast<int>(RmadState::kDeviceDestination),
            event.FindInt(kStateId));
  EXPECT_EQ(static_cast<int>(LogEventType::kData), event.FindInt(kType));
  EXPECT_EQ(device_destination,
            *event.FindDict(kDetails)->FindString(kLogDestination));
}

// Simulates adding the wipe device decision to an empty `logs` json.
TEST_F(LogsUtilsTest, RecordWipeDevice) {
  EXPECT_TRUE(CreateInputFile(kDefaultJson, std::size(kDefaultJson) - 1));

  const bool wipe_device = true;

  EXPECT_TRUE(RecordWipeDeviceToLogs(json_store_, wipe_device));
  base::Value logs(base::Value::Type::DICT);
  json_store_->GetValue(kLogs, &logs);

  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  EXPECT_EQ(1, events->size());
  const base::Value::Dict& event = (*events)[0].GetDict();
  EXPECT_EQ(static_cast<int>(RmadState::kWipeSelection),
            event.FindInt(kStateId));
  EXPECT_EQ(static_cast<int>(LogEventType::kData), event.FindInt(kType));
  EXPECT_TRUE(event.FindDict(kDetails)->FindBool(kLogWipeDevice).value());
}

// Simulates adding the wp disable method to an empty `logs` json.
TEST_F(LogsUtilsTest, RecordWpDisableMethod) {
  EXPECT_TRUE(CreateInputFile(kDefaultJson, std::size(kDefaultJson) - 1));

  const std::string wp_disable_method =
      WpDisableMethod_Name(RMAD_WP_DISABLE_METHOD_RSU);

  EXPECT_TRUE(RecordWpDisableMethodToLogs(json_store_, wp_disable_method));
  base::Value logs(base::Value::Type::DICT);
  json_store_->GetValue(kLogs, &logs);

  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  EXPECT_EQ(1, events->size());
  const base::Value::Dict& event = (*events)[0].GetDict();
  EXPECT_EQ(static_cast<int>(RmadState::kWpDisableMethod),
            event.FindInt(kStateId));
  EXPECT_EQ(static_cast<int>(LogEventType::kData), event.FindInt(kType));
  EXPECT_EQ(wp_disable_method,
            *event.FindDict(kDetails)->FindString(kLogWpDisableMethod));
}

// Simulates adding the RSU challenge code to an empty `logs` json.
TEST_F(LogsUtilsTest, RecordRsuChallengeCode) {
  EXPECT_TRUE(CreateInputFile(kDefaultJson, std::size(kDefaultJson) - 1));

  const std::string challenge_code = "H65SFQL111PBRSB6PDIRTMFO0KHG3QZW0YSF04PW";
  const std::string hwid = "BOOK_C4B-A3F-B4U-E2U-B4E-A6T";

  EXPECT_TRUE(RecordRsuChallengeCodeToLogs(json_store_, challenge_code, hwid));
  base::Value logs(base::Value::Type::DICT);
  json_store_->GetValue(kLogs, &logs);

  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  EXPECT_EQ(1, events->size());
  const base::Value::Dict& event = (*events)[0].GetDict();
  EXPECT_EQ(static_cast<int>(RmadState::kWpDisableRsu),
            event.FindInt(kStateId));
  EXPECT_EQ(static_cast<int>(LogEventType::kData), event.FindInt(kType));
  EXPECT_EQ(challenge_code,
            *event.FindDict(kDetails)->FindString(kLogRsuChallengeCode));
  EXPECT_EQ(hwid, *event.FindDict(kDetails)->FindString(kLogRsuHwid));
}

// Simulates adding the restock option to an empty `logs` json.
TEST_F(LogsUtilsTest, RecordRestockOption) {
  EXPECT_TRUE(CreateInputFile(kDefaultJson, std::size(kDefaultJson) - 1));

  EXPECT_TRUE(RecordRestockOptionToLogs(json_store_, /*restock=*/false));
  base::Value logs(base::Value::Type::DICT);
  json_store_->GetValue(kLogs, &logs);

  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  EXPECT_EQ(1, events->size());
  const base::Value::Dict& event = (*events)[0].GetDict();
  EXPECT_EQ(static_cast<int>(RmadState::kRestock), event.FindInt(kStateId));
  EXPECT_EQ(static_cast<int>(LogEventType::kData), event.FindInt(kType));
  EXPECT_FALSE(event.FindDict(kDetails)->FindBool(kLogRestockOption).value());
}

// Simulates adding an error to an empty `logs` json.
TEST_F(LogsUtilsTest, RecordError) {
  EXPECT_TRUE(CreateInputFile(kDefaultJson, std::size(kDefaultJson) - 1));

  const RmadState::StateCase current_state = RmadState::kComponentsRepair;
  const RmadErrorCode error = RmadErrorCode::RMAD_ERROR_CANNOT_CANCEL_RMA;

  EXPECT_TRUE(RecordOccurredErrorToLogs(json_store_, current_state, error));
  base::Value logs(base::Value::Type::DICT);
  json_store_->GetValue(kLogs, &logs);

  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  EXPECT_EQ(1, events->size());
  const base::Value::Dict& event = (*events)[0].GetDict();
  EXPECT_EQ(static_cast<int>(current_state), event.FindInt(kStateId));
  EXPECT_EQ(static_cast<int>(LogEventType::kError), event.FindInt(kType));
  EXPECT_EQ(static_cast<int>(error),
            event.FindDict(kDetails)->FindInt(kOccurredError));
}

// Simulates adding component calibration statuses to an empty `logs` json.
TEST_F(LogsUtilsTest, RecordComponentCalibrationStatus) {
  EXPECT_TRUE(CreateInputFile(kDefaultJson, std::size(kDefaultJson) - 1));

  const std::string component1 =
      RmadComponent_Name(RMAD_COMPONENT_BASE_ACCELEROMETER);
  const LogCalibrationStatus status1 = LogCalibrationStatus::kFailed;
  const std::string component2 =
      RmadComponent_Name(RMAD_COMPONENT_BASE_GYROSCOPE);
  const LogCalibrationStatus status2 = LogCalibrationStatus::kSkip;
  const std::string component3 =
      RmadComponent_Name(RMAD_COMPONENT_LID_ACCELEROMETER);
  const LogCalibrationStatus status3 = LogCalibrationStatus::kRetry;

  std::vector<std::pair<std::string, LogCalibrationStatus>>
      calibration_statuses{
          {component1, status1}, {component2, status2}, {component3, status3}};

  EXPECT_TRUE(RecordComponentCalibrationStatusToLogs(json_store_,
                                                     calibration_statuses));
  base::Value logs(base::Value::Type::DICT);
  json_store_->GetValue(kLogs, &logs);

  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  EXPECT_EQ(1, events->size());
  const base::Value::Dict& event = (*events)[0].GetDict();
  EXPECT_EQ(static_cast<int>(RmadState::kCheckCalibration),
            event.FindInt(kStateId));
  EXPECT_EQ(static_cast<int>(LogEventType::kData), event.FindInt(kType));

  const base::Value::List* components =
      event.FindDict(kDetails)->FindList(kLogCalibrationComponents);
  EXPECT_EQ(3, components->size());
  EXPECT_EQ(component1, *(*components)[0].GetDict().FindString(kLogComponent));
  EXPECT_EQ(static_cast<int>(status1),
            (*components)[0].GetDict().FindInt(kLogCalibrationStatus));
  EXPECT_EQ(component2, *(*components)[1].GetDict().FindString(kLogComponent));
  EXPECT_EQ(static_cast<int>(status2),
            (*components)[1].GetDict().FindInt(kLogCalibrationStatus));
  EXPECT_EQ(component3, *(*components)[2].GetDict().FindString(kLogComponent));
  EXPECT_EQ(static_cast<int>(status3),
            (*components)[2].GetDict().FindInt(kLogCalibrationStatus));
}

// Simulates adding component calibration setup instruction to an empty `logs`
// json.
TEST_F(LogsUtilsTest, RecordComponentCalibrationSetupInstruction) {
  EXPECT_TRUE(CreateInputFile(kDefaultJson, std::size(kDefaultJson) - 1));

  const CalibrationSetupInstruction calibration_instruction =
      RMAD_CALIBRATION_INSTRUCTION_PLACE_BASE_ON_FLAT_SURFACE;

  EXPECT_TRUE(RecordCalibrationSetupInstructionToLogs(json_store_,
                                                      calibration_instruction));
  base::Value logs(base::Value::Type::DICT);
  json_store_->GetValue(kLogs, &logs);

  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  EXPECT_EQ(1, events->size());
  const base::Value::Dict& event = (*events)[0].GetDict();
  EXPECT_EQ(static_cast<int>(RmadState::kSetupCalibration),
            event.FindInt(kStateId));
  EXPECT_EQ(static_cast<int>(LogEventType::kData), event.FindInt(kType));
  EXPECT_EQ(
      static_cast<int>(calibration_instruction),
      *event.FindDict(kDetails)->FindInt(kLogCalibrationSetupInstruction));
}

// Simulates adding the firmware update status updates to an empty `logs` json.
TEST_F(LogsUtilsTest, RecordFirmwareUpdateStatus) {
  EXPECT_TRUE(CreateInputFile(kDefaultJson, std::size(kDefaultJson) - 1));

  const FirmwareUpdateStatus status1 = FirmwareUpdateStatus::kFirmwareUpdated;
  const FirmwareUpdateStatus status2 = FirmwareUpdateStatus::kFirmwareComplete;

  EXPECT_TRUE(RecordFirmwareUpdateStatusToLogs(json_store_, status1));
  EXPECT_TRUE(RecordFirmwareUpdateStatusToLogs(json_store_, status2));
  // Adding a duplicate `kFirmwareComplete` should not be recorded to logs.
  EXPECT_FALSE(RecordFirmwareUpdateStatusToLogs(json_store_, status2));
  base::Value logs(base::Value::Type::DICT);
  json_store_->GetValue(kLogs, &logs);

  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  EXPECT_EQ(2, events->size());
  const base::Value::Dict& event1 = (*events)[0].GetDict();
  EXPECT_EQ(static_cast<int>(status1),
            event1.FindDict(kDetails)->FindInt(kFirmwareStatus));
  const base::Value::Dict& event2 = (*events)[1].GetDict();
  EXPECT_EQ(static_cast<int>(status2),
            event2.FindDict(kDetails)->FindInt(kFirmwareStatus));
}

// Simulates generating a text log.
TEST_F(LogsUtilsTest, GenerateTextLog) {
  EXPECT_TRUE(CreateInputFile(kSampleLogsJson, std::size(kSampleLogsJson) - 1));
  EXPECT_EQ(kExpectedLogText, GenerateLogsText(json_store_));
}

// Simulates generating the logs JSON.
TEST_F(LogsUtilsTest, GenerateLogsJson) {
  EXPECT_TRUE(CreateInputFile(kSampleLogsJson, std::size(kSampleLogsJson) - 1));
  base::Value logs(base::Value::Type::DICT);
  json_store_->GetValue(kLogs, &logs);

  std::string expected_logs_json;
  base::JSONWriter::WriteWithOptions(
      logs, base::JSONWriter::OPTIONS_PRETTY_PRINT, &expected_logs_json);
  EXPECT_EQ(expected_logs_json, GenerateLogsJson(json_store_));
}

}  // namespace rmad
