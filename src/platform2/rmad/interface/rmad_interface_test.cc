// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/interface/rmad_interface_impl.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/memory/scoped_refptr.h>
#include <base/strings/stringprintf.h>
#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "rmad/daemon/daemon_callback.h"
#include "rmad/logs/logs_constants.h"
#include "rmad/metrics/mock_metrics_utils.h"
#include "rmad/metrics/state_metrics.h"
#include "rmad/state_handler/mock_state_handler.h"
#include "rmad/state_handler/state_handler_manager.h"
#include "rmad/system/mock_power_manager_client.h"
#include "rmad/system/mock_runtime_probe_client.h"
#include "rmad/system/mock_shill_client.h"
#include "rmad/system/mock_tpm_manager_client.h"
#include "rmad/udev/mock_udev_device.h"
#include "rmad/udev/mock_udev_utils.h"
#include "rmad/utils/json_store.h"
#include "rmad/utils/mock_cmd_utils.h"

using testing::_;
using testing::Assign;
using testing::DoAll;
using testing::InSequence;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;
using testing::ReturnRef;
using testing::SetArgPointee;
using testing::StrictMock;

namespace rmad {

constexpr char kJsonStoreFileName[] = "json_store_file";
constexpr char kCurrentStateSetJson[] = R"({"state_history": [ 1 ]})";
constexpr char kCurrentStateNotSetJson[] = "{}";
constexpr char kCurrentStateInvalidStateJson[] = R"("state_history": [0])";
constexpr char kCurrentStateWithRepeatableHistoryJson[] =
    R"({"state_history": [ 1, 2 ]})";
constexpr char kCurrentStateWithUnrepeatableHistoryJson[] =
    R"({"state_history": [ 1, 2, 3 ]})";
constexpr char kCurrentStateWithUnsupportedStateJson[] =
    R"({"state_history": [ 1, 2, 4 ]})";
constexpr char kInitializeCurrentStateFailJson[] =
    R"({"state_history": [ 1 ]})";
constexpr char kInitializeNextStateFailJson[] =
    R"({"state_history": [ 1, 2 ]})";
constexpr char kInitializePreviousStateFailJson[] =
    R"({"state_history": [ 1, 2 ]})";
constexpr char kInvalidJson[] = R"(alfkjklsfsgdkjnbknd^^)";

constexpr char kStateHistoryWithMetricsJson[] =
    R"({
      "state_history": [ 1, 2 ],
      "metrics": {
        "replaced_component_names": [],
        "additional_activities": ["RMAD_ADDITIONAL_ACTIVITY_REBOOT"],
        "first_setup_timestamp": 123.456,
        "occurred_errors": ["RMAD_ERROR_MISSING_COMPONENT"],
        "ro_firmware_verified": true,
        "running_time": 333.333,
        "setup_timestamp": 456.789,
        "state_metrics": {
          "1": {
            "state_case": 1,
            "state_is_aborted": false,
            "state_setup_timestamp": 0.0,
            "state_overall_time": 123.456,
            "state_transition_count": 2,
            "state_get_log_count": 3,
            "state_save_log_count": 4
          },
          "2": {
            "state_case": 2,
            "state_is_aborted": true,
            "state_setup_timestamp": 123.456,
            "state_overall_time": 332.544,
            "state_transition_count": 1,
            "state_get_log_count": 0,
            "state_save_log_count": 0
          }
        }
      }
    })";

constexpr char kFakeRawLog[] = "fake_log";

constexpr char kDeviceFileFormat[] = "/dev/sd%c1";
constexpr char kMountSuccessDeviceId = 'e';

constexpr base::TimeDelta kTestTransitionInterval = base::Seconds(1);
constexpr base::TimeDelta kInitialStateOverallTime = base::Seconds(0);

class RmadInterfaceImplTest : public testing::Test {
 public:
  RmadInterfaceImplTest() {
    welcome_proto_.set_allocated_welcome(new WelcomeState());
    components_repair_proto_.set_allocated_components_repair(
        new ComponentsRepairState());
    device_destination_proto_.set_allocated_device_destination(
        new DeviceDestinationState());
  }

  base::FilePath CreateInputFile(std::string filename,
                                 const char* str,
                                 int size) {
    base::FilePath file_path = temp_dir_.GetPath().AppendASCII(filename);
    base::WriteFile(file_path, str, size);
    return file_path;
  }

  scoped_refptr<BaseStateHandler> CreateMockHandler(
      scoped_refptr<JsonStore> json_store,
      const RmadState& state,
      bool is_repeatable,
      RmadErrorCode initialize_error,
      RmadErrorCode get_next_state_case_error,
      RmadState::StateCase next_state) {
    auto daemon_callback = base::MakeRefCounted<DaemonCallback>();
    auto mock_handler = base::MakeRefCounted<NiceMock<MockStateHandler>>(
        json_store, daemon_callback);
    RmadState::StateCase state_case = state.state_case();
    ON_CALL(*mock_handler, GetStateCase()).WillByDefault(Return(state_case));
    ON_CALL(*mock_handler, GetState(_)).WillByDefault(ReturnRef(state));
    ON_CALL(*mock_handler, IsRepeatable()).WillByDefault(Return(is_repeatable));
    ON_CALL(*mock_handler, InitializeState())
        .WillByDefault(Return(initialize_error));
    ON_CALL(*mock_handler, GetNextStateCase(_))
        .WillByDefault(Return(BaseStateHandler::GetNextStateCaseReply{
            .error = get_next_state_case_error, .state_case = next_state}));
    ON_CALL(*mock_handler, TryGetNextStateCaseAtBoot())
        .WillByDefault(Return(BaseStateHandler::GetNextStateCaseReply{
            .error = get_next_state_case_error, .state_case = next_state}));
    return mock_handler;
  }

  std::unique_ptr<StateHandlerManager> CreateStateHandlerManagerWithHandlers(
      scoped_refptr<JsonStore> json_store,
      std::vector<scoped_refptr<BaseStateHandler>> mock_handlers) {
    auto state_handler_manager =
        std::make_unique<StateHandlerManager>(json_store);
    for (auto mock_handler : mock_handlers) {
      state_handler_manager->RegisterStateHandler(mock_handler);
    }
    return state_handler_manager;
  }

  std::unique_ptr<StateHandlerManager> CreateStateHandlerManager(
      scoped_refptr<JsonStore> json_store) {
    std::vector<scoped_refptr<BaseStateHandler>> mock_handlers;
    mock_handlers.push_back(CreateMockHandler(json_store, welcome_proto_, true,
                                              RMAD_ERROR_OK, RMAD_ERROR_OK,
                                              RmadState::kComponentsRepair));
    mock_handlers.push_back(CreateMockHandler(
        json_store, components_repair_proto_, true, RMAD_ERROR_OK,
        RMAD_ERROR_OK, RmadState::kDeviceDestination));
    mock_handlers.push_back(CreateMockHandler(
        json_store, device_destination_proto_, false, RMAD_ERROR_OK,
        RMAD_ERROR_OK, RmadState::kWpDisableMethod));
    return CreateStateHandlerManagerWithHandlers(json_store, mock_handlers);
  }

  std::unique_ptr<StateHandlerManager>
  CreateStateHandlerManagerGetNextStateCaseFail(
      scoped_refptr<JsonStore> json_store) {
    std::vector<scoped_refptr<BaseStateHandler>> mock_handlers;
    mock_handlers.push_back(CreateMockHandler(
        json_store, welcome_proto_, true, RMAD_ERROR_OK,
        RMAD_ERROR_REQUEST_ARGS_MISSING, RmadState::kWelcome));
    return CreateStateHandlerManagerWithHandlers(json_store, mock_handlers);
  }

  std::unique_ptr<StateHandlerManager> CreateStateHandlerManagerMissingHandler(
      scoped_refptr<JsonStore> json_store) {
    std::vector<scoped_refptr<BaseStateHandler>> mock_handlers;
    mock_handlers.push_back(CreateMockHandler(json_store, welcome_proto_, true,
                                              RMAD_ERROR_OK, RMAD_ERROR_OK,
                                              RmadState::kComponentsRepair));
    return CreateStateHandlerManagerWithHandlers(json_store, mock_handlers);
  }

  std::unique_ptr<StateHandlerManager>
  CreateStateHandlerManagerInitializeStateFail(
      scoped_refptr<JsonStore> json_store) {
    std::vector<scoped_refptr<BaseStateHandler>> mock_handlers;
    mock_handlers.push_back(CreateMockHandler(
        json_store, welcome_proto_, true, RMAD_ERROR_MISSING_COMPONENT,
        RMAD_ERROR_OK, RmadState::kComponentsRepair));
    mock_handlers.push_back(CreateMockHandler(
        json_store, components_repair_proto_, true, RMAD_ERROR_OK,
        RMAD_ERROR_OK, RmadState::kDeviceDestination));
    mock_handlers.push_back(
        CreateMockHandler(json_store, device_destination_proto_, false,
                          RMAD_ERROR_DEVICE_INFO_INVALID, RMAD_ERROR_OK,
                          RmadState::kWpDisableMethod));
    return CreateStateHandlerManagerWithHandlers(json_store, mock_handlers);
  }

  std::unique_ptr<RuntimeProbeClient> CreateRuntimeProbeClient(
      bool has_cellular) {
    auto mock_runtime_probe_client =
        std::make_unique<NiceMock<MockRuntimeProbeClient>>();
    ComponentsWithIdentifier components;
    if (has_cellular) {
      components.push_back(std::make_pair(RMAD_COMPONENT_CELLULAR, ""));
    }
    ON_CALL(*mock_runtime_probe_client, ProbeCategories(_, _, _))
        .WillByDefault(DoAll(SetArgPointee<2>(components), Return(true)));
    return mock_runtime_probe_client;
  }

  std::unique_ptr<ShillClient> CreateShillClient(bool* cellular_disabled) {
    auto mock_shill_client = std::make_unique<NiceMock<MockShillClient>>();
    if (cellular_disabled) {
      ON_CALL(*mock_shill_client, DisableCellular())
          .WillByDefault(DoAll(Assign(cellular_disabled, true), Return(true)));
    } else {
      ON_CALL(*mock_shill_client, DisableCellular())
          .WillByDefault(Return(true));
    }
    return mock_shill_client;
  }

  std::unique_ptr<TpmManagerClient> CreateTpmManagerClient(
      RoVerificationStatus ro_verification_status) {
    auto mock_tpm_manager_client =
        std::make_unique<NiceMock<MockTpmManagerClient>>();
    ON_CALL(*mock_tpm_manager_client, GetRoVerificationStatus(_))
        .WillByDefault(
            DoAll(SetArgPointee<0>(ro_verification_status), Return(true)));
    return mock_tpm_manager_client;
  }

  std::unique_ptr<PowerManagerClient> CreatePowerManagerClient() {
    return std::make_unique<NiceMock<MockPowerManagerClient>>();
  }

  std::unique_ptr<UdevUtils> CreateUdevUtils(int num_devices = 0) {
    auto mock_udev_utils = std::make_unique<NiceMock<MockUdevUtils>>();
    ON_CALL(*mock_udev_utils, EnumerateBlockDevices())
        .WillByDefault(Invoke([num_devices]() {
          std::vector<std::unique_ptr<UdevDevice>> devices;
          for (int i = 0; i < num_devices; ++i) {
            auto mock_device = std::make_unique<NiceMock<MockUdevDevice>>();
            ON_CALL(*mock_device, IsRemovable()).WillByDefault(Return(true));
            ON_CALL(*mock_device, GetDeviceNode())
                .WillByDefault(
                    Return(base::StringPrintf(kDeviceFileFormat, 'a' + i)));
            devices.push_back(std::move(mock_device));
          }
          return devices;
        }));
    return mock_udev_utils;
  }

  std::unique_ptr<CmdUtils> CreateCmdUtils(
      const std::vector<std::string>& statuses = {},
      const std::vector<std::string>& logs = {}) {
    auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
    ON_CALL(*mock_cmd_utils,
            GetOutput(std::vector<std::string>(
                          {"/usr/sbin/croslog", "--identifier=rmad"}),
                      _))
        .WillByDefault(DoAll(SetArgPointee<1>(kFakeRawLog), Return(true)));
    {
      InSequence seq;
      for (std::string status : statuses) {
        EXPECT_CALL(
            *mock_cmd_utils,
            GetOutput(std::vector<std::string>(
                          {"/sbin/initctl", "status", "system-services"}),
                      _))
            .WillOnce(DoAll(SetArgPointee<1>(status), Return(true)));
      }
      EXPECT_CALL(*mock_cmd_utils,
                  GetOutput(std::vector<std::string>(
                                {"/sbin/initctl", "status", "system-services"}),
                            _))
          .WillRepeatedly(DoAll(SetArgPointee<1>("running"), Return(true)));
    }
    {
      InSequence seq;
      for (std::string log : logs) {
        EXPECT_CALL(*mock_cmd_utils,
                    GetOutput(std::vector<std::string>(
                                  {"/usr/sbin/croslog", "--identifier=rmad"}),
                              _))
            .WillOnce(DoAll(SetArgPointee<1>(log), Return(true)));
      }
      EXPECT_CALL(*mock_cmd_utils,
                  GetOutput(std::vector<std::string>(
                                {"/usr/sbin/croslog", "--identifier=rmad"}),
                            _))
          .WillRepeatedly(DoAll(SetArgPointee<1>("fake_log"), Return(true)));
    }
    return mock_cmd_utils;
  }

  std::unique_ptr<MetricsUtils> CreateMetricsUtils(bool success) {
    auto mock_metrics_utils = std::make_unique<NiceMock<MockMetricsUtils>>();
    ON_CALL(*mock_metrics_utils, RecordAll(_)).WillByDefault(Return(success));
    return mock_metrics_utils;
  }

  void MountAndWriteLogCallback(
      uint8_t device_id,
      const std::string& text_log,
      const std::string& json_log,
      const std::string& system_log,
      const std::string& diagnostics_log,
      base::OnceCallback<void(const std::optional<std::string>&)> callback) {
    if (device_id == kMountSuccessDeviceId) {
      std::move(callback).Run("rma.log");
    } else {
      std::move(callback).Run(std::nullopt);
    }
  }

 protected:
  void SetUp() override { ASSERT_TRUE(temp_dir_.CreateUniqueTempDir()); }

  RmadState welcome_proto_;
  RmadState components_repair_proto_;
  RmadState device_destination_proto_;
  base::ScopedTempDir temp_dir_;
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
};

TEST_F(RmadInterfaceImplTest, Setup) {
  base::FilePath json_store_file_path =
      CreateInputFile(kJsonStoreFileName, kCurrentStateSetJson,
                      std::size(kCurrentStateSetJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  bool cellular_disabled = false;
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManager(json_store),
      CreateRuntimeProbeClient(true), CreateShillClient(&cellular_disabled),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(),
      CreateCmdUtils({"waiting"}), CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::kWelcome, rmad_interface.GetCurrentStateCase());

  EXPECT_TRUE(cellular_disabled);

  // Verify the repair start was recorded to logs.
  base::Value logs(base::Value::Type::DICT);
  json_store->GetValue(kLogs, &logs);
  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  EXPECT_EQ(1, events->size());

  const base::Value::Dict& event = (*events)[0].GetDict();
  EXPECT_EQ(static_cast<int>(RmadState::kWelcome), event.FindInt(kStateId));
}

TEST_F(RmadInterfaceImplTest, Setup_WaitForServices_Timeout) {
  base::FilePath json_store_file_path =
      CreateInputFile(kJsonStoreFileName, kCurrentStateSetJson,
                      std::size(kCurrentStateSetJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  bool cellular_disabled = false;
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManager(json_store),
      CreateRuntimeProbeClient(true), CreateShillClient(&cellular_disabled),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(),
      CreateCmdUtils(std::vector<std::string>(10, "waiting")),
      CreateMetricsUtils(true));
  EXPECT_FALSE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::STATE_NOT_SET, rmad_interface.GetCurrentStateCase());
}

TEST_F(RmadInterfaceImplTest, GetCurrentState_Set_HasCellular) {
  base::FilePath json_store_file_path =
      CreateInputFile(kJsonStoreFileName, kCurrentStateSetJson,
                      std::size(kCurrentStateSetJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  bool cellular_disabled = false;
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManager(json_store),
      CreateRuntimeProbeClient(true), CreateShillClient(&cellular_disabled),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::kWelcome, rmad_interface.GetCurrentStateCase());

  EXPECT_TRUE(cellular_disabled);

  auto callback = [](const GetStateReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_OK, reply.error());
    EXPECT_EQ(RmadState::kWelcome, reply.state().state_case());
    EXPECT_FALSE(reply.can_go_back());
    EXPECT_TRUE(reply.can_abort());
    EXPECT_FALSE(quit_daemon);
  };
  rmad_interface.GetCurrentState(base::BindOnce(callback));
}

TEST_F(RmadInterfaceImplTest, GetCurrentState_Set_NoCellular) {
  base::FilePath json_store_file_path =
      CreateInputFile(kJsonStoreFileName, kCurrentStateSetJson,
                      std::size(kCurrentStateSetJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  bool cellular_disabled = false;
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManager(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(&cellular_disabled),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::kWelcome, rmad_interface.GetCurrentStateCase());

  EXPECT_FALSE(cellular_disabled);

  auto callback = [](const GetStateReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_OK, reply.error());
    EXPECT_EQ(RmadState::kWelcome, reply.state().state_case());
    EXPECT_FALSE(reply.can_go_back());
    EXPECT_TRUE(reply.can_abort());
    EXPECT_FALSE(quit_daemon);
  };
  rmad_interface.GetCurrentState(base::BindOnce(callback));
}

TEST_F(RmadInterfaceImplTest,
       GetCurrentState_NotInRma_RoVerificationNotTriggered) {
  base::FilePath json_store_file_path =
      temp_dir_.GetPath().AppendASCII("missing.json");
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  bool cellular_disabled = false;
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManager(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(&cellular_disabled),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::STATE_NOT_SET, rmad_interface.GetCurrentStateCase());

  EXPECT_FALSE(cellular_disabled);

  auto callback = [](const GetStateReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_RMA_NOT_REQUIRED, reply.error());
    EXPECT_EQ(RmadState::STATE_NOT_SET, reply.state().state_case());
    EXPECT_TRUE(quit_daemon);
  };
  rmad_interface.GetCurrentState(base::BindOnce(callback));
}

TEST_F(RmadInterfaceImplTest, GetCurrentState_NotInRma_RoVerificationPass) {
  base::FilePath json_store_file_path =
      temp_dir_.GetPath().AppendASCII("missing.json");
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManager(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_PASS),
      CreatePowerManagerClient(), CreateUdevUtils(), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::kWelcome, rmad_interface.GetCurrentStateCase());

  auto callback = [](const GetStateReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_OK, reply.error());
    EXPECT_EQ(RmadState::kWelcome, reply.state().state_case());
    EXPECT_FALSE(reply.can_go_back());
    EXPECT_TRUE(reply.can_abort());
    EXPECT_FALSE(quit_daemon);
  };
  rmad_interface.GetCurrentState(base::BindOnce(callback));
}

TEST_F(RmadInterfaceImplTest,
       GetCurrentState_NotInRma_RoVerificationUnsupportedTriggered) {
  base::FilePath json_store_file_path =
      temp_dir_.GetPath().AppendASCII("missing.json");
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManager(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_UNSUPPORTED_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::kWelcome, rmad_interface.GetCurrentStateCase());

  auto callback = [](const GetStateReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_OK, reply.error());
    EXPECT_EQ(RmadState::kWelcome, reply.state().state_case());
    EXPECT_FALSE(reply.can_go_back());
    EXPECT_TRUE(reply.can_abort());
    EXPECT_FALSE(quit_daemon);
  };
  rmad_interface.GetCurrentState(base::BindOnce(callback));
}

TEST_F(RmadInterfaceImplTest, GetCurrentState_CorruptedFile) {
  base::FilePath json_store_file_path =
      CreateInputFile(kJsonStoreFileName, "", 0);
  // Make the file read-only.
  base::SetPosixFilePermissions(json_store_file_path, 0444);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManager(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_FALSE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::STATE_NOT_SET, rmad_interface.GetCurrentStateCase());
}

TEST_F(RmadInterfaceImplTest, GetCurrentState_EmptyFile) {
  base::FilePath json_store_file_path =
      CreateInputFile(kJsonStoreFileName, "", 0);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManager(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::kWelcome, rmad_interface.GetCurrentStateCase());

  auto callback = [](const GetStateReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_OK, reply.error());
    EXPECT_EQ(RmadState::kWelcome, reply.state().state_case());
    EXPECT_FALSE(reply.can_go_back());
    EXPECT_TRUE(reply.can_abort());
    EXPECT_FALSE(quit_daemon);
  };
  rmad_interface.GetCurrentState(base::BindOnce(callback));
}

TEST_F(RmadInterfaceImplTest, GetCurrentState_NotSet) {
  base::FilePath json_store_file_path =
      CreateInputFile(kJsonStoreFileName, kCurrentStateNotSetJson,
                      std::size(kCurrentStateNotSetJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManager(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::kWelcome, rmad_interface.GetCurrentStateCase());

  auto callback = [](const GetStateReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_OK, reply.error());
    EXPECT_EQ(RmadState::kWelcome, reply.state().state_case());
    EXPECT_FALSE(reply.can_go_back());
    EXPECT_TRUE(reply.can_abort());
    EXPECT_FALSE(quit_daemon);
  };
  rmad_interface.GetCurrentState(base::BindOnce(callback));
}

TEST_F(RmadInterfaceImplTest, GetCurrentState_WithHistory) {
  base::FilePath json_store_file_path = CreateInputFile(
      kJsonStoreFileName, kCurrentStateWithRepeatableHistoryJson,
      std::size(kCurrentStateWithRepeatableHistoryJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManager(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::kComponentsRepair, rmad_interface.GetCurrentStateCase());

  auto callback = [](const GetStateReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_OK, reply.error());
    EXPECT_EQ(RmadState::kComponentsRepair, reply.state().state_case());
    EXPECT_TRUE(reply.can_go_back());
    EXPECT_TRUE(reply.can_abort());
    EXPECT_FALSE(quit_daemon);
  };
  rmad_interface.GetCurrentState(base::BindOnce(callback));
}

TEST_F(RmadInterfaceImplTest, GetCurrentState_WithUnsupportedState) {
  base::FilePath json_store_file_path =
      CreateInputFile(kJsonStoreFileName, kCurrentStateWithUnsupportedStateJson,
                      std::size(kCurrentStateWithUnsupportedStateJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManager(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::kComponentsRepair, rmad_interface.GetCurrentStateCase());

  auto callback = [](const GetStateReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_OK, reply.error());
    EXPECT_EQ(RmadState::kComponentsRepair, reply.state().state_case());
    EXPECT_TRUE(reply.can_go_back());
    EXPECT_TRUE(reply.can_abort());
    EXPECT_FALSE(quit_daemon);
  };
  // TODO(gavindodd): Use mock log to check for expected error.
  rmad_interface.GetCurrentState(base::BindOnce(callback));
}

TEST_F(RmadInterfaceImplTest, GetCurrentState_InvalidState) {
  base::FilePath json_store_file_path =
      CreateInputFile(kJsonStoreFileName, kCurrentStateInvalidStateJson,
                      std::size(kCurrentStateInvalidStateJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManager(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::kWelcome, rmad_interface.GetCurrentStateCase());

  auto callback = [](const GetStateReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_OK, reply.error());
    EXPECT_EQ(RmadState::kWelcome, reply.state().state_case());
    EXPECT_FALSE(reply.can_go_back());
    EXPECT_TRUE(reply.can_abort());
    EXPECT_FALSE(quit_daemon);
  };
  rmad_interface.GetCurrentState(base::BindOnce(callback));
}

TEST_F(RmadInterfaceImplTest, GetCurrentState_InvalidJson) {
  base::FilePath json_store_file_path = CreateInputFile(
      kJsonStoreFileName, kInvalidJson, std::size(kInvalidJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManager(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::kWelcome, rmad_interface.GetCurrentStateCase());

  auto callback = [](const GetStateReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_OK, reply.error());
    EXPECT_EQ(RmadState::kWelcome, reply.state().state_case());
    EXPECT_FALSE(reply.can_go_back());
    EXPECT_TRUE(reply.can_abort());
    EXPECT_FALSE(quit_daemon);
  };
  rmad_interface.GetCurrentState(base::BindOnce(callback));
}

TEST_F(RmadInterfaceImplTest, GetCurrentState_InitializeStateFail) {
  base::FilePath json_store_file_path =
      CreateInputFile(kJsonStoreFileName, kInitializeCurrentStateFailJson,
                      std::size(kInitializeCurrentStateFailJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManagerInitializeStateFail(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::kWelcome, rmad_interface.GetCurrentStateCase());

  auto callback = [](const GetStateReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_MISSING_COMPONENT, reply.error());
    EXPECT_FALSE(reply.has_state());
    EXPECT_FALSE(quit_daemon);
  };
  rmad_interface.GetCurrentState(base::BindOnce(callback));
}

TEST_F(RmadInterfaceImplTest, TransitionNextState) {
  base::FilePath json_store_file_path =
      CreateInputFile(kJsonStoreFileName, kCurrentStateSetJson,
                      std::size(kCurrentStateSetJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManager(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_TRUE(rmad_interface.CanAbort());
  EXPECT_EQ(RmadState::kWelcome, rmad_interface.GetCurrentStateCase());
  auto callback1 = [](const GetStateReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_OK, reply.error());
    EXPECT_EQ(RmadState::kWelcome, reply.state().state_case());
    EXPECT_FALSE(reply.can_go_back());
    EXPECT_TRUE(reply.can_abort());
    EXPECT_FALSE(quit_daemon);
  };
  rmad_interface.GetCurrentState(base::BindOnce(callback1));

  task_environment_.FastForwardBy(kTestTransitionInterval);

  TransitionNextStateRequest request;
  auto callback2 = [](const GetStateReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_OK, reply.error());
    EXPECT_EQ(RmadState::kComponentsRepair, reply.state().state_case());
    EXPECT_TRUE(reply.can_go_back());
    EXPECT_TRUE(reply.can_abort());
    EXPECT_FALSE(quit_daemon);
  };
  rmad_interface.TransitionNextState(request, base::BindOnce(callback2));
  EXPECT_TRUE(rmad_interface.CanAbort());
  std::map<int, StateMetricsData> state_metrics;
  EXPECT_TRUE(
      MetricsUtils::GetMetricsValue(json_store, kStateMetrics, &state_metrics));
  EXPECT_DOUBLE_EQ(
      state_metrics[static_cast<int>(RmadState::kWelcome)].overall_time,
      kInitialStateOverallTime.InSecondsF());
  EXPECT_EQ(RmadState::kComponentsRepair, rmad_interface.GetCurrentStateCase());

  task_environment_.FastForwardBy(kTestTransitionInterval);

  auto callback3 = [](const GetStateReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_OK, reply.error());
    EXPECT_EQ(RmadState::kDeviceDestination, reply.state().state_case());
    EXPECT_FALSE(reply.can_go_back());
    EXPECT_FALSE(reply.can_abort());
    EXPECT_FALSE(quit_daemon);
  };
  rmad_interface.TransitionNextState(request, base::BindOnce(callback3));
  EXPECT_EQ(RmadState::kDeviceDestination,
            rmad_interface.GetCurrentStateCase());
  EXPECT_FALSE(rmad_interface.CanAbort());
  EXPECT_TRUE(
      MetricsUtils::GetMetricsValue(json_store, kStateMetrics, &state_metrics));
  EXPECT_DOUBLE_EQ(state_metrics[static_cast<int>(RmadState::kComponentsRepair)]
                       .overall_time,
                   kTestTransitionInterval.InSecondsF());
  EXPECT_EQ(RmadState::kDeviceDestination,
            rmad_interface.GetCurrentStateCase());

  // Verify that state transitions were recorded to logs.
  base::Value logs(base::Value::Type::DICT);
  json_store->GetValue(kLogs, &logs);
  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  EXPECT_EQ(3, events->size());

  const base::Value::Dict& event = (*events)[0].GetDict();
  EXPECT_EQ(static_cast<int>(RmadState::kWelcome), event.FindInt(kStateId));

  const base::Value::Dict& event1 = (*events)[1].GetDict();
  EXPECT_EQ(static_cast<int>(RmadState::kWelcome),
            event1.FindDict(kDetails)->FindInt(kFromStateId));
  EXPECT_EQ(static_cast<int>(RmadState::kComponentsRepair),
            event1.FindDict(kDetails)->FindInt(kToStateId));

  const base::Value::Dict& event2 = (*events)[2].GetDict();
  EXPECT_EQ(static_cast<int>(RmadState::kComponentsRepair),
            event2.FindDict(kDetails)->FindInt(kFromStateId));
  EXPECT_EQ(static_cast<int>(RmadState::kDeviceDestination),
            event2.FindDict(kDetails)->FindInt(kToStateId));
}

TEST_F(RmadInterfaceImplTest, TransitionNextStateAfterInterval) {
  base::FilePath json_store_file_path =
      CreateInputFile(kJsonStoreFileName, kCurrentStateNotSetJson,
                      std::size(kCurrentStateNotSetJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManager(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::kWelcome, rmad_interface.GetCurrentStateCase());

  // Set up again after a while.
  task_environment_.FastForwardBy(kTestTransitionInterval);
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::kWelcome, rmad_interface.GetCurrentStateCase());

  task_environment_.FastForwardBy(kTestTransitionInterval);

  TransitionNextStateRequest request;
  auto callback = [](const GetStateReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_OK, reply.error());
    EXPECT_EQ(RmadState::kComponentsRepair, reply.state().state_case());
    EXPECT_TRUE(reply.can_go_back());
    EXPECT_TRUE(reply.can_abort());
    EXPECT_FALSE(quit_daemon);
  };
  rmad_interface.TransitionNextState(request, base::BindOnce(callback));
  EXPECT_EQ(RmadState::kComponentsRepair, rmad_interface.GetCurrentStateCase());

  std::map<int, StateMetricsData> state_metrics;
  EXPECT_TRUE(
      MetricsUtils::GetMetricsValue(json_store, kStateMetrics, &state_metrics));
  EXPECT_DOUBLE_EQ(
      state_metrics[static_cast<int>(RmadState::kWelcome)].overall_time,
      kInitialStateOverallTime.InSecondsF());

  // Verify that state transitions were recorded to logs.
  base::Value logs(base::Value::Type::DICT);
  json_store->GetValue(kLogs, &logs);
  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  EXPECT_EQ(2, events->size());

  const base::Value::Dict& event = (*events)[0].GetDict();
  EXPECT_EQ(static_cast<int>(RmadState::kWelcome), event.FindInt(kStateId));

  const base::Value::Dict& event1 = (*events)[1].GetDict();
  EXPECT_EQ(static_cast<int>(RmadState::kWelcome),
            event1.FindDict(kDetails)->FindInt(kFromStateId));
  EXPECT_EQ(static_cast<int>(RmadState::kComponentsRepair),
            event1.FindDict(kDetails)->FindInt(kToStateId));
}

TEST_F(RmadInterfaceImplTest, TryTransitionNextState) {
  base::FilePath json_store_file_path =
      CreateInputFile(kJsonStoreFileName, kCurrentStateSetJson,
                      std::size(kCurrentStateSetJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManager(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_TRUE(rmad_interface.CanAbort());
  EXPECT_EQ(RmadState::kWelcome, rmad_interface.GetCurrentStateCase());
  rmad_interface.TryTransitionNextStateFromCurrentState();
  EXPECT_TRUE(rmad_interface.CanAbort());
  EXPECT_EQ(RmadState::kComponentsRepair, rmad_interface.GetCurrentStateCase());
  rmad_interface.TryTransitionNextStateFromCurrentState();
  EXPECT_FALSE(rmad_interface.CanAbort());
  EXPECT_EQ(RmadState::kDeviceDestination,
            rmad_interface.GetCurrentStateCase());
}

TEST_F(RmadInterfaceImplTest, TransitionNextState_MissingHandler) {
  base::FilePath json_store_file_path =
      CreateInputFile(kJsonStoreFileName, kCurrentStateSetJson,
                      std::size(kCurrentStateSetJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManagerMissingHandler(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::kWelcome, rmad_interface.GetCurrentStateCase());

  TransitionNextStateRequest request;
  rmad_interface.TransitionNextState(request, base::DoNothing());
  // Missing state handler of the next state detected, stay in the current
  // state.
  EXPECT_EQ(RmadState::kWelcome, rmad_interface.GetCurrentStateCase());
}

TEST_F(RmadInterfaceImplTest, TransitionNextState_InitializeNextStateFail) {
  base::FilePath json_store_file_path =
      CreateInputFile(kJsonStoreFileName, kInitializeNextStateFailJson,
                      std::size(kInitializeNextStateFailJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManagerInitializeStateFail(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::kComponentsRepair, rmad_interface.GetCurrentStateCase());

  TransitionNextStateRequest request;
  auto callback = [](const GetStateReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_DEVICE_INFO_INVALID, reply.error());
    EXPECT_EQ(RmadState::kComponentsRepair, reply.state().state_case());
    EXPECT_TRUE(reply.can_go_back());
    EXPECT_TRUE(reply.can_abort());
    EXPECT_FALSE(quit_daemon);
  };
  rmad_interface.TransitionNextState(request, base::BindOnce(callback));
  EXPECT_EQ(RmadState::kComponentsRepair, rmad_interface.GetCurrentStateCase());
}

TEST_F(RmadInterfaceImplTest, TransitionNextState_GetNextStateCaseFail) {
  base::FilePath json_store_file_path =
      CreateInputFile(kJsonStoreFileName, kCurrentStateSetJson,
                      std::size(kCurrentStateSetJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManagerGetNextStateCaseFail(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_TRUE(rmad_interface.CanAbort());
  EXPECT_EQ(RmadState::kWelcome, rmad_interface.GetCurrentStateCase());

  TransitionNextStateRequest request;
  auto callback = [](const GetStateReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_REQUEST_ARGS_MISSING, reply.error());
    EXPECT_EQ(RmadState::kWelcome, reply.state().state_case());
    EXPECT_FALSE(reply.can_go_back());
    EXPECT_TRUE(reply.can_abort());
    EXPECT_FALSE(quit_daemon);
  };
  rmad_interface.TransitionNextState(request, base::BindOnce(callback));
}

TEST_F(RmadInterfaceImplTest, TransitionPreviousState) {
  base::FilePath json_store_file_path =
      CreateInputFile(kJsonStoreFileName, kCurrentStateSetJson,
                      std::size(kCurrentStateSetJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManager(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::kWelcome, rmad_interface.GetCurrentStateCase());

  task_environment_.FastForwardBy(kTestTransitionInterval);

  TransitionNextStateRequest request;
  auto callback1 = [](const GetStateReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_OK, reply.error());
    EXPECT_EQ(RmadState::kComponentsRepair, reply.state().state_case());
    EXPECT_TRUE(reply.can_go_back());
    EXPECT_TRUE(reply.can_abort());
    EXPECT_FALSE(quit_daemon);
  };
  rmad_interface.TransitionNextState(request, base::BindOnce(callback1));
  EXPECT_EQ(RmadState::kComponentsRepair, rmad_interface.GetCurrentStateCase());

  task_environment_.FastForwardBy(kTestTransitionInterval);

  auto callback2 = [](const GetStateReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_OK, reply.error());
    EXPECT_EQ(RmadState::kWelcome, reply.state().state_case());
    EXPECT_FALSE(reply.can_go_back());
    EXPECT_TRUE(reply.can_abort());
    EXPECT_FALSE(quit_daemon);
  };
  rmad_interface.TransitionPreviousState(base::BindOnce(callback2));
  EXPECT_EQ(RmadState::kWelcome, rmad_interface.GetCurrentStateCase());

  std::map<int, StateMetricsData> state_metrics;
  EXPECT_TRUE(
      MetricsUtils::GetMetricsValue(json_store, kStateMetrics, &state_metrics));
  EXPECT_DOUBLE_EQ(
      state_metrics[static_cast<int>(RmadState::kWelcome)].overall_time,
      kInitialStateOverallTime.InSecondsF());
  EXPECT_DOUBLE_EQ(state_metrics[static_cast<int>(RmadState::kComponentsRepair)]
                       .overall_time,
                   kTestTransitionInterval.InSecondsF());

  // Verify that state transitions were recorded to logs.
  base::Value logs(base::Value::Type::DICT);
  json_store->GetValue(kLogs, &logs);
  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  EXPECT_EQ(3, events->size());

  const base::Value::Dict& event = (*events)[0].GetDict();
  EXPECT_EQ(static_cast<int>(RmadState::kWelcome), event.FindInt(kStateId));

  const base::Value::Dict& event1 = (*events)[1].GetDict();
  EXPECT_EQ(static_cast<int>(RmadState::kWelcome),
            event1.FindDict(kDetails)->FindInt(kFromStateId));
  EXPECT_EQ(static_cast<int>(RmadState::kComponentsRepair),
            event1.FindDict(kDetails)->FindInt(kToStateId));

  const base::Value::Dict& event2 = (*events)[2].GetDict();
  EXPECT_EQ(static_cast<int>(RmadState::kComponentsRepair),
            event2.FindDict(kDetails)->FindInt(kFromStateId));
  EXPECT_EQ(static_cast<int>(RmadState::kWelcome),
            event2.FindDict(kDetails)->FindInt(kToStateId));
}

TEST_F(RmadInterfaceImplTest, TransitionPreviousState_NoHistory) {
  base::FilePath json_store_file_path =
      CreateInputFile(kJsonStoreFileName, kCurrentStateSetJson,
                      std::size(kCurrentStateSetJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManager(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::kWelcome, rmad_interface.GetCurrentStateCase());

  auto callback = [](const GetStateReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_TRANSITION_FAILED, reply.error());
    EXPECT_EQ(RmadState::kWelcome, reply.state().state_case());
    EXPECT_FALSE(reply.can_go_back());
    EXPECT_TRUE(reply.can_abort());
    EXPECT_FALSE(quit_daemon);
  };
  rmad_interface.TransitionPreviousState(base::BindOnce(callback));
  EXPECT_EQ(RmadState::kWelcome, rmad_interface.GetCurrentStateCase());
}

TEST_F(RmadInterfaceImplTest, TransitionPreviousState_MissingHandler) {
  base::FilePath json_store_file_path = CreateInputFile(
      kJsonStoreFileName, kCurrentStateWithRepeatableHistoryJson,
      std::size(kCurrentStateWithRepeatableHistoryJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManagerMissingHandler(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::kWelcome, rmad_interface.GetCurrentStateCase());

  auto callback = [](const GetStateReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_TRANSITION_FAILED, reply.error());
    EXPECT_EQ(RmadState::kWelcome, reply.state().state_case());
    EXPECT_FALSE(reply.can_go_back());
    EXPECT_TRUE(reply.can_abort());
    EXPECT_FALSE(quit_daemon);
  };
  rmad_interface.TransitionPreviousState(base::BindOnce(callback));
  EXPECT_EQ(RmadState::kWelcome, rmad_interface.GetCurrentStateCase());
}

TEST_F(RmadInterfaceImplTest,
       TransitionPreviousState_InitializePreviousStateFail) {
  base::FilePath json_store_file_path =
      CreateInputFile(kJsonStoreFileName, kInitializePreviousStateFailJson,
                      std::size(kInitializePreviousStateFailJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManagerInitializeStateFail(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::kComponentsRepair, rmad_interface.GetCurrentStateCase());

  auto callback = [](const GetStateReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_MISSING_COMPONENT, reply.error());
    EXPECT_EQ(RmadState::kComponentsRepair, reply.state().state_case());
    EXPECT_TRUE(reply.can_go_back());
    EXPECT_TRUE(reply.can_abort());
    EXPECT_FALSE(quit_daemon);
  };
  rmad_interface.TransitionPreviousState(base::BindOnce(callback));
  EXPECT_EQ(RmadState::kComponentsRepair, rmad_interface.GetCurrentStateCase());
}

TEST_F(RmadInterfaceImplTest, AbortRma) {
  base::FilePath json_store_file_path = CreateInputFile(
      kJsonStoreFileName, kCurrentStateWithRepeatableHistoryJson,
      std::size(kCurrentStateWithRepeatableHistoryJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManager(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::kComponentsRepair, rmad_interface.GetCurrentStateCase());

  // Check that the state file exists now.
  EXPECT_TRUE(base::PathExists(json_store_file_path));

  auto callback = [](const AbortRmaReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_RMA_NOT_REQUIRED, reply.error());
    EXPECT_TRUE(quit_daemon);
  };
  rmad_interface.AbortRma(base::BindOnce(callback));
  EXPECT_EQ(RmadState::STATE_NOT_SET, rmad_interface.GetCurrentStateCase());

  // Check the the state file is cleared.
  EXPECT_FALSE(base::PathExists(json_store_file_path));
}

TEST_F(RmadInterfaceImplTest, AbortRma_NoHistory) {
  base::FilePath json_store_file_path =
      CreateInputFile(kJsonStoreFileName, kCurrentStateSetJson,
                      std::size(kCurrentStateSetJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManager(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::kWelcome, rmad_interface.GetCurrentStateCase());

  // Check that the state file exists now.
  EXPECT_TRUE(base::PathExists(json_store_file_path));

  auto callback = [](const AbortRmaReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_RMA_NOT_REQUIRED, reply.error());
    EXPECT_TRUE(quit_daemon);
  };
  rmad_interface.AbortRma(base::BindOnce(callback));
  EXPECT_EQ(RmadState::STATE_NOT_SET, rmad_interface.GetCurrentStateCase());

  // Check the the state file is cleared.
  EXPECT_FALSE(base::PathExists(json_store_file_path));
}

TEST_F(RmadInterfaceImplTest, AbortRma_Failed) {
  base::FilePath json_store_file_path = CreateInputFile(
      kJsonStoreFileName, kCurrentStateWithUnrepeatableHistoryJson,
      std::size(kCurrentStateWithUnrepeatableHistoryJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManager(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::kDeviceDestination,
            rmad_interface.GetCurrentStateCase());

  // Check that the state file exists now.
  EXPECT_TRUE(base::PathExists(json_store_file_path));

  auto callback = [](const AbortRmaReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_ABORT_FAILED, reply.error());
    EXPECT_FALSE(quit_daemon);
  };
  rmad_interface.AbortRma(base::BindOnce(callback));
  EXPECT_EQ(RmadState::kDeviceDestination,
            rmad_interface.GetCurrentStateCase());

  // Check the the state file still exists.
  EXPECT_TRUE(base::PathExists(json_store_file_path));
}

TEST_F(RmadInterfaceImplTest, GetLog) {
  base::FilePath json_store_file_path =
      CreateInputFile(kJsonStoreFileName, kStateHistoryWithMetricsJson,
                      std::size(kStateHistoryWithMetricsJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManager(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(),
      CreateCmdUtils({}, {"test_log"}), CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::kComponentsRepair, rmad_interface.GetCurrentStateCase());

  auto callback1 = [](const GetLogReply& reply, bool quit_daemon) {
    EXPECT_FALSE(reply.log().empty());
    EXPECT_FALSE(quit_daemon);
  };
  rmad_interface.GetLog(base::BindOnce(callback1));

  std::map<int, StateMetricsData> state_metrics;
  EXPECT_TRUE(
      MetricsUtils::GetMetricsValue(json_store, kStateMetrics, &state_metrics));
  auto state_it =
      state_metrics.find(static_cast<int>(RmadState::kComponentsRepair));
  EXPECT_NE(state_it, state_metrics.end());
  EXPECT_EQ(state_it->second.get_log_count, 1);

  auto callback2 = [](const GetLogReply& reply, bool quit_daemon) {
    EXPECT_FALSE(reply.log().empty());
    EXPECT_FALSE(quit_daemon);
  };
  rmad_interface.GetLog(base::BindOnce(callback2));

  EXPECT_TRUE(
      MetricsUtils::GetMetricsValue(json_store, kStateMetrics, &state_metrics));
  state_it = state_metrics.find(static_cast<int>(RmadState::kComponentsRepair));
  EXPECT_NE(state_it, state_metrics.end());
  EXPECT_EQ(state_it->second.get_log_count, 2);
}

TEST_F(RmadInterfaceImplTest, SaveLog_Success) {
  base::FilePath json_store_file_path =
      CreateInputFile(kJsonStoreFileName, "", 0);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManager(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(10), CreateCmdUtils(),
      CreateMetricsUtils(true));
  // Inject fake |ExecuteMountAndWriteLog| callback.
  auto daemon_callback = base::MakeRefCounted<DaemonCallback>();
  daemon_callback->SetExecuteMountAndWriteLogCallback(
      base::BindRepeating(&RmadInterfaceImplTest::MountAndWriteLogCallback,
                          base::Unretained(this)));
  EXPECT_TRUE(rmad_interface.SetUp(daemon_callback));
  EXPECT_EQ(RmadState::kWelcome, rmad_interface.GetCurrentStateCase());

  auto callback = [](const SaveLogReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_OK, reply.error());
    EXPECT_EQ("rma.log", reply.save_path());
    EXPECT_FALSE(quit_daemon);
  };
  rmad_interface.SaveLog("", base::BindOnce(callback));

  std::map<int, StateMetricsData> state_metrics;
  EXPECT_TRUE(
      MetricsUtils::GetMetricsValue(json_store, kStateMetrics, &state_metrics));
  auto state_it = state_metrics.find(static_cast<int>(RmadState::kWelcome));
  EXPECT_NE(state_it, state_metrics.end());
  EXPECT_EQ(state_it->second.save_log_count, 1);
}

TEST_F(RmadInterfaceImplTest, SaveLog_NoExternalDisk) {
  base::FilePath json_store_file_path =
      CreateInputFile(kJsonStoreFileName, "", 0);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManager(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(0), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::kWelcome, rmad_interface.GetCurrentStateCase());

  auto callback = [](const SaveLogReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_USB_NOT_FOUND, reply.error());
    EXPECT_FALSE(quit_daemon);
  };
  rmad_interface.SaveLog("", base::BindOnce(callback));

  std::map<int, StateMetricsData> state_metrics;
  EXPECT_TRUE(
      MetricsUtils::GetMetricsValue(json_store, kStateMetrics, &state_metrics));
  auto state_it = state_metrics.find(static_cast<int>(RmadState::kWelcome));
  EXPECT_NE(state_it, state_metrics.end());
  EXPECT_EQ(state_it->second.save_log_count, 0);
}

TEST_F(RmadInterfaceImplTest, SaveLog_MountFail) {
  base::FilePath json_store_file_path =
      CreateInputFile(kJsonStoreFileName, "", 0);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManager(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(3), CreateCmdUtils(),
      CreateMetricsUtils(true));
  // Inject fake |ExecuteMountAndWriteLog| callback.
  auto daemon_callback = base::MakeRefCounted<DaemonCallback>();
  daemon_callback->SetExecuteMountAndWriteLogCallback(
      base::BindRepeating(&RmadInterfaceImplTest::MountAndWriteLogCallback,
                          base::Unretained(this)));
  EXPECT_TRUE(rmad_interface.SetUp(daemon_callback));

  auto callback = [](const SaveLogReply& reply, bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_CANNOT_SAVE_LOG, reply.error());
    EXPECT_FALSE(quit_daemon);
  };
  rmad_interface.SaveLog("", base::BindOnce(callback));

  std::map<int, StateMetricsData> state_metrics;
  EXPECT_TRUE(
      MetricsUtils::GetMetricsValue(json_store, kStateMetrics, &state_metrics));
  auto state_it = state_metrics.find(static_cast<int>(RmadState::kWelcome));
  EXPECT_NE(state_it, state_metrics.end());
  EXPECT_EQ(state_it->second.save_log_count, 0);
}

TEST_F(RmadInterfaceImplTest, RecordBrowserActionMetric) {
  base::FilePath json_store_file_path =
      CreateInputFile(kJsonStoreFileName, "", 0);
  auto json_store = base::MakeRefCounted<JsonStore>(json_store_file_path);
  RmadInterfaceImpl rmad_interface(
      json_store, CreateStateHandlerManager(json_store),
      CreateRuntimeProbeClient(false), CreateShillClient(nullptr),
      CreateTpmManagerClient(RMAD_RO_VERIFICATION_NOT_TRIGGERED),
      CreatePowerManagerClient(), CreateUdevUtils(), CreateCmdUtils(),
      CreateMetricsUtils(true));
  EXPECT_TRUE(rmad_interface.SetUp(base::MakeRefCounted<DaemonCallback>()));
  EXPECT_EQ(RmadState::kWelcome, rmad_interface.GetCurrentStateCase());

  auto callback = [](const RecordBrowserActionMetricReply& reply,
                     bool quit_daemon) {
    EXPECT_EQ(RMAD_ERROR_OK, reply.error());
    EXPECT_FALSE(quit_daemon);
  };
  RecordBrowserActionMetricRequest request;
  request.set_diagnostics(true);
  request.set_os_update(true);

  rmad_interface.RecordBrowserActionMetric(request, base::BindOnce(callback));

  std::vector<std::string> additional_activities;
  EXPECT_TRUE(MetricsUtils::GetMetricsValue(
      json_store, kMetricsAdditionalActivities, &additional_activities));
  EXPECT_EQ(additional_activities,
            std::vector<std::string>(
                {AdditionalActivity_Name(RMAD_ADDITIONAL_ACTIVITY_DIAGNOSTICS),
                 AdditionalActivity_Name(RMAD_ADDITIONAL_ACTIVITY_OS_UPDATE)}));
}

}  // namespace rmad
