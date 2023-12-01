// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <cstring>
#include <iterator>
#include <memory>
#include <optional>

#if __has_include(<asm/bootparam.h>)
#include <asm/bootparam.h>
#define HAVE_BOOTPARAM
#endif
#include "absl/status/status.h"
#include "attestation/dbus-constants.h"
#include "attestation/proto_bindings/interface.pb.h"
#include "attestation-client-test/attestation/dbus-proxy-mocks.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/memory/scoped_refptr.h"
#include "base/run_loop.h"
#include "base/strings/stringprintf.h"
#include "base/test/task_environment.h"
#include "base/time/time.h"
#include "dbus/mock_bus.h"
#include "dbus/mock_object_proxy.h"
#include "gmock/gmock.h"  // IWYU pragma: keep
#include "gtest/gtest.h"
#include "missive/proto/record_constants.pb.h"
#include "missive/util/status.h"
#include "secagentd/plugins.h"
#include "secagentd/proto/security_xdr_events.pb.h"
#include "secagentd/test/mock_device_user.h"
#include "secagentd/test/mock_message_sender.h"
#include "tpm_manager/dbus-constants.h"
#include "tpm_manager/proto_bindings/tpm_manager.pb.h"
#include "tpm_manager-client-test/tpm_manager/dbus-proxy-mocks.h"

namespace secagentd::testing {

namespace pb = cros_xdr::reporting;

namespace {
ACTION_TEMPLATE(InvokeCallbackArgument,
                HAS_1_TEMPLATE_PARAMS(int, k),
                AND_1_VALUE_PARAMS(p0)) {
  // Runs it as base::OnceCallback anyway.
  std::move(
      const_cast<typename std::remove_cv<typename std::remove_reference<
          decltype(*std::get<k>(args))>::type>::type&>(*std::get<k>(args)))
      .Run(p0);
}
}  // namespace

using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::WithArg;
using ::testing::WithArgs;

struct BootmodeAndTpm {
  bool boot_mode;
  pb::TcbAttributes_FirmwareSecureBoot expected_firmware_secure_boot;
  tpm_manager::GscVersion gsc_version;
  pb::TcbAttributes_SecurityChip::Kind expected_security_chip_kind;
};

constexpr char kDeviceUser[] = "deviceUser@email.com";

class AgentPluginTestFixture : public ::testing::TestWithParam<BootmodeAndTpm> {
 protected:
  AgentPluginTestFixture()
      : task_environment_(base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}
  void SetUp() override {
    message_sender_ = base::MakeRefCounted<MockMessageSender>();
    device_user_ = base::MakeRefCounted<MockDeviceUser>();
    plugin_factory_ = std::make_unique<PluginFactory>();
    dbus::Bus::Options options;
    options.bus_type = dbus::Bus::SYSTEM;
    bus_ = new dbus::MockBus(options);
    heartbeat_timer = 300;
  }
  void TearDown() override { task_environment_.RunUntilIdle(); }

  void CreateAndRunAgentPlugin() {
    base::RunLoop run_loop = base::RunLoop();
    CreateAgentPlugin(&run_loop);
    EXPECT_OK(plugin_->Activate());
    run_loop.Run();
  }

  void CreateAgentPlugin(base::RunLoop* run_loop) {
    plugin_ = plugin_factory_->CreateAgentPlugin(
        message_sender_, device_user_, std::move(attestation_proxy_),
        std::move(tpm_manager_proxy_),
        base::BindOnce(
            [](base::RunLoop* run_loop) {
              if (run_loop) {
                run_loop->Quit();
              }
            },
            run_loop),
        heartbeat_timer);
    EXPECT_NE(nullptr, plugin_);
    agent_plugin_ = static_cast<AgentPlugin*>(plugin_.get());
  }

  void CheckTcbAttributes(pb::TcbAttributes tcb,
                          tpm_manager::GetVersionInfoReply tpm_information,
                          uint32_t level,
                          uint32_t revision,
                          std::string family,
                          std::string manufacturer) {
    EXPECT_EQ(pb::TcbAttributes_FirmwareSecureBoot_CROS_VERIFIED_BOOT,
              tcb.firmware_secure_boot());
    // Tpm information.
    EXPECT_EQ(base::StringPrintf("%s.%u.%u", family.c_str(), level, revision),
              tcb.security_chip().chip_version());
    EXPECT_EQ(pb::TcbAttributes_SecurityChip::Kind::
                  TcbAttributes_SecurityChip_Kind_TPM,
              tcb.security_chip().kind());
    EXPECT_EQ(family, tcb.security_chip().spec_family());
    EXPECT_EQ(std::to_string(level), tcb.security_chip().spec_level());
    EXPECT_EQ(manufacturer, tcb.security_chip().manufacturer());
    EXPECT_EQ(tpm_information.vendor_specific(),
              tcb.security_chip().vendor_id());
    EXPECT_EQ(std::to_string(tpm_information.tpm_model()),
              tcb.security_chip().tpm_model());
    EXPECT_EQ(std::to_string(tpm_information.firmware_version()),
              tcb.security_chip().firmware_version());
  }

  void SetupObjectProxies(bool available) {
    attestation_proxy_ =
        std::make_unique<org::chromium::AttestationProxyMock>();
    tpm_manager_proxy_ = std::make_unique<org::chromium::TpmManagerProxyMock>();
    attestation_object_proxy_ = new dbus::MockObjectProxy(
        bus_.get(), attestation::kAttestationServiceName,
        dbus::ObjectPath(attestation::kAttestationServicePath));
    tpm_manager_object_proxy_ = new dbus::MockObjectProxy(
        bus_.get(), tpm_manager::kTpmManagerServiceName,
        dbus::ObjectPath(tpm_manager::kTpmManagerServicePath));
    EXPECT_CALL(*attestation_proxy_, GetObjectProxy)
        .WillRepeatedly(Return(attestation_object_proxy_.get()));
    EXPECT_CALL(*tpm_manager_proxy_, GetObjectProxy)
        .WillRepeatedly(Return(tpm_manager_object_proxy_.get()));
    EXPECT_CALL(*attestation_object_proxy_, DoWaitForServiceToBeAvailable(_))
        .WillRepeatedly(InvokeCallbackArgument<0>(available));
    EXPECT_CALL(*tpm_manager_object_proxy_, DoWaitForServiceToBeAvailable(_))
        .WillRepeatedly(InvokeCallbackArgument<0>(available));
  }

  void CallGetCrosSecureBootInformation() {
    agent_plugin_->GetCrosSecureBootInformation(true);
  }

  void CallGetTpmInformation() { agent_plugin_->GetTpmInformation(true); }

  void CallGetUefiSecureBootInformation(
      const base::FilePath& boot_params_filepath) {
    agent_plugin_->GetUefiSecureBootInformation(boot_params_filepath);
  }

  pb::TcbAttributes GetTcbAttributes() {
    return agent_plugin_->tcb_attributes_;
  }

  base::test::TaskEnvironment task_environment_;
  scoped_refptr<MockMessageSender> message_sender_;
  scoped_refptr<dbus::MockBus> bus_;
  scoped_refptr<dbus::MockObjectProxy> attestation_object_proxy_;
  scoped_refptr<dbus::MockObjectProxy> tpm_manager_object_proxy_;
  scoped_refptr<MockDeviceUser> device_user_;
  std::unique_ptr<PluginFactory> plugin_factory_;
  std::unique_ptr<PluginInterface> plugin_;
  AgentPlugin* agent_plugin_;
  std::unique_ptr<org::chromium::AttestationProxyMock> attestation_proxy_;
  std::unique_ptr<org::chromium::TpmManagerProxyMock> tpm_manager_proxy_;
  uint32_t heartbeat_timer;
};

TEST_F(AgentPluginTestFixture, TestGetName) {
  CreateAgentPlugin(nullptr);
  ASSERT_EQ("Agent", plugin_->GetName());
}

TEST_F(AgentPluginTestFixture, TestSendStartEventServicesAvailable) {
  SetupObjectProxies(true);

  // Setup attestation GetStatus mock.
  EXPECT_CALL(*attestation_proxy_, GetStatus)
      .WillOnce(WithArg<1>(Invoke([](attestation::GetStatusReply* out_reply) {
        out_reply->set_verified_boot(true);
        return true;
      })));

  // Setup tpm_manager GetVersionInfo mock and
  // initialize tpm_information that the mock will return.
  tpm_manager::GetVersionInfoReply tpm_information;
  uint64_t level = 1;
  uint64_t revision = 2;
  int family_decimal = 841887744;
  std::string family_string = "2.0";
  int manufacturer_decimal = 1397312853;
  std::string manufacturer_string = "SIMU";
  tpm_information.set_gsc_version(tpm_manager::GSC_VERSION_NOT_GSC);
  tpm_information.set_family(family_decimal);
  tpm_information.set_spec_level((level << 32) | revision);
  tpm_information.set_manufacturer(manufacturer_decimal);
  tpm_information.set_vendor_specific("xCG fTPM");
  tpm_information.set_tpm_model(3);
  tpm_information.set_firmware_version(4);
  EXPECT_CALL(*tpm_manager_proxy_, GetTpmStatus)
      .WillOnce(
          WithArg<1>(Invoke([](tpm_manager::GetTpmStatusReply* out_reply) {
            out_reply->set_enabled(true);
            return true;
          })));
  EXPECT_CALL(*tpm_manager_proxy_, GetVersionInfo)
      .WillOnce(WithArg<1>(Invoke(
          [&tpm_information](tpm_manager::GetVersionInfoReply* out_reply) {
            out_reply->CopyFrom(tpm_information);
            return true;
          })));

  EXPECT_CALL(*device_user_, GetDeviceUser)
      .Times(3)
      .WillRepeatedly(Return(kDeviceUser));

  // Setup message sender mock. WillOnce is for StartEvent and
  // WillRepeatedly is for HeartbeatEvent.
  // In each case the sent proto will be deserialized into either a StartEvent
  // or HeartbeatEvent respectively.
  auto agent_start_message = std::make_unique<pb::XdrAgentEvent>();
  auto agent_heartbeat_message = std::make_unique<pb::XdrAgentEvent>();
  EXPECT_CALL(*message_sender_,
              SendMessage(reporting::Destination::CROS_SECURITY_AGENT, _, _, _))
      .Times(3)
      .WillOnce(WithArgs<2, 3>(Invoke(
          [&agent_start_message](
              std::unique_ptr<google::protobuf::MessageLite> message,
              std::optional<reporting::ReportQueue::EnqueueCallback> cb) {
            agent_start_message->ParseFromString(
                std::move(message->SerializeAsString()));

            EXPECT_TRUE(cb.has_value());
            std::move(cb.value()).Run(reporting::Status::StatusOK());
          })))
      .WillRepeatedly(WithArg<2>(
          Invoke([&agent_heartbeat_message](
                     std::unique_ptr<google::protobuf::MessageLite> message) {
            agent_heartbeat_message->ParseFromString(
                std::move(message->SerializeAsString()));
          })));

  CreateAndRunAgentPlugin();
  task_environment_.FastForwardBy(base::Minutes(10));

  // Check tcb attributes for agent start and heartbeat.
  EXPECT_EQ(1, agent_start_message->batched_events_size());
  CheckTcbAttributes(
      agent_start_message->batched_events()[0].agent_start().tcb(),
      tpm_information, level, revision, family_string, manufacturer_string);
  EXPECT_EQ(1, agent_heartbeat_message->batched_events_size());
  CheckTcbAttributes(
      agent_heartbeat_message->batched_events()[0].agent_heartbeat().tcb(),
      tpm_information, level, revision, family_string, manufacturer_string);

  EXPECT_EQ(kDeviceUser,
            agent_start_message->batched_events()[0].common().device_user());
  EXPECT_EQ(
      kDeviceUser,
      agent_heartbeat_message->batched_events()[0].common().device_user());
}

TEST_F(AgentPluginTestFixture, TestSetHeartbeatTimerNonzero) {
  SetupObjectProxies(false);

  EXPECT_CALL(*device_user_, GetDeviceUser)
      .Times(4)
      .WillRepeatedly(Return(kDeviceUser));

  EXPECT_CALL(*message_sender_,
              SendMessage(reporting::Destination::CROS_SECURITY_AGENT, _, _, _))
      .Times(4)
      .WillOnce(WithArgs<3>(
          Invoke([](std::optional<reporting::ReportQueue::EnqueueCallback> cb) {
            EXPECT_TRUE(cb.has_value());
            std::move(cb.value()).Run(reporting::Status::StatusOK());
          })))
      .WillRepeatedly(WithArgs<3>(
          Invoke([](std::optional<reporting::ReportQueue::EnqueueCallback> cb) {
            EXPECT_FALSE(cb.has_value());
          })));

  heartbeat_timer = 3;
  CreateAndRunAgentPlugin();
  task_environment_.FastForwardBy(base::Seconds(10));
}

TEST_F(AgentPluginTestFixture, TestSetHeartbeatTimerZero) {
  SetupObjectProxies(false);

  heartbeat_timer = 0;
  static constexpr double kTimePassed = 3.1;
  // When heartbeat timer is 0 seconds it defaults to 1.
  // Add 1 for Agent start.
  static constexpr int kTimes = 1 + kTimePassed / 1;

  EXPECT_CALL(*device_user_, GetDeviceUser)
      .Times(kTimes)
      .WillRepeatedly(Return(kDeviceUser));

  EXPECT_CALL(*message_sender_,
              SendMessage(reporting::Destination::CROS_SECURITY_AGENT, _, _, _))
      .Times(kTimes)
      .WillOnce(WithArgs<3>(
          Invoke([](std::optional<reporting::ReportQueue::EnqueueCallback> cb) {
            EXPECT_TRUE(cb.has_value());
            std::move(cb.value()).Run(reporting::Status::StatusOK());
          })))
      .WillRepeatedly(WithArgs<3>(
          Invoke([](std::optional<reporting::ReportQueue::EnqueueCallback> cb) {
            EXPECT_FALSE(cb.has_value());
          })));

  CreateAndRunAgentPlugin();
  task_environment_.FastForwardBy(base::Seconds(kTimePassed));
}

TEST_F(AgentPluginTestFixture, TestSendStartEventServicesUnvailable) {
  SetupObjectProxies(false);

  EXPECT_CALL(*device_user_, GetDeviceUser).WillOnce(Return(kDeviceUser));

  auto agent_message = std::make_unique<pb::XdrAgentEvent>();
  EXPECT_CALL(*message_sender_,
              SendMessage(reporting::Destination::CROS_SECURITY_AGENT, _, _, _))
      .WillOnce(WithArgs<2, 3>(Invoke(
          [&agent_message](
              std::unique_ptr<google::protobuf::MessageLite> message,
              std::optional<reporting::ReportQueue::EnqueueCallback> cb) {
            agent_message->ParseFromString(
                std::move(message->SerializeAsString()));

            EXPECT_TRUE(cb.has_value());
            std::move(cb.value()).Run(reporting::Status::StatusOK());
          })));

  CreateAndRunAgentPlugin();

  EXPECT_EQ(1, agent_message->batched_events_size());
  auto tcb = agent_message->batched_events()[0].agent_start().tcb();
  EXPECT_FALSE(tcb.has_firmware_secure_boot());
  EXPECT_FALSE(tcb.has_security_chip());

  EXPECT_EQ(kDeviceUser,
            agent_message->batched_events()[0].common().device_user());
}

TEST_F(AgentPluginTestFixture, TestSendStartEventServicesFailedToRetrieve) {
  SetupObjectProxies(true);

  EXPECT_CALL(*attestation_proxy_, GetStatus)
      .WillOnce(WithArgs<2>(Invoke([](brillo::ErrorPtr* error) {
        *error = brillo::Error::Create(FROM_HERE, "", "", "GetStatus failed");
        return false;
      })));
  EXPECT_CALL(*tpm_manager_proxy_, GetTpmStatus)
      .WillOnce(WithArgs<2>(Invoke([](brillo::ErrorPtr* error) {
        *error =
            brillo::Error::Create(FROM_HERE, "", "", "GetTpmStatus failed");
        return false;
      })));

  EXPECT_CALL(*device_user_, GetDeviceUser).WillOnce(Return(kDeviceUser));

  auto agent_message = std::make_unique<pb::AgentEventAtomicVariant>();
  EXPECT_CALL(*message_sender_,
              SendMessage(reporting::Destination::CROS_SECURITY_AGENT, _, _, _))
      .WillOnce(WithArgs<2, 3>(Invoke(
          [&agent_message](
              std::unique_ptr<google::protobuf::MessageLite> message,
              std::optional<reporting::ReportQueue::EnqueueCallback> cb) {
            agent_message->ParseFromString(
                std::move(message->SerializeAsString()));

            EXPECT_TRUE(cb.has_value());
            std::move(cb.value()).Run(reporting::Status::StatusOK());
          })));

  CreateAndRunAgentPlugin();

  auto tcb = agent_message->agent_start().tcb();
  EXPECT_FALSE(tcb.has_firmware_secure_boot());
  EXPECT_FALSE(tcb.has_security_chip());
}

TEST_F(AgentPluginTestFixture, TestSendStartEventFailure) {
  SetupObjectProxies(false);

  EXPECT_CALL(*device_user_, GetDeviceUser)
      .Times(4)
      .WillRepeatedly(Return(kDeviceUser));

  EXPECT_CALL(*message_sender_,
              SendMessage(reporting::Destination::CROS_SECURITY_AGENT, _, _, _))
      .Times(4)
      .WillRepeatedly(WithArg<3>(
          Invoke([](std::optional<reporting::ReportQueue::EnqueueCallback> cb) {
            EXPECT_TRUE(cb.has_value());
            std::move(cb.value())
                .Run(
                    reporting::Status(reporting::error::UNAVAILABLE, "Failed"));
          })));

  CreateAgentPlugin(nullptr);
  EXPECT_OK(plugin_->Activate());
  task_environment_.FastForwardBy(base::Seconds(10));
}

#ifdef HAVE_BOOTPARAM
TEST_F(AgentPluginTestFixture, TestUefiSecureBootFileExistsEnabled) {
  base::FilePath boot_params_filepath;
  base::CreateTemporaryFile(&boot_params_filepath);

  boot_params boot;
  static constexpr int kEfiSecurebootModeEnabled = 3;
  boot.secure_boot = kEfiSecurebootModeEnabled;
  base::WriteFile(boot_params_filepath, reinterpret_cast<char*>(&boot),
                  sizeof(boot));

  CreateAgentPlugin(nullptr);
  CallGetUefiSecureBootInformation(boot_params_filepath);

  auto tcb = GetTcbAttributes();
  EXPECT_EQ(pb::TcbAttributes_FirmwareSecureBoot_CROS_FLEX_UEFI_SECURE_BOOT,
            tcb.firmware_secure_boot());
}

TEST_F(AgentPluginTestFixture, TestUefiSecureBootFileExistsNotEnabled) {
  base::FilePath boot_params_filepath;
  base::CreateTemporaryFile(&boot_params_filepath);

  boot_params boot;
  boot.secure_boot = -1;
  base::WriteFile(boot_params_filepath, reinterpret_cast<char*>(&boot),
                  sizeof(boot));

  CreateAgentPlugin(nullptr);
  CallGetUefiSecureBootInformation(boot_params_filepath);

  auto tcb = GetTcbAttributes();
  EXPECT_FALSE(tcb.has_firmware_secure_boot());
}

TEST_F(AgentPluginTestFixture, TestUefiSecureBootFileInvalidSize) {
  base::FilePath boot_params_filepath;
  base::CreateTemporaryFile(&boot_params_filepath);

  std::string content = "invalid file size";
  base::WriteFile(boot_params_filepath, content.c_str(), content.size());

  CreateAgentPlugin(nullptr);
  CallGetUefiSecureBootInformation(boot_params_filepath);

  auto tcb = GetTcbAttributes();
  EXPECT_FALSE(tcb.has_firmware_secure_boot());
}
#endif

TEST_F(AgentPluginTestFixture, TestUefiSecureBootFileDoesNotExist) {
  CreateAgentPlugin(nullptr);
  base::FilePath non_existent_filepath = base::FilePath("badfile");
  CallGetUefiSecureBootInformation(non_existent_filepath);

  auto tcb = GetTcbAttributes();
  EXPECT_FALSE(tcb.has_firmware_secure_boot());
}

TEST_F(AgentPluginTestFixture, TestNoTpm) {
  SetupObjectProxies(false);
  EXPECT_CALL(*tpm_manager_proxy_, GetTpmStatus)
      .WillOnce(
          WithArg<1>(Invoke([](tpm_manager::GetTpmStatusReply* out_reply) {
            out_reply->set_enabled(true);
            return true;
          })));
  EXPECT_CALL(*tpm_manager_proxy_, GetVersionInfo)
      .WillOnce(WithArg<1>(Invoke(
          [](tpm_manager::GetVersionInfoReply* out_reply) { return true; })));

  CreateAgentPlugin(nullptr);
  CallGetTpmInformation();
  EXPECT_EQ(pb::TcbAttributes_SecurityChip_Kind_NONE,
            GetTcbAttributes().security_chip().kind());
}

TEST_F(AgentPluginTestFixture, TestTpmDisabled) {
  SetupObjectProxies(false);
  EXPECT_CALL(*tpm_manager_proxy_, GetTpmStatus)
      .WillOnce(
          WithArg<1>(Invoke([](tpm_manager::GetTpmStatusReply* out_reply) {
            out_reply->set_enabled(false);
            return true;
          })));

  CreateAgentPlugin(nullptr);
  CallGetTpmInformation();
  EXPECT_FALSE(GetTcbAttributes().has_security_chip());
}

TEST_P(AgentPluginTestFixture, TestBootAndTpmModes) {
  SetupObjectProxies(false);
  const BootmodeAndTpm param = GetParam();

  EXPECT_CALL(*attestation_proxy_, GetStatus)
      .WillOnce(
          WithArg<1>(Invoke([&param](attestation::GetStatusReply* out_reply) {
            out_reply->set_verified_boot(param.boot_mode);
            return true;
          })));
  EXPECT_CALL(*tpm_manager_proxy_, GetTpmStatus)
      .WillOnce(
          WithArg<1>(Invoke([](tpm_manager::GetTpmStatusReply* out_reply) {
            out_reply->set_enabled(true);
            return true;
          })));
  EXPECT_CALL(*tpm_manager_proxy_, GetVersionInfo)
      .WillOnce(WithArg<1>(
          Invoke([&param](tpm_manager::GetVersionInfoReply* out_reply) {
            out_reply->set_gsc_version(param.gsc_version);
            return true;
          })));

  CreateAgentPlugin(nullptr);
  CallGetCrosSecureBootInformation();
  CallGetTpmInformation();

  auto tcb = GetTcbAttributes();
  EXPECT_EQ(param.expected_firmware_secure_boot, tcb.firmware_secure_boot());
  EXPECT_EQ(param.expected_security_chip_kind, tcb.security_chip().kind());
}

INSTANTIATE_TEST_SUITE_P(
    AgentPluginTestFixture,
    AgentPluginTestFixture,
    ::testing::ValuesIn<BootmodeAndTpm>({
        {false, pb::TcbAttributes_FirmwareSecureBoot_NONE,
         tpm_manager::GscVersion::GSC_VERSION_NOT_GSC,
         pb::TcbAttributes_SecurityChip::Kind::
             TcbAttributes_SecurityChip_Kind_TPM},
        {false, pb::TcbAttributes_FirmwareSecureBoot_NONE,
         tpm_manager::GscVersion::GSC_VERSION_CR50,
         pb::TcbAttributes_SecurityChip_Kind_GOOGLE_SECURITY_CHIP},
        {false, pb::TcbAttributes_FirmwareSecureBoot_NONE,
         tpm_manager::GscVersion::GSC_VERSION_TI50,
         pb::TcbAttributes_SecurityChip_Kind_GOOGLE_SECURITY_CHIP},
        {true, pb::TcbAttributes_FirmwareSecureBoot_CROS_VERIFIED_BOOT,
         tpm_manager::GscVersion::GSC_VERSION_NOT_GSC,
         pb::TcbAttributes_SecurityChip::Kind::
             TcbAttributes_SecurityChip_Kind_TPM},
        {true, pb::TcbAttributes_FirmwareSecureBoot_CROS_VERIFIED_BOOT,
         tpm_manager::GscVersion::GSC_VERSION_CR50,
         pb::TcbAttributes_SecurityChip_Kind_GOOGLE_SECURITY_CHIP},
        {true, pb::TcbAttributes_FirmwareSecureBoot_CROS_VERIFIED_BOOT,
         tpm_manager::GscVersion::GSC_VERSION_TI50,
         pb::TcbAttributes_SecurityChip_Kind_GOOGLE_SECURITY_CHIP},
    }),
    [](const ::testing::TestParamInfo<AgentPluginTestFixture::ParamType>&
           info) {
      std::string boot_mode =
          info.param.boot_mode ? "CrosVerifiedBoot" : "NoBoot";
      std::string gsc_version;

      switch (info.param.gsc_version) {
        case tpm_manager::GscVersion::GSC_VERSION_NOT_GSC:
          gsc_version = "NotGSC";
          break;
        case tpm_manager::GscVersion::GSC_VERSION_CR50:
          gsc_version = "CR50";
          break;
        case tpm_manager::GscVersion::GSC_VERSION_TI50:
          gsc_version = "TI50";
          break;
      }
      return base::StringPrintf("%s_%s", boot_mode.c_str(),
                                gsc_version.c_str());
    });

}  // namespace secagentd::testing
