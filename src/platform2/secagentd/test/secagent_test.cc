// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "secagentd/secagent.h"

#include <cstdint>
#include <cstring>
#include <iterator>
#include <memory>
#include <optional>
#include <sysexits.h>

#include "absl/status/status.h"
#include "base/functional/bind.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "base/run_loop.h"
#include "base/strings/stringprintf.h"
#include "base/test/task_environment.h"
#include "gmock/gmock.h"  // IWYU pragma: keep
#include "gtest/gtest.h"
#include "metrics/metrics_library.h"
#include "secagentd/common.h"
#include "secagentd/plugins.h"
#include "secagentd/policies_features_broker.h"
#include "secagentd/test/mock_device_user.h"
#include "secagentd/test/mock_message_sender.h"
#include "secagentd/test/mock_plugin_factory.h"
#include "secagentd/test/mock_policies_features_broker.h"
#include "secagentd/test/mock_process_cache.h"
#include "session_manager/dbus-proxies.h"
#include "session_manager/dbus-proxy-mocks.h"

namespace secagentd::testing {

namespace pb = cros_xdr::reporting;

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::AtLeast;
using ::testing::AtMost;
using ::testing::ByMove;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::WithArg;
using ::testing::WithArgs;

struct XdrFeatureAndPolicy {
  bool xdr_feature_enabled;
  bool xdr_policy_enabled;
};
class MockSystemQuit {
 public:
  MOCK_METHOD(void, Quit, (int rv));
  base::WeakPtrFactory<MockSystemQuit> weak_factory_{this};
};
class SecAgentTestFixture
    : public ::testing::TestWithParam<XdrFeatureAndPolicy> {
 protected:
  SecAgentTestFixture() = default;
  void SetUp() override {
    agent_plugin_ = std::make_unique<MockPlugin>();
    agent_plugin_ref_ = agent_plugin_.get();

    process_plugin_ = std::make_unique<MockPlugin>();
    process_plugin_ref_ = process_plugin_.get();

    network_plugin_ = std::make_unique<MockPlugin>();
    network_plugin_ref_ = network_plugin_.get();

    plugin_factory_ = std::make_unique<MockPluginFactory>();
    plugin_factory_ref = plugin_factory_.get();

    message_sender_ = base::MakeRefCounted<MockMessageSender>();
    process_cache_ = base::MakeRefCounted<MockProcessCache>();
    policies_features_broker_ =
        base::MakeRefCounted<MockPoliciesFeaturesBroker>();
    device_user_ = base::MakeRefCounted<MockDeviceUser>();
    secagent_ = std::make_unique<SecAgent>(
        base::BindOnce(&MockSystemQuit::Quit,
                       mock_system_quit_.weak_factory_.GetWeakPtr()),
        message_sender_, process_cache_, device_user_,
        std::move(plugin_factory_),
        // attestation and tpm proxies.
        nullptr /* Attestation */, nullptr /* Tpm */,
        nullptr /* PlatformFeatures */, 0, 0, 300, 120, 10);
    secagent_->policies_features_broker_ = this->policies_features_broker_;

    ON_CALL(*process_plugin_ref_, GetName())
        .WillByDefault(Return("ProcessPluginTest"));
    ON_CALL(*network_plugin_ref_, GetName())
        .WillByDefault(Return("NetworkPluginTest"));
    ON_CALL(*agent_plugin_ref_, GetName())
        .WillByDefault(Return("AgentPluginRef"));

    ON_CALL(*process_plugin_ref_, IsActive).WillByDefault(Invoke([this]() {
      return process_plugin_ref_->is_active_;
    }));
    ON_CALL(*agent_plugin_ref_, IsActive).WillByDefault(Invoke([this] {
      return agent_plugin_ref_->is_active_;
    }));
    ON_CALL(*network_plugin_ref_, IsActive).WillByDefault(Invoke([this]() {
      return network_plugin_ref_->is_active_;
    }));

    // Default behavior for plugin creation.
    ON_CALL(*plugin_factory_ref, CreateAgentPlugin)
        .WillByDefault(WithArg<4>(Invoke([this](base::OnceCallback<void()> cb) {
          agent_activation_callback_ = std::move(cb);
          return std::move(agent_plugin_);
        })));
    ON_CALL(*plugin_factory_ref, Create(Types::Plugin::kProcess, _, _, _, _, _))
        .WillByDefault(Return(ByMove(std::move(process_plugin_))));
    ON_CALL(*plugin_factory_ref, Create(Types::Plugin::kNetwork, _, _, _, _, _))
        .WillByDefault(Return(ByMove(std::move(network_plugin_))));

    // Default activate actions.
    ON_CALL(*process_plugin_ref_, MockActivate())
        .WillByDefault(Return(absl::OkStatus()));
    ON_CALL(*agent_plugin_ref_, MockActivate()).WillByDefault(Invoke([this]() {
      std::move(agent_activation_callback_).Run();
      return absl::OkStatus();
    }));
    ON_CALL(*network_plugin_ref_, MockActivate())
        .WillByDefault(Return(absl::OkStatus()));
  }

  void InstallDontCarePluginIsActive() {
    EXPECT_CALL(*process_plugin_ref_, IsActive()).Times(AnyNumber());
    EXPECT_CALL(*agent_plugin_ref_, IsActive()).Times(AnyNumber());
    EXPECT_CALL(*network_plugin_ref_, IsActive()).Times(AnyNumber());
  }

  void InstallDontCarePluginGetName() {
    EXPECT_CALL(*process_plugin_ref_, GetName()).Times(AnyNumber());
    EXPECT_CALL(*agent_plugin_ref_, GetName()).Times(AnyNumber());
    EXPECT_CALL(*network_plugin_ref_, GetName()).Times(AnyNumber());
  }

  void InstallActivateExpectations() {
    // An activated secagent should always fulfill these expectations.
    EXPECT_CALL(*message_sender_, Initialize)
        .WillOnce(Return(absl::OkStatus()));
    EXPECT_CALL(*process_cache_, InitializeFilter);
    EXPECT_CALL(*policies_features_broker_, StartAndBlockForSync);
  }

  base::OnceCallback<void()> agent_activation_callback_;
  std::unique_ptr<SecAgent> secagent_;
  std::unique_ptr<MockPluginFactory> plugin_factory_;
  std::unique_ptr<MockPlugin> agent_plugin_;
  MockPlugin* agent_plugin_ref_;
  std::unique_ptr<MockPlugin> network_plugin_;
  MockPlugin* network_plugin_ref_;
  std::unique_ptr<MockPlugin> process_plugin_;
  MockPlugin* process_plugin_ref_;
  MockPluginFactory* plugin_factory_ref;
  scoped_refptr<MockMessageSender> message_sender_;
  scoped_refptr<MockProcessCache> process_cache_;
  scoped_refptr<MockPoliciesFeaturesBroker> policies_features_broker_;
  scoped_refptr<MockDeviceUser> device_user_;
  ::testing::StrictMock<MockSystemQuit> mock_system_quit_;
  base::test::TaskEnvironment task_environment_;
};

TEST_F(SecAgentTestFixture, TestReportingEnabled) {
  InstallActivateExpectations();
  InstallDontCarePluginIsActive();
  InstallDontCarePluginGetName();
  EXPECT_CALL(*policies_features_broker_, GetDeviceReportXDREventsPolicy)
      .WillOnce(Return(true));
  EXPECT_CALL(
      *policies_features_broker_,
      GetFeature(
          PoliciesFeaturesBroker::Feature::kCrOSLateBootSecagentdXDRReporting))
      .WillOnce(Return(true));
  EXPECT_CALL(*policies_features_broker_,
              GetFeature(PoliciesFeaturesBrokerInterface::Feature::
                             kCrOSLateBootSecagentdXDRNetworkEvents))
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));

  EXPECT_CALL(*device_user_, RegisterSessionChangeHandler);
  // All plugins should be created.
  EXPECT_CALL(*plugin_factory_ref, CreateAgentPlugin);
  EXPECT_CALL(*plugin_factory_ref,
              Create(Types::Plugin::kNetwork, _, _, _, _, _));
  EXPECT_CALL(*plugin_factory_ref,
              Create(Types::Plugin::kProcess, _, _, _, _, _));

  // Everything is enabled so all plugins should be activated.
  EXPECT_CALL(*process_plugin_ref_, MockActivate);
  EXPECT_CALL(*network_plugin_ref_, MockActivate);
  EXPECT_CALL(*agent_plugin_ref_, MockActivate);
  secagent_->Activate();
  secagent_->CheckPolicyAndFeature();
}

TEST_F(SecAgentTestFixture, TestEnabledToDisabled) {
  InstallActivateExpectations();
  InstallDontCarePluginIsActive();
  InstallDontCarePluginGetName();
  EXPECT_CALL(*policies_features_broker_, GetDeviceReportXDREventsPolicy)
      .WillOnce(Return(true));
  EXPECT_CALL(
      *policies_features_broker_,
      GetFeature(
          PoliciesFeaturesBroker::Feature::kCrOSLateBootSecagentdXDRReporting))
      .WillOnce(Return(true));
  EXPECT_CALL(*policies_features_broker_,
              GetFeature(PoliciesFeaturesBrokerInterface::Feature::
                             kCrOSLateBootSecagentdXDRNetworkEvents))
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));

  EXPECT_CALL(*device_user_, RegisterSessionChangeHandler);
  // All plugins should be created.
  EXPECT_CALL(*plugin_factory_ref, CreateAgentPlugin);
  EXPECT_CALL(*plugin_factory_ref,
              Create(Types::Plugin::kNetwork, _, _, _, _, _));
  EXPECT_CALL(*plugin_factory_ref,
              Create(Types::Plugin::kProcess, _, _, _, _, _));

  // Everything is enabled so all plugins should be activated.
  EXPECT_CALL(*process_plugin_ref_, MockActivate);
  EXPECT_CALL(*network_plugin_ref_, MockActivate);
  EXPECT_CALL(*agent_plugin_ref_, MockActivate);
  secagent_->Activate();
  secagent_->CheckPolicyAndFeature();
  // Retire expectations.
  ::testing::Mock::VerifyAndClearExpectations(process_plugin_ref_);
  ::testing::Mock::VerifyAndClearExpectations(agent_plugin_ref_);
  ::testing::Mock::VerifyAndClearExpectations(network_plugin_ref_);
  ::testing::Mock::VerifyAndClearExpectations(policies_features_broker_.get());
  // Now on policy refresh show that we deactivate all the plugins when
  // XDR policy is disabled or emergency-XDR-kill-switch is enabled.
  EXPECT_CALL(*policies_features_broker_, GetDeviceReportXDREventsPolicy)
      .WillRepeatedly(Return(false));
  EXPECT_CALL(
      *policies_features_broker_,
      GetFeature(
          PoliciesFeaturesBroker::Feature::kCrOSLateBootSecagentdXDRReporting))
      .WillOnce(Return(false));
  // If no plugins were activated then no XDR events are being generated.
  EXPECT_CALL(*process_plugin_ref_, MockActivate()).Times(0);
  EXPECT_CALL(*agent_plugin_ref_, MockActivate()).Times(0);
  EXPECT_CALL(*network_plugin_ref_, MockActivate()).Times(0);
  EXPECT_CALL(mock_system_quit_, Quit(EX_OK));
  secagent_->CheckPolicyAndFeature();
}

TEST_F(SecAgentTestFixture, TestDisabledToEnabled) {
  // Standard expectations of a just launched secagentd.
  InstallActivateExpectations();
  InstallDontCarePluginIsActive();
  InstallDontCarePluginGetName();

  EXPECT_CALL(*device_user_, RegisterSessionChangeHandler);
  // Reporting is disabled.
  EXPECT_CALL(*policies_features_broker_, GetDeviceReportXDREventsPolicy)
      .WillOnce(Return(false));
  EXPECT_CALL(
      *policies_features_broker_,
      GetFeature(
          PoliciesFeaturesBroker::Feature::kCrOSLateBootSecagentdXDRReporting))
      .WillOnce(Return(false));
  // With everything disabled, plugins can be created but shouldn't be
  // activated.
  EXPECT_CALL(*plugin_factory_ref, CreateAgentPlugin).Times(AtMost(1));
  EXPECT_CALL(*plugin_factory_ref,
              Create(Types::Plugin::kProcess, _, _, _, _, _))
      .Times(AtMost(1));
  EXPECT_CALL(*plugin_factory_ref,
              Create(Types::Plugin::kNetwork, _, _, _, _, _))
      .Times(AtMost(1));

  EXPECT_CALL(*agent_plugin_ref_, MockActivate()).Times(0);
  EXPECT_CALL(*process_plugin_ref_, MockActivate()).Times(0);
  EXPECT_CALL(*network_plugin_ref_, MockActivate()).Times(0);
  secagent_->Activate();
  secagent_->CheckPolicyAndFeature();
  // Retire expectations.
  ::testing::Mock::VerifyAndClearExpectations(plugin_factory_ref);
  ::testing::Mock::VerifyAndClearExpectations(process_plugin_ref_);
  ::testing::Mock::VerifyAndClearExpectations(agent_plugin_ref_);
  ::testing::Mock::VerifyAndClearExpectations(network_plugin_ref_);

  // Enable reporting.
  EXPECT_CALL(*policies_features_broker_, GetDeviceReportXDREventsPolicy)
      .WillOnce(Return(true));
  EXPECT_CALL(
      *policies_features_broker_,
      GetFeature(
          PoliciesFeaturesBroker::Feature::kCrOSLateBootSecagentdXDRReporting))
      .WillOnce(Return(true));
  EXPECT_CALL(*policies_features_broker_,
              GetFeature(PoliciesFeaturesBroker::Feature::
                             kCrOSLateBootSecagentdXDRNetworkEvents))
      .WillOnce(Return(true));
  EXPECT_CALL(*plugin_factory_ref, CreateAgentPlugin).Times(1);
  EXPECT_CALL(*plugin_factory_ref,
              Create(Types::Plugin::kProcess, _, _, _, _, _))
      .Times(1);
  EXPECT_CALL(*plugin_factory_ref,
              Create(Types::Plugin::kNetwork, _, _, _, _, _))
      .Times(1);
  // If all plugins are activated then all XDR events are reporting.
  EXPECT_CALL(*agent_plugin_ref_, MockActivate());
  EXPECT_CALL(*process_plugin_ref_, MockActivate());
  EXPECT_CALL(*network_plugin_ref_, MockActivate());
  secagent_->CheckPolicyAndFeature();
}

TEST_F(SecAgentTestFixture, TestFailedInitialization) {
  InstallDontCarePluginIsActive();
  InstallDontCarePluginGetName();
  EXPECT_CALL(*message_sender_, Initialize)
      .WillOnce(Return(absl::InternalError(
          "InitializeQueues: Report queue failed to create")));
  // Creating plugins is fine, it's the activation that don't want to happen.
  EXPECT_CALL(*plugin_factory_ref, CreateAgentPlugin).Times(AtMost(1));
  EXPECT_CALL(*plugin_factory_ref,
              Create(Types::Plugin::kProcess, _, _, _, _, _))
      .Times(AtMost(1));
  EXPECT_CALL(*plugin_factory_ref,
              Create(Types::Plugin::kNetwork, _, _, _, _, _))
      .Times(AtMost(1));
  EXPECT_CALL(*agent_plugin_ref_, MockActivate()).Times(0);
  EXPECT_CALL(*process_plugin_ref_, MockActivate()).Times(0);
  EXPECT_CALL(*network_plugin_ref_, MockActivate()).Times(0);
  EXPECT_CALL(mock_system_quit_, Quit(EX_SOFTWARE));
  secagent_->Activate();
}

TEST_F(SecAgentTestFixture, TestFailedPluginCreation) {
  InstallActivateExpectations();
  InstallDontCarePluginIsActive();
  InstallDontCarePluginGetName();
  EXPECT_CALL(*device_user_, RegisterSessionChangeHandler);

  // It's fine if plugins are created very early and we never get to
  // instantiating the policy manager, grabbing device policies etc..
  EXPECT_CALL(*plugin_factory_ref, CreateAgentPlugin).WillOnce(Return(nullptr));
  EXPECT_CALL(*plugin_factory_ref,
              Create(Types::Plugin::kProcess, _, _, _, _, _))
      .Times(AtMost(1));
  EXPECT_CALL(*plugin_factory_ref,
              Create(Types::Plugin::kNetwork, _, _, _, _, _))
      .Times(AtMost(1));

  EXPECT_CALL(*policies_features_broker_, GetDeviceReportXDREventsPolicy)
      .Times(AtMost(1))
      .WillOnce(Return(true));
  EXPECT_CALL(
      *policies_features_broker_,
      GetFeature(
          PoliciesFeaturesBroker::Feature::kCrOSLateBootSecagentdXDRReporting))
      .Times(AtMost(1))
      .WillOnce(Return(true));
  // But we should never see an activation of the plugins.
  EXPECT_CALL(*process_plugin_ref_, MockActivate()).Times(0);
  EXPECT_CALL(*network_plugin_ref_, MockActivate()).Times(0);
  EXPECT_CALL(mock_system_quit_, Quit(EX_SOFTWARE));

  secagent_->Activate();
  secagent_->CheckPolicyAndFeature();
}

TEST_F(SecAgentTestFixture, TestFailedPluginActivation) {
  InstallActivateExpectations();
  InstallDontCarePluginIsActive();
  InstallDontCarePluginGetName();
  EXPECT_CALL(*policies_features_broker_, GetDeviceReportXDREventsPolicy)
      .WillRepeatedly(Return(true));
  EXPECT_CALL(
      *policies_features_broker_,
      GetFeature(
          PoliciesFeaturesBroker::Feature::kCrOSLateBootSecagentdXDRReporting))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*policies_features_broker_,
              GetFeature(PoliciesFeaturesBrokerInterface::Feature::
                             kCrOSLateBootSecagentdXDRNetworkEvents))
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));

  EXPECT_CALL(*device_user_, RegisterSessionChangeHandler);
  // All plugins should be created.
  EXPECT_CALL(*plugin_factory_ref, CreateAgentPlugin);
  EXPECT_CALL(*plugin_factory_ref,
              Create(Types::Plugin::kNetwork, _, _, _, _, _));
  EXPECT_CALL(*plugin_factory_ref,
              Create(Types::Plugin::kProcess, _, _, _, _, _));

  // Everything is enabled so all plugins should be activated.
  EXPECT_CALL(*process_plugin_ref_, MockActivate)
      .WillOnce(
          Return(absl::InternalError("Process plugin failed to activate.")));
  EXPECT_CALL(*network_plugin_ref_, MockActivate).Times(1);
  EXPECT_CALL(*agent_plugin_ref_, MockActivate).Times(1);

  secagent_->Activate();
  secagent_->CheckPolicyAndFeature();
}

TEST_P(SecAgentTestFixture, TestReportingDisabled) {
  const XdrFeatureAndPolicy param = GetParam();

  InstallActivateExpectations();
  EXPECT_CALL(*policies_features_broker_, GetDeviceReportXDREventsPolicy)
      .WillOnce(Return(param.xdr_policy_enabled));
  EXPECT_CALL(
      *policies_features_broker_,
      GetFeature(
          PoliciesFeaturesBroker::Feature::kCrOSLateBootSecagentdXDRReporting))
      .WillOnce(Return(param.xdr_feature_enabled));
  // It's fine for plugins to be created regardless of whether XDR reporting
  // is enabled. It's the activation that we want to guard against.
  EXPECT_CALL(*plugin_factory_ref, CreateAgentPlugin)
      .Times(AtMost(1))
      .WillOnce(Return(ByMove(std::move(agent_plugin_))));
  EXPECT_CALL(*plugin_factory_ref,
              Create(Types::Plugin::kProcess, _, _, _, _, _))
      .Times(AtMost(1))
      .WillOnce(Return(ByMove(std::move(process_plugin_))));
  EXPECT_CALL(*plugin_factory_ref,
              Create(Types::Plugin::kNetwork, _, _, _, _, _))
      .Times(AtMost(1))
      .WillOnce(Return(ByMove(std::move(network_plugin_))));
  EXPECT_CALL(*agent_plugin_ref_, MockActivate()).Times(0);
  EXPECT_CALL(*process_plugin_ref_, MockActivate()).Times(0);
  EXPECT_CALL(*network_plugin_ref_, MockActivate()).Times(0);

  secagent_->Activate();
  secagent_->CheckPolicyAndFeature();
}

INSTANTIATE_TEST_SUITE_P(
    SecAgentTestFixture,
    SecAgentTestFixture,
    // {featured, policy}
    ::testing::ValuesIn<XdrFeatureAndPolicy>(
        {{false, false}, {false, true}, {true, false}}),
    [](const ::testing::TestParamInfo<SecAgentTestFixture::ParamType>& info) {
      std::string featured = info.param.xdr_feature_enabled
                                 ? "FeaturedEnabled"
                                 : "FeaturedDisabled";
      std::string policy =
          info.param.xdr_policy_enabled ? "PolicyEnabled" : "PolicyDisabled";

      return base::StringPrintf("%s_%s", featured.c_str(), policy.c_str());
    });

}  // namespace secagentd::testing
