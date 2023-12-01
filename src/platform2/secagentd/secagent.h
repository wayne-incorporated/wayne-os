// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SECAGENTD_SECAGENT_H_
#define SECAGENTD_SECAGENT_H_

#include <cstdint>
#include <memory>
#include <vector>

#include "attestation/proto_bindings/interface.pb.h"
#include "attestation-client/attestation/dbus-proxies.h"
#include "base/memory/scoped_refptr.h"
#include "dbus/mock_bus.h"
#include "featured/feature_library.h"
#include "secagentd/device_user.h"
#include "secagentd/message_sender.h"
#include "secagentd/metrics_sender.h"
#include "secagentd/plugins.h"
#include "secagentd/policies_features_broker.h"
#include "secagentd/process_cache.h"
#include "secagentd/proto/security_xdr_events.pb.h"
#include "session_manager/dbus-proxies.h"
#include "tpm_manager/dbus-proxies.h"
#include "tpm_manager/proto_bindings/tpm_manager.pb.h"
#include "tpm_manager-client/tpm_manager/dbus-proxies.h"

namespace secagentd {

namespace testing {
class SecAgentTestFixture;
}

class SecAgent {
 public:
  SecAgent() = delete;
  SecAgent(base::OnceCallback<void(int)>,
           scoped_refptr<MessageSenderInterface>,
           scoped_refptr<ProcessCacheInterface>,
           scoped_refptr<DeviceUserInterface>,
           std::unique_ptr<PluginFactoryInterface>,
           std::unique_ptr<org::chromium::AttestationProxyInterface>,
           std::unique_ptr<org::chromium::TpmManagerProxyInterface>,
           feature::PlatformFeaturesInterface*,
           bool bypass_policy_for_testing,
           bool bypass_enq_ok_wait_for_testing,
           uint32_t heartbeat_period_s,
           uint32_t plugin_batch_interval_s,
           uint32_t feature_poll_interval_s_for_testing);
  ~SecAgent() = default;

  // Start polling for policy and feature flags.
  void Activate();
  // Checks the status of the XDR feature flag and policy flag. Starts/stops
  // reporting as necessary.
  void CheckPolicyAndFeature();

 protected:
  // Activate or deactivate BPF plugins based on any applicable feature gates.
  void ActivateOrDeactivateBpfPlugins();
  // Create and activate all BPF plugins.
  void CreateAndActivateBpfPlugins();
  // Starts the plugin loading process. First creates the agent plugin and
  // waits for a successfully sent heartbeat before creating and running
  // the BPF plugins.
  void StartXDRReporting();

 private:
  friend class testing::SecAgentTestFixture;

  struct PluginConfig {
    std::optional<PoliciesFeaturesBrokerInterface::Feature> gated_by_feature;
    std::unique_ptr<PluginInterface> plugin;
  };

  std::vector<PluginConfig> bpf_plugins_;
  scoped_refptr<MessageSenderInterface> message_sender_;
  scoped_refptr<ProcessCacheInterface> process_cache_;
  scoped_refptr<PoliciesFeaturesBrokerInterface> policies_features_broker_;
  scoped_refptr<DeviceUserInterface> device_user_;
  std::unique_ptr<PluginFactoryInterface> plugin_factory_;
  std::unique_ptr<PluginInterface> agent_plugin_;
  std::unique_ptr<org::chromium::AttestationProxyInterface> attestation_proxy_;
  std::unique_ptr<org::chromium::TpmManagerProxyInterface> tpm_proxy_;
  feature::PlatformFeaturesInterface* platform_features_;
  bool bypass_policy_for_testing_ = false;
  bool bypass_enq_ok_wait_for_testing_ = false;
  bool reporting_events_ = false;
  uint32_t heartbeat_period_s_;
  uint32_t plugin_batch_interval_s_;
  uint32_t feature_poll_interval_s_;
  base::OnceCallback<void(int)> quit_daemon_cb_;
  base::WeakPtrFactory<SecAgent> weak_ptr_factory_;
};
};      // namespace secagentd
#endif  // SECAGENTD_SECAGENT_H_
