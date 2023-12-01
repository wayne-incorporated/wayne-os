// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "secagentd/secagent.h"

#include <unistd.h>

#include <cstdlib>
#include <iomanip>
#include <memory>
#include <string>
#include <sysexits.h>
#include <utility>

#include "absl/status/status.h"
#include "attestation-client/attestation/dbus-proxies.h"
#include "base/functional/bind.h"
#include "base/functional/callback_forward.h"
#include "base/functional/callback_helpers.h"
#include "base/logging.h"
#include "base/memory/scoped_refptr.h"
#include "base/task/thread_pool/thread_pool_instance.h"
#include "brillo/daemons/daemon.h"
#include "brillo/daemons/dbus_daemon.h"
#include "missive/client/missive_client.h"
#include "secagentd/daemon.h"
#include "secagentd/message_sender.h"
#include "secagentd/metrics_sender.h"
#include "secagentd/plugins.h"
#include "secagentd/policies_features_broker.h"
#include "secagentd/process_cache.h"

namespace secagentd {

SecAgent::SecAgent(
    base::OnceCallback<void(int)> quit_daemon_cb,
    scoped_refptr<MessageSenderInterface> message_sender,
    scoped_refptr<ProcessCacheInterface> process_cache,
    scoped_refptr<DeviceUserInterface> device_user,
    std::unique_ptr<PluginFactoryInterface> plugin_factory,
    std::unique_ptr<org::chromium::AttestationProxyInterface> attestation_proxy,
    std::unique_ptr<org::chromium::TpmManagerProxyInterface> tpm_proxy,
    feature::PlatformFeaturesInterface* platform_features,
    bool bypass_policy_for_testing,
    bool bypass_enq_ok_wait_for_testing,
    uint32_t heartbeat_period_s,
    uint32_t plugin_batch_interval_s,
    uint32_t feature_poll_interval_s_for_testing)
    : message_sender_(message_sender),
      process_cache_(process_cache),
      device_user_(device_user),
      plugin_factory_(std::move(plugin_factory)),
      attestation_proxy_(std::move(attestation_proxy)),
      tpm_proxy_(std::move(tpm_proxy)),
      platform_features_(platform_features),
      bypass_policy_for_testing_(bypass_policy_for_testing),
      bypass_enq_ok_wait_for_testing_(bypass_enq_ok_wait_for_testing),
      heartbeat_period_s_(heartbeat_period_s),
      plugin_batch_interval_s_(plugin_batch_interval_s),
      feature_poll_interval_s_(feature_poll_interval_s_for_testing),
      quit_daemon_cb_(std::move(quit_daemon_cb)),
      weak_ptr_factory_(this) {
  policies_features_broker_ = base::MakeRefCounted<PoliciesFeaturesBroker>(
      std::make_unique<policy::PolicyProvider>(), platform_features_,
      base::BindRepeating(&SecAgent::CheckPolicyAndFeature,
                          weak_ptr_factory_.GetWeakPtr()));
}

void SecAgent::Activate() {
  absl::Status result = message_sender_->Initialize();
  if (result != absl::OkStatus()) {
    LOG(ERROR) << result.message();
    std::move(quit_daemon_cb_).Run(EX_SOFTWARE);
    return;
  }

  process_cache_->InitializeFilter();

  // This will post a task to run CheckPolicyAndFeature.
  policies_features_broker_->StartAndBlockForSync(
      base::Seconds(feature_poll_interval_s_));
}

void SecAgent::CheckPolicyAndFeature() {
  static bool first_visit = true;
  bool xdr_reporting_policy =
      policies_features_broker_->GetDeviceReportXDREventsPolicy() ||
      bypass_policy_for_testing_;
  bool xdr_reporting_feature = policies_features_broker_->GetFeature(
      PoliciesFeaturesBroker::Feature::kCrOSLateBootSecagentdXDRReporting);

  if (first_visit) {
    LOG(INFO) << "DeviceReportXDREventsPolicy: " << xdr_reporting_policy
              << (bypass_policy_for_testing_ ? " (set by flag)" : "");
    LOG(INFO) << "CrOSLateBootSecagentdXDRReporting: " << xdr_reporting_feature;
  }

  // If either policy is false do not report.
  if (reporting_events_ && !(xdr_reporting_feature && xdr_reporting_policy)) {
    LOG(INFO) << "Stopping event reporting and quitting. Policy: "
              << std::to_string(xdr_reporting_policy)
              << " Feature: " << std::to_string(xdr_reporting_feature);
    reporting_events_ = false;
    // Will exit and restart secagentd.
    std::move(quit_daemon_cb_).Run(EX_OK);
    return;
  } else if (!reporting_events_ &&
             (xdr_reporting_feature && xdr_reporting_policy)) {
    LOG(INFO) << "Starting event reporting";
    // This is emitted at most once per daemon lifetime.
    MetricsSender::GetInstance().SendEnumMetricToUMA(metrics::kPolicy,
                                                     metrics::Policy::kEnabled);
    reporting_events_ = true;
    StartXDRReporting();
  } else if (reporting_events_ && xdr_reporting_feature &&
             xdr_reporting_policy) {
    // BPF plugins were activated in the past. Repoll features and
    // activate/deactivate relevant plugins.
    ActivateOrDeactivateBpfPlugins();
  } else if (first_visit) {
    LOG(INFO) << "Not reporting yet.";
  }

  // Else do nothing until the next poll.
  first_visit = false;
}

void SecAgent::StartXDRReporting() {
  device_user_->RegisterSessionChangeHandler();
  MetricsSender::GetInstance().InitBatchedMetrics();

  using CbType = base::OnceCallback<void()>;
  CbType cb_for_agent = base::BindOnce(&SecAgent::CreateAndActivateBpfPlugins,
                                       weak_ptr_factory_.GetWeakPtr());
  CbType cb_for_now = base::DoNothing();
  if (bypass_enq_ok_wait_for_testing_) {
    std::swap(cb_for_agent, cb_for_now);
  }
  agent_plugin_ = plugin_factory_->CreateAgentPlugin(
      message_sender_, device_user_, std::move(attestation_proxy_),
      std::move(tpm_proxy_), std::move(cb_for_agent), heartbeat_period_s_);
  if (!agent_plugin_) {
    std::move(quit_daemon_cb_).Run(EX_SOFTWARE);
    return;
  }

  absl::Status result = agent_plugin_->Activate();
  if (!result.ok()) {
    LOG(ERROR) << result.message();
    std::move(quit_daemon_cb_).Run(EX_SOFTWARE);
    return;
  }

  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, std::move(cb_for_now));
}

void SecAgent::ActivateOrDeactivateBpfPlugins() {
  absl::Status result;
  std::string action;
  auto activate = [&action](PluginConfig& pc) {
    if (!pc.plugin->IsActive()) {
      action = "activated";
      return pc.plugin->Activate();
    }
    return absl::OkStatus();
  };
  auto deactivate = [&action](PluginConfig& pc) {
    if (pc.plugin->IsActive()) {
      action = "deactivated";
      return pc.plugin->Deactivate();
    }
    return absl::OkStatus();
  };

  for (auto& plugin_config : bpf_plugins_) {
    auto& feature = plugin_config.gated_by_feature;
    auto& plugin = plugin_config.plugin;
    action = "";
    if (feature.has_value()) {
      // The plugin is gated by a feature.
      if (policies_features_broker_->GetFeature(feature.value())) {
        result = activate(plugin_config);
      } else {
        result = deactivate(plugin_config);
      }
    } else {
      result = activate(plugin_config);
    }
    if (!result.ok()) {
      LOG(ERROR) << result.message();
    } else if (!action.empty()) {
      LOG(INFO) << plugin->GetName() << " plugin " << action;
    }
  }
}

void SecAgent::CreateAndActivateBpfPlugins() {
  using Feature = PoliciesFeaturesBrokerInterface::Feature;
  using Plugin = Types::Plugin;
  static const std::vector<std::pair<Plugin, std::optional<Feature>>>
      bpf_plugins = {
          std::make_pair(
              Plugin::kNetwork,
              std::optional(Feature::kCrOSLateBootSecagentdXDRNetworkEvents)),
          std::make_pair(Plugin::kProcess, std::nullopt)};
  std::unique_ptr<PluginInterface> plugin;
  for (const auto& p : bpf_plugins) {
    plugin = plugin_factory_->Create(p.first, message_sender_, process_cache_,
                                     policies_features_broker_, device_user_,
                                     plugin_batch_interval_s_);
    if (!plugin) {
      std::move(quit_daemon_cb_).Run(EX_SOFTWARE);
    }
    bpf_plugins_.push_back({p.second, std::move(plugin)});
  }
  ActivateOrDeactivateBpfPlugins();
}
}  // namespace secagentd
