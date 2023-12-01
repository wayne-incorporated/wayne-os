// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/strings/str_format.h"
#include "attestation/proto_bindings/interface.pb.h"
#include "attestation-client/attestation/dbus-proxies.h"
#include "base/memory/scoped_refptr.h"
#include "secagentd/bpf_skeleton_wrappers.h"
#include "secagentd/bpf_skeletons/skeleton_network_bpf.h"
#include "secagentd/bpf_skeletons/skeleton_process_bpf.h"
#include "secagentd/common.h"
#include "secagentd/message_sender.h"
#include "secagentd/metrics_sender.h"
#include "secagentd/plugins.h"
#include "secagentd/policies_features_broker.h"
#include "secagentd/proto/security_xdr_events.pb.h"

namespace secagentd {

namespace pb = cros_xdr::reporting;

std::unique_ptr<BpfSkeletonInterface> BpfSkeletonFactory::Create(
    Types::BpfSkeleton type, BpfCallbacks cbs, uint32_t batch_interval_s) {
  std::unique_ptr<BpfSkeletonInterface> rv{nullptr};
  switch (type) {
    case Types::BpfSkeleton::kProcess:
      if (di_.process) {
        rv = std::move(di_.process);
      } else {
        SkeletonCallbacks<process_bpf> skel_cbs;
        skel_cbs.destroy = base::BindRepeating(process_bpf__destroy);
        skel_cbs.open = base::BindRepeating(process_bpf__open);
        skel_cbs.open_opts = base::BindRepeating(process_bpf__open_opts);
        rv = std::make_unique<BpfSkeleton<process_bpf>>("process", skel_cbs);
      }
      break;
    case Types::BpfSkeleton::kNetwork:
      if (di_.network) {
        rv = std::move(di_.network);
      } else {
        rv = std::make_unique<NetworkBpfSkeleton>(batch_interval_s);
      }
      break;
    default:
      LOG(ERROR) << "Failed to create skeleton: unhandled type " << type;
      return nullptr;
  }

  rv->RegisterCallbacks(std::move(cbs));
  auto pair = rv->LoadAndAttach();
  if (static_cast<int>(pair.second) != -1) {
    MetricsSender::GetInstance().SendEnumMetricToUMA(metrics::kProcessBpfAttach,
                                                     pair.second);
  }
  auto status = pair.first;
  if (!status.ok()) {
    LOG(ERROR) << "Failed to create skeleton of type " << type << ":"
               << status.message();
    return nullptr;
  }
  return rv;
}

PluginFactory::PluginFactory() {
  bpf_skeleton_factory_ = ::base::MakeRefCounted<BpfSkeletonFactory>();
}

std::unique_ptr<PluginInterface> PluginFactory::Create(
    Types::Plugin type,
    scoped_refptr<MessageSenderInterface> message_sender,
    scoped_refptr<ProcessCacheInterface> process_cache,
    scoped_refptr<PoliciesFeaturesBrokerInterface> policies_features_broker,
    scoped_refptr<DeviceUserInterface> device_user,
    uint32_t batch_interval_s) {
  std::unique_ptr<PluginInterface> rv{nullptr};
  switch (type) {
    case Types::Plugin::kProcess:
      rv = std::make_unique<ProcessPlugin>(
          bpf_skeleton_factory_, message_sender, process_cache,
          policies_features_broker, device_user, batch_interval_s);
      break;
    case Types::Plugin::kNetwork:
      rv = std::make_unique<NetworkPlugin>(
          bpf_skeleton_factory_, message_sender, process_cache,
          policies_features_broker, device_user, batch_interval_s);
      break;

    default:
      CHECK(false) << "Unsupported plugin type";
  }
  return rv;
}

std::unique_ptr<PluginInterface> PluginFactory::CreateAgentPlugin(
    scoped_refptr<MessageSenderInterface> message_sender,
    scoped_refptr<DeviceUserInterface> device_user,
    std::unique_ptr<org::chromium::AttestationProxyInterface> attestation_proxy,
    std::unique_ptr<org::chromium::TpmManagerProxyInterface> tpm_manager_proxy,
    base::OnceCallback<void()> cb,
    uint32_t set_heartbeat_period_s_for_testing) {
  return std::make_unique<AgentPlugin>(
      message_sender, device_user, std::move(attestation_proxy),
      std::move(tpm_manager_proxy), std::move(cb),
      set_heartbeat_period_s_for_testing);
}
}  // namespace secagentd
