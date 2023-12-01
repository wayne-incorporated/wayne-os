// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <unistd.h>

#include <cstdlib>
#include <iomanip>
#include <memory>
#include <optional>
#include <string>
#include <sysexits.h>
#include <utility>

#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "attestation/proto_bindings/interface.pb.h"
#include "attestation-client/attestation/dbus-proxies.h"
#include "base/functional/bind.h"
#include "base/functional/callback_forward.h"
#include "base/functional/callback_helpers.h"
#include "base/logging.h"
#include "base/memory/scoped_refptr.h"
#include "base/task/thread_pool/thread_pool_instance.h"
#include "brillo/daemons/dbus_daemon.h"
#include "missive/client/missive_client.h"
#include "secagentd/daemon.h"
#include "secagentd/message_sender.h"
#include "secagentd/metrics_sender.h"
#include "secagentd/plugins.h"
#include "secagentd/policies_features_broker.h"
#include "secagentd/process_cache.h"
#include "secagentd/secagent.h"

namespace secagentd {

Daemon::Daemon(bool bypass_policy_for_testing,
               bool bypass_enq_ok_wait_for_testing,
               uint32_t heartbeat_period_s,
               uint32_t plugin_batch_interval_s,
               uint32_t feature_polling_interval_s)
    : bypass_policy_for_testing_(bypass_policy_for_testing),
      bypass_enq_ok_wait_for_testing_(bypass_enq_ok_wait_for_testing),
      heartbeat_period_s_(heartbeat_period_s),
      plugin_batch_interval_s_(plugin_batch_interval_s),
      feature_polling_interval_s_(feature_polling_interval_s),
      weak_ptr_factory_(this) {}

int Daemon::OnInit() {
  int rv = brillo::DBusDaemon::OnInit();
  if (rv != EX_OK) {
    return rv;
  }
  CHECK(feature::PlatformFeatures::Initialize(bus_));

  secagent_ = std::make_unique<SecAgent>(
      base::BindOnce(&Daemon::QuitDaemon, weak_ptr_factory_.GetWeakPtr()),
      base::MakeRefCounted<MessageSender>(),
      base::MakeRefCounted<ProcessCache>(),
      base::MakeRefCounted<DeviceUser>(
          std::make_unique<org::chromium::SessionManagerInterfaceProxy>(bus_)),
      std::make_unique<PluginFactory>(),
      std::make_unique<org::chromium::AttestationProxy>(bus_),
      std::make_unique<org::chromium::TpmManagerProxy>(bus_),
      feature::PlatformFeatures::Get(), bypass_policy_for_testing_,
      bypass_enq_ok_wait_for_testing_, heartbeat_period_s_,
      plugin_batch_interval_s_, feature_polling_interval_s_);

  // Set up ERP.
  base::ThreadPoolInstance::CreateAndStartWithDefaultParams(
      "missive_thread_pool");
  reporting::MissiveClient::Initialize(bus_.get());

  return EX_OK;
}

int Daemon::OnEventLoopStarted() {
  // We emit this metric here and not inside the polled method so that we do it
  // exactly once per daemon lifetime.
  MetricsSender::GetInstance().SendEnumMetricToUMA(metrics::kPolicy,
                                                   metrics::Policy::kChecked);
  secagent_->Activate();
  return EX_OK;
}

void Daemon::QuitDaemon(int exit_code) {
  QuitWithExitCode(exit_code);
}

void Daemon::OnShutdown(int* exit_code) {
  // Disconnect missive.
  reporting::MissiveClient::Shutdown();

  brillo::DBusDaemon::OnShutdown(exit_code);
}
}  // namespace secagentd
