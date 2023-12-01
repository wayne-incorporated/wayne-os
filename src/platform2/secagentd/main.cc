// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdlib>

#include "base/logging.h"
#include "brillo/flag_helper.h"
#include "brillo/syslog_logging.h"
#include "secagentd/daemon.h"
#include "secagentd/policies_features_broker.h"

int main(int argc, char** argv) {
  DEFINE_int32(log_level, 0,
               "Logging level - 0: LOG(INFO), 1: LOG(WARNING), 2: LOG(ERROR), "
               "-1: VLOG(1), -2: VLOG(2), ...");
  DEFINE_bool(bypass_policy_for_testing, false,
              "Set to true to bypass policy checks at startup");
  DEFINE_bool(
      bypass_enq_ok_wait_for_testing, false,
      "Set to true to skip waiting for an Agent Start event to be "
      "enqueued successfully before attempting to enqueue subsequent events");
  DEFINE_uint32(
      set_heartbeat_period_s_for_testing,
      secagentd::Daemon::kDefaultHeartbeatPeriodS,
      "Set value in seconds > 0 for the agent heartbeat timer for testing.");
  DEFINE_uint32(plugin_batch_interval_s_for_testing,
                secagentd::Daemon::kDefaultPluginBatchIntervalS,
                "Set value in seconds for the event batching interval.");
  DEFINE_uint32(feature_poll_interval_s_for_testing,
                secagentd::PoliciesFeaturesBroker::kDefaultPollDurationS,
                "Set value in seconds for the feature and policy polling "
                "interval.");
  brillo::FlagHelper::Init(argc, argv,
                           "ChromiumOS Security Event Reporting Daemon");
  brillo::InitLog(brillo::kLogToStderrIfTty | brillo::kLogToSyslog);
  logging::SetMinLogLevel(FLAGS_log_level);
  auto daemon = secagentd::Daemon(FLAGS_bypass_policy_for_testing,
                                  FLAGS_bypass_enq_ok_wait_for_testing,
                                  FLAGS_set_heartbeat_period_s_for_testing,
                                  FLAGS_plugin_batch_interval_s_for_testing,
                                  FLAGS_feature_poll_interval_s_for_testing);
  return daemon.Run();
}
