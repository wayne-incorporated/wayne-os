// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SECAGENTD_DAEMON_H_
#define SECAGENTD_DAEMON_H_

#include <cstdint>
#include <memory>
#include <vector>

#include "base/memory/scoped_refptr.h"
#include "brillo/daemons/dbus_daemon.h"
#include "dbus/mock_bus.h"
#include "secagentd/device_user.h"
#include "secagentd/message_sender.h"
#include "secagentd/metrics_sender.h"
#include "secagentd/plugins.h"
#include "secagentd/policies_features_broker.h"
#include "secagentd/process_cache.h"
#include "secagentd/proto/security_xdr_events.pb.h"
#include "secagentd/secagent.h"

namespace secagentd {

// The secagentd main daemon.
// On startup the device policy is fetched. Based on the security collection
// policies certain BPFs will be loaded and attached.
// These BPFs will produce security events that are collected by this daemon,
// which are packaged into protobuffs and sent to missived for delivery
// to an off-machine service.

class Daemon : public brillo::DBusDaemon {
 public:
  static constexpr uint32_t kDefaultHeartbeatPeriodS = 300;
  static constexpr uint32_t kDefaultPluginBatchIntervalS = 2 * 60;

  Daemon() = delete;
  /* dependency injection for unit tests */
  explicit Daemon(struct Inject);
  Daemon(bool bypass_policy_for_testing,
         bool bypass_enq_ok_wait_for_testing,
         uint32_t heartbeat_period_s,
         uint32_t plugin_batch_interval_s,
         uint32_t policy_polling_interval_s);
  ~Daemon() override = default;

 protected:
  void QuitDaemon(int);
  int OnInit() override;
  int OnEventLoopStarted() override;
  void OnShutdown(int*) override;

 private:
  std::unique_ptr<SecAgent> secagent_;
  bool bypass_policy_for_testing_ = false;
  bool bypass_enq_ok_wait_for_testing_ = false;
  uint32_t heartbeat_period_s_ = kDefaultHeartbeatPeriodS;
  uint32_t plugin_batch_interval_s_ = kDefaultPluginBatchIntervalS;
  uint32_t feature_polling_interval_s_ =
      PoliciesFeaturesBroker::kDefaultPollDurationS;
  base::WeakPtrFactory<Daemon> weak_ptr_factory_;
};
};  // namespace secagentd

#endif  // SECAGENTD_DAEMON_H_
