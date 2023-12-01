// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IIOSERVICE_IIOSERVICE_SIMPLECLIENT_DAEMON_EVENTS_OBSERVER_H_
#define IIOSERVICE_IIOSERVICE_SIMPLECLIENT_DAEMON_EVENTS_OBSERVER_H_

#include <memory>
#include <string>
#include <vector>

#include <base/memory/weak_ptr.h>

#include "iioservice/iioservice_simpleclient/daemon.h"

namespace iioservice {

class DaemonEventsObserver : public Daemon {
 public:
  DaemonEventsObserver(int device_id,
                       cros::mojom::DeviceType device_type,
                       std::vector<int> event_indices,
                       int events);
  ~DaemonEventsObserver() override;

 protected:
  // Daemon overrides:
  void SetSensorClient() override;

  int device_id_;
  cros::mojom::DeviceType device_type_;
  std::vector<int> event_indices_;
  int events_;

  // Must be last class member.
  base::WeakPtrFactory<DaemonEventsObserver> weak_ptr_factory_;
};

}  // namespace iioservice

#endif  // IIOSERVICE_IIOSERVICE_SIMPLECLIENT_DAEMON_EVENTS_OBSERVER_H_
