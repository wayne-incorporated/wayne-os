// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IIOSERVICE_IIOSERVICE_SIMPLECLIENT_DAEMON_QUERY_H_
#define IIOSERVICE_IIOSERVICE_SIMPLECLIENT_DAEMON_QUERY_H_

#include <string>
#include <vector>

#include <base/memory/weak_ptr.h>

#include "iioservice/iioservice_simpleclient/daemon.h"

namespace iioservice {

class DaemonQuery : public Daemon {
 public:
  DaemonQuery(cros::mojom::DeviceType device_type,
              std::vector<std::string> attributes);
  ~DaemonQuery() override;

 protected:
  // Daemon overrides:
  void SetSensorClient() override;

  cros::mojom::DeviceType device_type_;
  std::vector<std::string> attributes_;

  // Must be last class member.
  base::WeakPtrFactory<DaemonQuery> weak_ptr_factory_;
};

}  // namespace iioservice

#endif  // IIOSERVICE_IIOSERVICE_SIMPLECLIENT_DAEMON_QUERY_H_
