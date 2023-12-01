// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MOJO_SERVICE_MANAGER_DAEMON_CONFIGURATION_H_
#define MOJO_SERVICE_MANAGER_DAEMON_CONFIGURATION_H_

namespace chromeos {
namespace mojo_service_manager {

// Stores the configuration for the service manager daemon.
struct Configuration {
  // Indicates whether the service manager daemon is in the permissive mode. In
  // permissive mode, the requests with wrong identity won't be rejected. This
  // can be used in development to allow registering and requesting services
  // through ssh terminal.
  bool is_permissive = false;
};

}  // namespace mojo_service_manager
}  // namespace chromeos

#endif  // MOJO_SERVICE_MANAGER_DAEMON_CONFIGURATION_H_
