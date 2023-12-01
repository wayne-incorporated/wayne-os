// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_health_tool/mojo_util.h"

#include <base/check.h>
#include <base/no_destructor.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <mojo_service_manager/lib/connect.h>

namespace diagnostics {

chromeos::mojo_service_manager::mojom::ServiceManager*
GetServiceManagerProxy() {
  static const base::NoDestructor<
      mojo::Remote<chromeos::mojo_service_manager::mojom::ServiceManager>>
      remote(chromeos::mojo_service_manager::ConnectToMojoServiceManager());

  CHECK(remote->is_bound()) << "Failed to connect to mojo service manager.";
  return remote->get();
}

}  // namespace diagnostics
