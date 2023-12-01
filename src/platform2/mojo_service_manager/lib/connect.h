// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MOJO_SERVICE_MANAGER_LIB_CONNECT_H_
#define MOJO_SERVICE_MANAGER_LIB_CONNECT_H_

#include <base/files/file_path.h>
#include <brillo/brillo_export.h>
#include <mojo/public/cpp/bindings/pending_remote.h>

#include "mojo_service_manager/lib/mojom/service_manager.mojom.h"

namespace chromeos::mojo_service_manager {

// Connects to the mojo service manager. This will try to connect to the mojo
// service manager socket and bootstrap the mojo connection. If fails to
// connect, this will return an invalid pending remote.
BRILLO_EXPORT mojo::PendingRemote<mojom::ServiceManager>
ConnectToMojoServiceManager();

// Allows caller to change the socket path for testing.
mojo::PendingRemote<mojom::ServiceManager>
ConnectToMojoServiceManagerForTesting(const base::FilePath& socket_path);

}  // namespace chromeos::mojo_service_manager

#endif  // MOJO_SERVICE_MANAGER_LIB_CONNECT_H_
