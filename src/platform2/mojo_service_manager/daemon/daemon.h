// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MOJO_SERVICE_MANAGER_DAEMON_DAEMON_H_
#define MOJO_SERVICE_MANAGER_DAEMON_DAEMON_H_

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <brillo/daemons/daemon.h>
#include <mojo/core/embedder/scoped_ipc_support.h>

#include "mojo_service_manager/daemon/configuration.h"
#include "mojo_service_manager/daemon/service_manager.h"
#include "mojo_service_manager/daemon/service_policy.h"

namespace chromeos {
namespace mojo_service_manager {

// Exported for testing.
std::string GetSEContextStringFromChar(const char* buf, size_t len);

// Sets up threading environment and initializes unix socket server of the
// service manager daemon.
class Daemon : public brillo::Daemon {
 public:
  class Delegate {
   public:
    Delegate();
    Delegate(const Delegate&) = delete;
    Delegate& operator=(const Delegate&) = delete;
    virtual ~Delegate();

    // Calls |getsockopt| system call.
    virtual int GetSockOpt(const base::ScopedFD& socket,
                           int level,
                           int optname,
                           void* optval,
                           socklen_t* optlen) const;

    // Loads policy files.
    virtual ServicePolicyMap LoadPolicyFiles(
        const std::vector<base::FilePath>& policy_dir_paths) const;
  };

  Daemon(Delegate* delegate,
         const base::FilePath& socket_path,
         const std::vector<base::FilePath>& policy_dir_paths,
         Configuration configuration);
  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;
  ~Daemon() override;

 private:
  // ::brillo::Daemon overrides.
  int OnInit() override;
  void OnShutdown(int* exit_code) override;

  // Sends mojo invitation to the peer socket and binds the receiver of
  // mojom::ServiceManager.
  void SendMojoInvitationAndBindReceiver();

  // Gets the identity of the remote process of the peer socket.
  mojom::ProcessIdentityPtr GetProcessIdentityFromPeerSocket(
      const base::ScopedFD& peer) const;

  // The |ScopedIPCSupport| instance for mojo.
  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;
  // Accesses Delegate.
  Delegate* const delegate_;
  // The path to the unix socket of the daemon.
  const base::FilePath socket_path_;
  // The fd of the unix socket server of the daemon.
  base::ScopedFD socket_fd_;
  // The fd watcher to monitor the socket server.
  std::unique_ptr<base::FileDescriptorWatcher::Controller> socket_watcher_;
  // The paths to load policy files.
  std::vector<base::FilePath> policy_dir_paths_;
  // The configuration for the service manager.
  Configuration configuration_;
  // Implements mojom::ServiceManager. It will be initialized after policy files
  // are loaded.
  std::unique_ptr<ServiceManager> service_manager_;
};

}  // namespace mojo_service_manager
}  // namespace chromeos

#endif  // MOJO_SERVICE_MANAGER_DAEMON_DAEMON_H_
