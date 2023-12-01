// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_MOJO_PROXY_SERVER_PROXY_H_
#define ARC_VM_MOJO_PROXY_SERVER_PROXY_H_

#include <memory>
#include <string>
#include <vector>

#include <base/memory/ref_counted.h>

#include "arc/vm/mojo_proxy/message_stream.h"
#include "arc/vm/mojo_proxy/mojo_proxy.h"
#include "arc/vm/mojo_proxy/proxy_file_system.h"

namespace arc {

class ProxyFileSystem;

// ServerProxy sets up the MojoProxy and handles initial socket negotiation.
class ServerProxy : public MojoProxy::Delegate,
                    public ProxyFileSystem::Delegate {
 public:
  ServerProxy(scoped_refptr<base::TaskRunner> proxy_file_system_task_runner,
              const base::FilePath& proxy_file_system_mount_path,
              base::OnceClosure quit_closure);
  ServerProxy(const ServerProxy&) = delete;
  ServerProxy& operator=(const ServerProxy&) = delete;

  ~ServerProxy() override;

  // Sets up the ServerProxy. Specifically, start listening on virtio-wl.
  // Then, connect to /run/chrome/arc/arc_bridge.sock.
  bool Initialize();

  // MojoProxy::Delegate overrides:
  MojoProxy::Type GetType() const override { return MojoProxy::Type::SERVER; }
  int GetPollFd() override { return message_stream_->Get(); }
  base::ScopedFD CreateProxiedRegularFile(int64_t handle,
                                          int32_t flags) override;
  bool SendMessage(const arc_proxy::MojoMessage& message,
                   const std::vector<base::ScopedFD>& fds) override;
  bool ReceiveMessage(arc_proxy::MojoMessage* message,
                      std::vector<base::ScopedFD>* fds) override;
  void OnStopped() override;

  // ProxyFileSystem::Delegate overrides:
  void Pread(int64_t handle,
             uint64_t count,
             uint64_t offset,
             PreadCallback callback) override;
  void Pwrite(int64_t handle,
              std::string blob,
              uint64_t offset,
              PwriteCallback callback) override;
  void Close(int64_t handle) override;
  void Fstat(int64_t handle, FstatCallback callback) override;
  void Ftruncate(int64_t handle,
                 int64_t length,
                 FtruncateCallback callback) override;

 private:
  scoped_refptr<base::TaskRunner> proxy_file_system_task_runner_;
  ProxyFileSystem proxy_file_system_;
  base::OnceClosure quit_closure_;
  base::ScopedFD virtwl_socket_;
  base::ScopedFD virtwl_context_;
  std::unique_ptr<MessageStream> message_stream_;
  std::unique_ptr<MojoProxy> mojo_proxy_;
};

}  // namespace arc

#endif  // ARC_VM_MOJO_PROXY_SERVER_PROXY_H_
