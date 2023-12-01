// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_SENESCHAL_SERVICE_H_
#define VM_TOOLS_SENESCHAL_SERVICE_H_

#include <stdint.h>
#include <sys/types.h>

#include <map>
#include <memory>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/scoped_file.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/callback.h>
#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>
#include <dbus/bus.h>
#include <dbus/exported_object.h>
#include <dbus/message.h>

namespace vm_tools {
namespace seneschal {

class Service final {
 public:
  // Creates a new Service instance.  |quit_closure| is posted to the TaskRunner
  // for the current thread when this process receives a SIGTERM.
  static std::unique_ptr<Service> Create(base::OnceClosure quit_closure);
  ~Service() = default;

 private:
  // Relevant information about a currently running server.
  class ServerInfo final {
   public:
    ServerInfo(pid_t pid, base::FilePath root_dir);
    ~ServerInfo();

    // Make sure this type can be moved.  Unfortunately we cannot use the
    // default move constructor because ScopedTempDir doesn't have a move
    // constructor.
    ServerInfo(ServerInfo&& other) noexcept;
    ServerInfo(const ServerInfo&) = delete;
    ServerInfo& operator=(const ServerInfo&) = delete;

    ServerInfo& operator=(ServerInfo&& other) noexcept;

    pid_t pid() const { return pid_; }
    const base::ScopedTempDir& root_dir() const { return root_dir_; }

   private:
    // The process id for this server.
    pid_t pid_;

    // The root of this server.
    base::ScopedTempDir root_dir_;
  };

  explicit Service(base::OnceClosure quit_closure);
  Service(const Service&) = delete;
  Service& operator=(const Service&) = delete;

  // Initializes the service by connecting to the system DBus daemon, exporting
  // its methods, and taking ownership of it's name.
  bool Init();

  // Handles the termination of a child process.
  void HandleChildExit();

  // Handles a SIGTERM.
  void HandleSigterm();

  void OnSignalReadable();

  // Handles a request to start a new 9p server.
  std::unique_ptr<dbus::Response> StartServer(dbus::MethodCall* method_call);

  // Handles a request to stop a running 9p server.
  std::unique_ptr<dbus::Response> StopServer(dbus::MethodCall* method_call);

  // Handles a request to share a path with a running server.
  std::unique_ptr<dbus::Response> SharePath(dbus::MethodCall* method_call);

  // Handles a request to share a path with a running server.
  std::unique_ptr<dbus::Response> UnsharePath(dbus::MethodCall* method_call);

  // Forcibly kills a server if it hasn't already exited.
  void KillServer(uint32_t handle);

  // The currently active 9p servers.
  std::map<uint32_t, ServerInfo> servers_;
  uint32_t next_server_handle_;

  // File descriptor on which we will watch for signals.
  base::ScopedFD signal_fd_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> watcher_;

  // Connection to the system bus.
  scoped_refptr<dbus::Bus> bus_;
  dbus::ExportedObject* exported_object_;  // Owned by |bus_|.

  // Closure to be posted to the task runner when we receive a SIGTERM.
  base::OnceClosure quit_closure_;

  base::WeakPtrFactory<Service> weak_factory_;
};

}  // namespace seneschal
}  // namespace vm_tools

#endif  // VM_TOOLS_SENESCHAL_SERVICE_H_
