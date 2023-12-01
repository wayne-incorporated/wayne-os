// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_VM_WL_INTERFACE_H_
#define VM_TOOLS_CONCIERGE_VM_WL_INTERFACE_H_

#include <memory>
#include <string>

#include <vm_wl/wl.pb.h>

#include "base/files/file_path.h"
#include "base/files/scoped_file.h"
#include "base/files/scoped_temp_dir.h"
#include "base/memory/scoped_refptr.h"
#include "base/types/expected.h"
#include "vm_tools/common/vm_id.h"

namespace dbus {
class Bus;
}  // namespace dbus

namespace vm_tools::concierge {

// Handle to a wayland server. This object's existence represents that a wayland
// server is running, and it will try to shut the server down (with a
// non-blocking dbus call) when it is destroyed.
class ScopedWlSocket {
 public:
  // This destructor issues a non-blocking dbus call to close the server.
  // Closing the server is not critical, so if the call fails we just rely on
  // the OS cleaning up its /tmp on shutdown.
  ~ScopedWlSocket();

  // Returns the filesystem path to the server.
  base::FilePath GetPath() const;

 private:
  // Only the interface can construct these.
  friend class VmWlInterface;
  ScopedWlSocket(base::ScopedTempDir socket_dir,
                 base::ScopedFD socket_fd,
                 scoped_refptr<dbus::Bus> bus,
                 wl::VmDescription description);

  // Path to the socket which concierge made using bind().
  base::ScopedTempDir socket_dir_;

  // Concerge's handle to the server socket, this will be dup()ed for chrome.
  base::ScopedFD socket_fd_;

  // Keep the dbus ref alive just in case
  scoped_refptr<dbus::Bus> bus_;

  // Description of the VM that uses this socket
  wl::VmDescription description_;
};

class VmWlInterface {
 public:
  // Convenience typedef
  using Result = base::expected<std::unique_ptr<ScopedWlSocket>, std::string>;

  // Creates a wayland server, via a blocking dbus call, for a vm with the given
  // id and type. Returns either a scoped handle to that server or a string
  // description of the error that happened during creation.
  static Result CreateWaylandServer(scoped_refptr<dbus::Bus> bus,
                                    const VmId& vm_id,
                                    VmId::Type classification);
};

}  // namespace vm_tools::concierge

#endif  //  VM_TOOLS_CONCIERGE_VM_WL_INTERFACE_H_
