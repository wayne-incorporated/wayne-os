// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_ADB_PROXY_H_
#define PATCHPANEL_ADB_PROXY_H_

#include <deque>
#include <memory>
#include <optional>

#include <base/files/scoped_file.h>
#include <base/memory/weak_ptr.h>
#include <brillo/daemons/dbus_daemon.h>
#include <dbus/bus.h>

#include "patchpanel/file_descriptor_watcher_posix.h"
#include "patchpanel/ipc.h"
#include "patchpanel/message_dispatcher.h"
#include "patchpanel/socket.h"
#include "patchpanel/socket_forwarder.h"

namespace patchpanel {

// Running the proxy on port 5555 will cause ADBD to see it as an Android
// emulator rather than an attached device. This means, whenever host ADBD
// server runs a device named "emulator-5554" will show up.
// Connections to ARC via ADB (including by Tast) should now be done by
// starting ADB server (e.g. 'adb devices') instead of
// 'adb connect 127.0.0.1:5555' to avoid seeing multiple devices.
constexpr uint16_t kAdbProxyTcpListenPort = 5555;

// Subprocess for proxying ADB traffic.
class AdbProxy : public brillo::DBusDaemon {
 public:
  explicit AdbProxy(base::ScopedFD control_fd);
  AdbProxy(const AdbProxy&) = delete;
  AdbProxy& operator=(const AdbProxy&) = delete;

  virtual ~AdbProxy();

 protected:
  int OnInit() override;

  void OnParentProcessExit();
  void OnGuestMessage(const SubprocessMessage& msg);

 private:
  void InitialSetup();
  void Reset();
  void OnFileCanReadWithoutBlocking();

  // Attempts to establish a connection to ADB at well-known destinations.
  std::unique_ptr<Socket> Connect() const;

  // Start listening for ADB connection. Only listen when ARC guest is started
  // and either Chrome OS is in developer mode or ADB sideloading is turned on.
  void Listen();

  // Checks ADB sideloading status and set it to |adb_sideloading_enabled_|.
  // This function will call itself again if ADB sideloading status is not
  // known yet. If ADB sideloading status is enabled and guest is started,
  // start listening for connections.
  void CheckAdbSideloadingStatus(int num_try);

  MessageDispatcher<SubprocessMessage> msg_dispatcher_;
  std::unique_ptr<Socket> src_;
  std::deque<std::unique_ptr<SocketForwarder>> fwd_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> src_watcher_;

  GuestMessage::GuestType arc_type_;
  std::optional<uint32_t> arcvm_vsock_cid_;

  bool dev_mode_enabled_;
  bool adb_sideloading_enabled_;

  base::WeakPtrFactory<AdbProxy> weak_factory_{this};
};

}  // namespace patchpanel

#endif  // PATCHPANEL_ADB_PROXY_H_
