// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OCR_DAEMON_H_
#define OCR_DAEMON_H_

#include <memory>
#include <string>

#include <base/files/scoped_file.h>
#include <base/memory/weak_ptr.h>
#include <brillo/daemons/dbus_daemon.h>
#include <brillo/dbus/async_event_sequencer.h>
#include <brillo/dbus/dbus_object.h>
#include <mojo/core/embedder/scoped_ipc_support.h>

#include "ocr/ocr_service_impl.h"

namespace ocr {

// Optical Character Recognition daemon with D-Bus support.
// The primary function of the D-Bus interface is to receive Mojo
// bootstrap requests from clients.
class OcrDaemon : public brillo::DBusServiceDaemon {
 public:
  OcrDaemon();
  ~OcrDaemon() override;
  OcrDaemon(const OcrDaemon&) = delete;
  OcrDaemon& operator=(const OcrDaemon&) = delete;

 protected:
  // brillo:DBusServiceDaemon:
  int OnInit() override;
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override;

 private:
  // Implementation of org.chromium.OpticalCharacterRecognition interface:
  // Bootstraps a Mojo connection to the OCR service. The client
  // passes a file descriptor |mojo_fd|, representing a Unix socket.
  // We only accept invitations from Chrome and send invitations to other
  // processes.
  std::string BootstrapMojoConnection(const base::ScopedFD& mojo_fd,
                                      bool should_accept_invitation);

  // Responds to Mojo connection errors with Chrome by quitting the daemon.
  // Ignores disconnection errors from other clients.
  void OnDisconnect(bool should_quit);

  // As long as this object is alive, all Mojo API surfaces relevant to IPC
  // connections are usable and message pipes which span a process boundary
  // will continue to function.
  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;

  // D-Bus object that supports the OpticalCharacterRecognition interface.
  std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object_;

  // Maintains the Mojo connection with OCR service clients.
  std::unique_ptr<OcrServiceImpl> ocr_service_impl_;

  // Whether binding of the Mojo service was attempted. This flag is needed for
  // detecting repeated Mojo bootstrapping attempts.
  bool mojo_service_bind_attempted_ = false;

  // Member variables should appear before the WeakPtrFactory to ensure
  // that any WeakPtrs to OcrDaemon are invalidated before its member
  // variables' destructors are executed, rendering them invalid.
  // Members are destructed in reverse-order that they appear in the
  // class definition, so this must be the last class member.
  base::WeakPtrFactory<OcrDaemon> weak_ptr_factory_{this};
};

}  // namespace ocr

#endif  // OCR_DAEMON_H_
