// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IMAGE_BURNER_DAEMON_H_
#define IMAGE_BURNER_DAEMON_H_

#include <memory>

#include <brillo/daemons/dbus_daemon.h>

#include "image-burner/image_burner_impl.h"
#include "image-burner/image_burner_utils.h"

namespace imageburn {

class ImageBurnService;

class Daemon : public brillo::DBusServiceDaemon {
 public:
  Daemon();
  ~Daemon() override;

  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;

 private:
  // brillo::DBusServiceDaemon overrides:
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override;

  BurnWriter writer_;
  BurnReader reader_;
  BurnPathGetter path_getter_;
  BurnerImpl burner_{&writer_, &reader_, nullptr, &path_getter_};

  std::unique_ptr<ImageBurnService> service_;
};

}  // namespace imageburn

#endif  // IMAGE_BURNER_DAEMON_H_
