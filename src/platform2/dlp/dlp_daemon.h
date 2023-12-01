// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef DLP_DLP_DAEMON_H_
#define DLP_DLP_DAEMON_H_

#include <memory>

#include <brillo/daemons/dbus_daemon.h>

namespace brillo {
namespace dbus_utils {
class AsyncEventSequencer;
}
}  // namespace brillo

namespace dlp {

class DlpAdaptor;

class DlpDaemon : public brillo::DBusServiceDaemon {
 public:
  DlpDaemon(int fanotify_perm_fd,
            int fanotify_notif_fd,
            const base::FilePath& home_path,
            const base::FilePath& database_path);
  DlpDaemon(const DlpDaemon&) = delete;
  DlpDaemon& operator=(const DlpDaemon&) = delete;
  ~DlpDaemon();

 protected:
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override;

 private:
  // Params to be passed to DlpAdaptor:
  // Already initialized fanotify file descriptors.
  int fanotify_perm_fd_;
  int fanotify_notif_fd_;
  // Path to the root directory with user files.
  const base::FilePath home_path_;
  // Path to the database directory location.
  const base::FilePath database_path_;

  std::unique_ptr<DlpAdaptor> adaptor_;
};

}  // namespace dlp
#endif  // DLP_DLP_DAEMON_H_
