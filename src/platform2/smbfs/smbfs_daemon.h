// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBFS_SMBFS_DAEMON_H_
#define SMBFS_SMBFS_DAEMON_H_

#include <fuse_lowlevel.h>
#include <sys/types.h>

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <brillo/daemons/dbus_daemon.h>
#include <mojo/core/embedder/scoped_ipc_support.h>

#include "smbfs/mojo_session.h"

namespace smbfs {

class Filesystem;
class FuseSession;
struct Options;

class SmbFsDaemon : public brillo::DBusDaemon {
 public:
  SmbFsDaemon(fuse_chan* chan, const Options& options);
  SmbFsDaemon(const SmbFsDaemon&) = delete;
  SmbFsDaemon& operator=(const SmbFsDaemon&) = delete;

  ~SmbFsDaemon() override;

 protected:
  // brillo::Daemon overrides.
  int OnInit() override;
  int OnEventLoopStarted() override;

 private:
  // Starts the fuse session using the filesystem |fs|. Returns true if the
  // session is successfully started.
  bool StartFuseSession(std::unique_ptr<Filesystem> fs);

  // Set up libsmbclient configuration files.
  bool SetupSmbConf();

  // Initialise Mojo IPC system.
  bool InitMojo();

  // Callback for MojoSession shutdown.
  void OnSessionShutdown();

  fuse_chan* chan_;
  const bool use_test_fs_;
  const std::string share_path_;
  const uid_t uid_;
  const gid_t gid_;
  const std::string mojo_id_;
  std::unique_ptr<FuseSession> session_;
  std::unique_ptr<Filesystem> fs_;
  base::ScopedTempDir temp_dir_;

  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;
  std::unique_ptr<MojoSession> mojo_session_;
};

}  // namespace smbfs

#endif  // SMBFS_SMBFS_DAEMON_H_
