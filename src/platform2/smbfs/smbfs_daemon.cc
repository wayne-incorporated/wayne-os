// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbfs/smbfs_daemon.h"

#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>

#include <utility>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/no_destructor.h>
#include <base/notreached.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/message_loops/message_loop.h>
#include <brillo/daemons/dbus_daemon.h>
#include <chromeos/dbus/service_constants.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/platform/platform_channel.h>
#include <mojo/public/cpp/system/invitation.h>

#include "smbfs/dbus-proxies.h"
#include "smbfs/fuse_session.h"
#include "smbfs/smb_filesystem.h"
#include "smbfs/smbfs.h"
#include "smbfs/test_filesystem.h"

namespace smbfs {
namespace {

constexpr char kSmbConfDir[] = ".smb";
constexpr char kSmbConfFile[] = "smb.conf";

constexpr char kSmbConfData[] = R"(
[global]
  client min protocol = SMB2
  client max protocol = SMB3
  security = user
)";

bool CreateDirectoryAndLog(const base::FilePath& path) {
  CHECK(path.IsAbsolute());
  base::File::Error error;
  bool success = base::CreateDirectoryAndGetError(path, &error);
  LOG_IF(ERROR, !success) << "Failed to create directory " << path.value()
                          << ": " << base::File::ErrorToString(error);
  return success;
}

// SmbFilesystem delegate that does nothing.
class NopSmbFilesystemDelegate : public SmbFilesystem::Delegate {
 public:
  NopSmbFilesystemDelegate() = default;
  ~NopSmbFilesystemDelegate() = default;

 private:
  // SmbFilesystem::Delegate overrides.:
  void RequestCredentials(RequestCredentialsCallback callback) override {
    // Respond with no null credentials, equivalent to the user canceling the
    // request dialog.
    std::move(callback).Run(nullptr);
  }
};

}  // namespace

SmbFsDaemon::SmbFsDaemon(fuse_chan* chan, const Options& options)
    : chan_(chan),
      use_test_fs_(options.use_test),
      share_path_(options.share_path),
      uid_(options.uid ? options.uid : getuid()),
      gid_(options.gid ? options.gid : getgid()),
      mojo_id_(options.mojo_id ? options.mojo_id : "") {
  DCHECK(chan_);
}

SmbFsDaemon::~SmbFsDaemon() = default;

int SmbFsDaemon::OnInit() {
  int ret = brillo::DBusDaemon::OnInit();
  if (ret != EX_OK) {
    return ret;
  }

  if (!SetupSmbConf()) {
    return EX_SOFTWARE;
  }

  if (!share_path_.empty()) {
    static NopSmbFilesystemDelegate dummy_delegate;
    SmbFilesystem::Options options;
    options.share_path = share_path_;
    options.uid = uid_;
    options.gid = gid_;
    options.allow_ntlm = true;
    std::unique_ptr<SmbFilesystem> fs =
        std::make_unique<SmbFilesystem>(&dummy_delegate, std::move(options));
    SmbFilesystem::ConnectError error = fs->EnsureConnected();
    if (error != SmbFilesystem::ConnectError::kOk) {
      LOG(ERROR) << "Unable to connect to SMB filesystem: " << error;
      return EX_SOFTWARE;
    }
    fs_ = std::move(fs);
  }

  return EX_OK;
}

int SmbFsDaemon::OnEventLoopStarted() {
  int ret = brillo::DBusDaemon::OnEventLoopStarted();
  if (ret != EX_OK) {
    return ret;
  }

  std::unique_ptr<Filesystem> fs;
  if (use_test_fs_) {
    fs = std::make_unique<TestFilesystem>(uid_, gid_);
  } else if (fs_) {
    fs = std::move(fs_);
  } else if (!mojo_id_.empty()) {
    if (!InitMojo()) {
      return EX_SOFTWARE;
    }
    return EX_OK;
  } else {
    NOTREACHED();
  }

  session_ = std::make_unique<FuseSession>(std::move(fs), chan_);
  chan_ = nullptr;
  if (!session_->Start(base::BindOnce(&Daemon::Quit, base::Unretained(this)))) {
    return EX_SOFTWARE;
  }

  return EX_OK;
}

bool SmbFsDaemon::SetupSmbConf() {
  // Create a temporary "home" directory where configuration files used by
  // libsmbclient will be placed.
  CHECK(temp_dir_.CreateUniqueTempDir());
  PCHECK(setenv("HOME", temp_dir_.GetPath().value().c_str(),
                1 /* overwrite */) == 0);
  LOG(INFO) << "Storing SMB configuration files in: "
            << temp_dir_.GetPath().value();

  bool success = CreateDirectoryAndLog(temp_dir_.GetPath().Append(kSmbConfDir));
  if (!success) {
    return false;
  }

  // TODO(amistry): Replace with smbc_setOptionProtocols() when Samba is
  // updated.
  return base::WriteFile(
             temp_dir_.GetPath().Append(kSmbConfDir).Append(kSmbConfFile),
             kSmbConfData, sizeof(kSmbConfData)) == sizeof(kSmbConfData);
}

bool SmbFsDaemon::InitMojo() {
  LOG(INFO) << "Boostrapping connection using Mojo";

  mojo::core::Init();
  ipc_support_ = std::make_unique<mojo::core::ScopedIPCSupport>(
      base::SingleThreadTaskRunner::GetCurrentDefault(),
      mojo::core::ScopedIPCSupport::ShutdownPolicy::FAST);

  mojo::PlatformChannel channel;

  // The SmbFs service is hosted in the browser, so is expected to
  // already be running when this starts. If this is not the case, the D-Bus
  // IPC below will fail and this process will shut down.
  org::chromium::SmbFsProxy dbus_proxy(bus_, kSmbFsServiceName);
  brillo::ErrorPtr error;
  if (!dbus_proxy.OpenIpcChannel(
          mojo_id_, channel.TakeRemoteEndpoint().TakePlatformHandle().TakeFD(),
          &error)) {
    return false;
  }

  mojo::IncomingInvitation invitation =
      mojo::IncomingInvitation::Accept(channel.TakeLocalEndpoint());
  mojo_session_ = std::make_unique<MojoSession>(
      bus_, temp_dir_.GetPath(), chan_,
      mojo::PendingReceiver<mojom::SmbFsBootstrap>(
          invitation.ExtractMessagePipe(mojom::kBootstrapPipeName)),
      uid_, gid_,
      base::BindOnce(&SmbFsDaemon::OnSessionShutdown, base::Unretained(this)));

  return true;
}

void SmbFsDaemon::OnSessionShutdown() {
  LOG(INFO) << "Mojo session shut down. Exiting.";
  QuitWithExitCode(EX_SOFTWARE);
}

}  // namespace smbfs
