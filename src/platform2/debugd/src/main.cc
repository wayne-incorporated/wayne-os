// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include <base/command_line.h>
#include <base/logging.h>
#include <brillo/daemons/dbus_daemon.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>
#include <chromeos/dbus/service_constants.h>
#include <chromeos/libminijail.h>
#include <chromeos/scoped_minijail.h>

#include <memory>

#include "debugd/src/debugd_dbus_adaptor.h"

namespace {

// For TPM 1.2 only: Directory to mount for access to tcsd socket.
constexpr char kTcsdDir[] = "/run/tcsd";

// Minijail APIs tend to return the errno value directly, so pull that out and
// then return success based on it.
static inline bool mj_call(int ret) {
  errno = -ret;
  return errno == 0;
}

// @brief Enter a VFS namespace.
//
// We don't want anyone other than our descendants to see our tmpfs.
void enter_vfs_namespace() {
  ScopedMinijail j(minijail_new());

  // Create a minimalistic mount namespace with just the bare minimum required.
  minijail_namespace_vfs(j.get());
  PCHECK(mj_call(minijail_enter_pivot_root(j.get(), "/mnt/empty")));
  PCHECK(mj_call(minijail_bind(j.get(), "/", "/", 0)));
  PCHECK(mj_call(minijail_mount_with_data(j.get(), "none", "/proc", "proc",
                                          MS_NOSUID | MS_NOEXEC | MS_NODEV,
                                          nullptr)));
  PCHECK(mj_call(minijail_bind(j.get(), "/var", "/var", 1)));

  // Hack a path for vpd until it can migrate to /var.
  // https://crbug.com/876838
  PCHECK(mj_call(minijail_mount_with_data(j.get(), "tmpfs", "/mnt", "tmpfs",
                                          MS_NOSUID | MS_NOEXEC | MS_NODEV,
                                          "mode=0755,size=10M")));
  const char kVpdPath[] = "/mnt/stateful_partition/unencrypted/cache/vpd";
  PCHECK(mj_call(minijail_bind(j.get(), kVpdPath, kVpdPath, 1)));

  // debugd needs access to the stateful swap directory.
  const base::FilePath kSwapWbDir(
      "/mnt/stateful_partition/unencrypted/userspace_swap.tmp");
  if (!base::PathExists(kSwapWbDir)) {
    base::File::Error error;
    if (!base::CreateDirectoryAndGetError(kSwapWbDir, &error)) {
      LOG(FATAL) << "Unable to create " << kSwapWbDir << ":"
                 << base::File::ErrorToString(error);
    }
  }
  PCHECK(mj_call(minijail_bind(j.get(), kSwapWbDir.MaybeAsASCII().c_str(),
                               kSwapWbDir.MaybeAsASCII().c_str(), 1)));

  minijail_remount_mode(j.get(), MS_SLAVE);

  PCHECK(mj_call(minijail_mount_with_data(j.get(), "tmpfs", "/run", "tmpfs",
                                          MS_NOSUID | MS_NOEXEC | MS_NODEV,
                                          nullptr)));

  PCHECK(mj_call(minijail_mount(j.get(), "/run/daemon-store/debugd",
                                "/run/daemon-store/debugd", "none",
                                MS_BIND | MS_REC)));

  // Mount /run/debugd for a shared place for runtime data.
  PCHECK(mj_call(minijail_bind(j.get(), "/run/debugd", "/run/debugd", 1)));

  // Mount /run/dbus to be able to communicate with D-Bus.
  PCHECK(mj_call(minijail_bind(j.get(), "/run/dbus", "/run/dbus", 0)));

  // Mount /tmp, /run/cups, and /run/ippusb to be able to communicate with CUPS.
  // /tmp must be at least 3 * kernel partition size plus a little extra. This
  // is required by make_dev_ssd.sh, which is called from debugd through
  // dev_features_rootfs_verification.
  //
  // The script reads out the old kernel partition as a blob, repacks it (which
  // often leads to a smaller blob), then copies the old blob to a new blob and
  // overwrites the repacked kernel onto the new blob.
  minijail_mount_tmp_size(j.get(), 100 * 1024 * 1024);
  PCHECK(mj_call(minijail_bind(j.get(), "/run/cups", "/run/cups", 0)));
  // Mount /run/ippusb to be able to communicate with CUPS.
  PCHECK(mj_call(minijail_bind(j.get(), "/run/ippusb", "/run/ippusb", 0)));

  // Mount writable debug directories for cups, ippusb, and lorgnette for use
  // with printscan_tool.
  PCHECK(
      mj_call(minijail_bind(j.get(), "/run/cups/debug", "/run/cups/debug", 1)));
  PCHECK(mj_call(
      minijail_bind(j.get(), "/run/ippusb/debug", "/run/ippusb/debug", 1)));
  PCHECK(mj_call(minijail_bind(j.get(), "/run/lorgnette/debug",
                               "/run/lorgnette/debug", 1)));

  // In case we start before avahi-daemon, make sure the path exists.
  mkdir("/var/run/avahi-daemon", 0755);
  // Mount /run/avahi-daemon in order to perform mdns name resolution.
  PCHECK(mj_call(
      minijail_bind(j.get(), "/run/avahi-daemon", "/run/avahi-daemon", 0)));

  // Since shill provides network resolution settings, bind mount it.
  // In case we start before shill, make sure the path exists.
  // TODO(259354228): Remove once resolv.conf migration to dns-proxy is done.
  mkdir("/run/shill", 0755);
  PCHECK(mj_call(minijail_bind(j.get(), "/run/shill", "/run/shill", 0)));

  // Since dns-proxy provides network resolution settings, bind mount it.
  // Path is expected to always exists before as it is created through
  // tmpfiles.d.
  PCHECK(
      mj_call(minijail_bind(j.get(), "/run/dns-proxy", "/run/dns-proxy", 0)));

  // Bind mount /run/lockbox and /var/lib/devicesettings to be able to read
  // policy files and check device policies.
  // In case we start before, make sure the path exists.
  mkdir("/run/lockbox", 0755);
  PCHECK(mj_call(minijail_bind(j.get(), "/run/lockbox", "/run/lockbox", 0)));
  // In case we start before, make sure the path exists.
  mkdir("/var/lib/devicesettings", 0755);
  PCHECK(mj_call(minijail_bind(j.get(), "/var/lib/devicesettings",
                               "/var/lib/devicesettings", 0)));

  // Mount /dev to be able to inspect devices.
  PCHECK(mj_call(minijail_mount_with_data(j.get(), "/dev", "/dev", "bind",
                                          MS_BIND | MS_REC, nullptr)));

  // Mount /sys to access some logs.
  PCHECK(mj_call(minijail_mount_with_data(j.get(), "/sys", "/sys", "bind",
                                          MS_BIND | MS_REC, nullptr)));

  // Mount /run/chromeos-config/v1 to access chromeos-config.
  // /run/chromeos-config/v1 is not consistently available on devices in the
  // field, see b/256739303. Make this failure non-fatal.
  if (!mj_call(minijail_bind(j.get(), "/run/chromeos-config/v1",
                             "/run/chromeos-config/v1", 0))) {
    PLOG(ERROR) << "Could not bind mount /run/chromeos-config/v1";
  }

  // Mount /run/lock so that lock file for crossystem is shared.
  PCHECK(mj_call(minijail_bind(j.get(), "/run/lock", "/run/lock", 1)));

  if (USE_TPM) {
    // For TPM 1.2 only: Enable utilities that communicate with TPM via tcsd -
    // mount directory containing tcsd socket.
    mkdir(kTcsdDir, 0755);
    PCHECK(mj_call(minijail_bind(j.get(), kTcsdDir, kTcsdDir, 0)));
  }

  minijail_enter(j.get());
}

class Daemon : public brillo::DBusServiceDaemon {
 public:
  explicit Daemon(const bool perf_logging)
      : DBusServiceDaemon(debugd::kDebugdServiceName),
        perf_logging_(perf_logging) {}
  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;

 protected:
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override {
    adaptor_ = std::make_unique<debugd::DebugdDBusAdaptor>(bus_, perf_logging_);
    adaptor_->RegisterAsync(
        sequencer->GetHandler("RegisterAsync() failed.", true));
  }

 private:
  std::unique_ptr<debugd::DebugdDBusAdaptor> adaptor_;
  bool perf_logging_;
};

}  // namespace

int main(int argc, char* argv[]) {
  DEFINE_bool(perf_logging, false,
              "Record and locally log the performance of all LogTool sub-tasks "
              "within the feedback log collection function.")
      brillo::FlagHelper::Init(argc, argv, "CrOS debug daemon");
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  enter_vfs_namespace();
  Daemon(FLAGS_perf_logging).Run();
  return 0;
}
