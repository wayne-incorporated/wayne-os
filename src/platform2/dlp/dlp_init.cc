// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sys/fanotify.h>
#include <sys/mount.h>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/syslog_logging.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>
#include <libminijail.h>
#include <scoped_minijail.h>

#include "dlp/dlp_metrics.h"
#include "dlp/kernel_version_tools.h"

namespace {

constexpr char kDlpPath[] = "/usr/sbin/dlp";

const char kDlpSeccompPolicy[] = "/usr/share/policy/dlp-seccomp.policy";

bool RetrieveSanitizedPrimaryUsername(std::string* out_sanitized_username) {
  DCHECK(out_sanitized_username);

  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::Bus> bus = new dbus::Bus(options);
  CHECK(bus->Connect()) << "Failed to connect to system D-Bus";

  dbus::ObjectProxy* session_manager_proxy = bus->GetObjectProxy(
      login_manager::kSessionManagerServiceName,
      dbus::ObjectPath(login_manager::kSessionManagerServicePath));
  dbus::MethodCall method_call(
      login_manager::kSessionManagerInterface,
      login_manager::kSessionManagerRetrievePrimarySession);
  std::unique_ptr<dbus::Response> response =
      session_manager_proxy->CallMethodAndBlock(
          &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!response.get()) {
    LOG(ERROR) << "Cannot retrieve username for primary session.";
    bus->ShutdownAndBlock();
    return false;
  }

  dbus::MessageReader response_reader(response.get());
  std::string username;
  if (!response_reader.PopString(&username)) {
    LOG(ERROR) << "Primary session username bad format.";
    bus->ShutdownAndBlock();
    return false;
  }
  if (!response_reader.PopString(out_sanitized_username)) {
    LOG(ERROR) << "Primary session sanitized username bad format.";
    bus->ShutdownAndBlock();
    return false;
  }
  bus->ShutdownAndBlock();
  return true;
}

base::FilePath GetUserHomePath(const std::string& username) {
  return base::FilePath("/home/chronos/").Append("u-" + username);
}

base::FilePath GetDatabaseFilePath(const std::string& username) {
  return base::FilePath("/run/daemon-store/dlp/")
      .Append(username)
      .Append("database");
}

bool SetDatabaseDirectoryOwnership(const base::FilePath& path) {
  struct passwd user;
  struct passwd* user_p;
  std::vector<char> user_buf(16384);
  getpwnam_r("dlp", &user, user_buf.data(), user_buf.size(), &user_p);
  if (!user_p) {
    LOG(ERROR) << "User dlp not found";
    return false;
  }

  struct group group;
  struct group* group_p;
  std::vector<char> group_buf(16384);
  getgrnam_r("dlp", &group, group_buf.data(), group_buf.size(), &group_p);
  if (!group_p) {
    LOG(ERROR) << "Group dlp not found";
    return false;
  }

  return (HANDLE_EINTR(
              chown(path.value().c_str(), user.pw_uid, group.gr_gid)) == 0);
}

ScopedMinijail SetupMinijail(const base::FilePath& home_path,
                             const std::vector<int> fds_to_preserve) {
  ScopedMinijail j(minijail_new());

  minijail_change_user(j.get(), "dlp");
  minijail_change_group(j.get(), "dlp");
  minijail_inherit_usergroups(j.get());

  minijail_no_new_privs(j.get());
  minijail_namespace_cgroups(j.get());
  minijail_namespace_uts(j.get());
  minijail_namespace_ipc(j.get());
  minijail_namespace_net(j.get());
  minijail_namespace_vfs(j.get());

  minijail_enter_pivot_root(j.get(), "/mnt/empty");
  minijail_bind(j.get(), "/", "/", 0);
  minijail_bind(j.get(), "/dev", "/dev", 0);
  minijail_bind(j.get(), "/proc", "/proc", 0);

  minijail_remount_mode(j.get(), MS_SLAVE);
  minijail_remount_proc_readonly(j.get());
  minijail_mount_tmp(j.get());
  minijail_mount_with_data(j.get(), "tmpfs", "/run", "tmpfs", 0, nullptr);
  minijail_mount_with_data(j.get(), "tmpfs", "/var", "tmpfs", 0, nullptr);
  minijail_bind(j.get(), "/run/dbus", "/run/dbus", 0);
  minijail_mount(j.get(), "/run/daemon-store/dlp", "/run/daemon-store/dlp",
                 "none", MS_BIND | MS_REC);
  minijail_bind(j.get(), "/home/chronos", "/home/chronos", 0);
  minijail_bind(j.get(), home_path.value().c_str(), home_path.value().c_str(),
                0);
  minijail_bind(j.get(), home_path.Append("MyFiles/Downloads").value().c_str(),
                home_path.Append("MyFiles/Downloads").value().c_str(), 0);
  minijail_bind(j.get(), "/var/lib/metrics", "/var/lib/metrics", 0);

  // Use a seccomp filter.
  minijail_parse_seccomp_filters(j.get(), kDlpSeccompPolicy);
  minijail_use_seccomp_filter(j.get());

  for (const auto& fd : fds_to_preserve) {
    minijail_preserve_fd(j.get(), fd, fd);
  }

  return j;
}

}  // namespace

int main(int /* argc */, char* /* argv */[]) {
  brillo::OpenLog("dlp_init", true /* log_pid */);
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  dlp::DlpMetrics dlp_metrics;

  LOG(INFO) << "DLP Init";

  // Get user session hash.
  std::string sanitized_username;
  if (!RetrieveSanitizedPrimaryUsername(&sanitized_username)) {
    LOG(ERROR) << "Failed to get primary username";
    dlp_metrics.SendInitError(dlp::InitError::kPrimaryUsernameRetrievalError);
    return 1;
  }

  // Create database directory.
  const base::FilePath database_path = GetDatabaseFilePath(sanitized_username);
  if (!base::CreateDirectory(database_path)) {
    PLOG(ERROR) << "Can't create database directory: " << database_path;
    dlp_metrics.SendDatabaseError(dlp::DatabaseError::kCreateDirError);
    return 1;
  }
  if (!SetDatabaseDirectoryOwnership(database_path)) {
    LOG(ERROR) << "Can't set database directory ownership: " << database_path;
    dlp_metrics.SendDatabaseError(dlp::DatabaseError::kSetOwnershipError);
    return 1;
  }

  // Retrieve user home path.
  const base::FilePath home_path = GetUserHomePath(sanitized_username);

  // Initialize fanotify file descriptors.
  int fanotify_perm_fd =
      fanotify_init(FAN_CLASS_CONTENT, O_RDONLY | O_LARGEFILE);
  if (fanotify_perm_fd < 0) {
    PLOG(ERROR) << "fanotify_init() failed";
    dlp_metrics.SendFanotifyError(dlp::FanotifyError::kInitError);
    return 1;
  }

  const std::pair<int, int> kernel_version = dlp::GetKernelVersion();

  dlp_metrics.SendBooleanHistogram(
      dlp::kDlpFanotifyMarkFilesystemSupport,
      kernel_version >= dlp::kMinKernelVersionForFanMarkFilesystem);

  if (kernel_version >= dlp::kMinKernelVersionForFanMarkFilesystem) {
    if (fanotify_mark(fanotify_perm_fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                      FAN_OPEN_PERM, AT_FDCWD, home_path.value().c_str()) < 0) {
      PLOG(ERROR) << "fanotify_mark for OPEN_PERM (" << home_path << ") failed";
      dlp_metrics.SendFanotifyError(dlp::FanotifyError::kMarkError);
      return 1;
    }
  } else {
    LOG(INFO) << "FAN_MARK_FILESYSTEM is not supported, DLP is not active";
  }

  dlp_metrics.SendBooleanHistogram(
      dlp::kDlpFanotifyDeleteEventSupport,
      kernel_version >= dlp::kMinKernelVersionForFanDeleteEvents);

  int fanoify_notif_fd = 0;
  if (kernel_version >= dlp::kMinKernelVersionForFanDeleteEvents) {
    fanoify_notif_fd =
        fanotify_init(FAN_CLASS_NOTIF | /*FAN_REPORT_FID=*/0x00000200, 0);
    if (fanoify_notif_fd < 0) {
      PLOG(ERROR) << "fanotify_init() failed";
      dlp_metrics.SendFanotifyError(dlp::FanotifyError::kInitError);
      return 1;
    }
  } else {
    LOG(INFO) << "FAN_DELETE_SELF is not supported, DLP is not listening to "
                 "file deletions";
  }

  // Setup minijail.
  ScopedMinijail j =
      SetupMinijail(home_path, {fanotify_perm_fd, fanoify_notif_fd});

  // Configure arguments.
  const std::string fanotify_perm_fd_s = base::NumberToString(fanotify_perm_fd);
  const std::string fanotify_notif_fd_s =
      base::NumberToString(fanoify_notif_fd);
  const char* const args[] = {kDlpPath,
                              fanotify_perm_fd_s.c_str(),
                              fanotify_notif_fd_s.c_str(),
                              home_path.value().c_str(),
                              database_path.value().c_str(),
                              nullptr};

  // Run the DLP daemon in the minijail.
  minijail_run(j.get(), kDlpPath, const_cast<char* const*>(args));

  return 0;
}
