// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//

#include <base/check.h>
#include <base/check_op.h>
#include <base/command_line.h>
#include <base/logging.h>
#include <brillo/syslog_logging.h>
#include <brillo/userdb_utils.h>
#include <libminijail.h>
#include <scoped_minijail.h>

#include "trunks/csme/tpm_tunnel_service.h"

namespace {

namespace switches {

constexpr char kNoCloseOnDaemonize[] = "noclose";
constexpr char kNoDaemonize[] = "nodaemonize";
constexpr char kLogToStderr[] = "log_to_stderr";

}  // namespace switches

constexpr uid_t kRootUID = 0;
constexpr char kTpmTunnelUser[] = "tpm_tunneld";
constexpr char kTpmTunnelGroup[] = "tpm_tunneld";
constexpr char kTpmTunnelSeccompPath[] =
    "/usr/share/policy/tpm_tunneld-seccomp.policy";

void InitMinijailSandbox() {
  uid_t tpm_tunnel_uid;
  gid_t tpm_tunnel_gid;
  CHECK(brillo::userdb::GetUserInfo(kTpmTunnelUser, &tpm_tunnel_uid,
                                    &tpm_tunnel_gid))
      << "Error getting tpm_tunnel uid and gid.";
  CHECK_EQ(getuid(), kRootUID) << "tpm_tunneld not initialized as root.";

  ScopedMinijail j(minijail_new());
  minijail_set_seccomp_filter_tsync(j.get());
  minijail_no_new_privs(j.get());
  minijail_use_seccomp_filter(j.get());
  minijail_parse_seccomp_filters(j.get(), kTpmTunnelSeccompPath);
  minijail_change_user(j.get(), kTpmTunnelUser);
  minijail_change_group(j.get(), kTpmTunnelGroup);
  minijail_enter(j.get());

  CHECK_EQ(getuid(), tpm_tunnel_uid)
      << "tpm_tunneld was not able to drop user privilege.";
  CHECK_EQ(getgid(), tpm_tunnel_gid)
      << "tpm_tunneld was not able to drop group privilege.";
}

}  // namespace

int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  int flags = brillo::kLogToSyslog;
  if (cl->HasSwitch(switches::kLogToStderr)) {
    flags |= brillo::kLogToStderr;
  }
  brillo::InitLog(flags);

  bool noclose = cl->HasSwitch(switches::kNoCloseOnDaemonize);
  bool daemonize = !cl->HasSwitch(switches::kNoDaemonize);

  // Upstart would know tpm_tunneld is ready after tpm_tunneld daemonized.
  if (daemonize) {
    PLOG_IF(FATAL, daemon(0, noclose) == -1) << "Failed to daemonize";
  }

  trunks::csme::TpmTunnelService service;
  CHECK(service.Initialize());

  InitMinijailSandbox();

  bool success = service.Run();
  // In case any error that brings the connetion to MEI a bad state, crash the
  // program so it can recover by upstart control.
  CHECK(success) << " Error when handling requests.";

  return 0;
}
