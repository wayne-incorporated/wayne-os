// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fuse_lowlevel.h>
#include <stddef.h>
#include <sysexits.h>

#include <base/logging.h>
#include <base/strings/string_util.h>
#include <brillo/syslog_logging.h>

#include "smbfs/smbfs.h"
#include "smbfs/smbfs_daemon.h"

namespace {

void PrintUsage(const char* self) {
  printf(
      "usage: %s [-o options] [share_path] <mountpoint>\n\n"
      "general options:\n"
      "    -o opt,[opt...]        mount options\n"
      "    -f                     foreground operation\n"
      "    -h   --help            print help\n"
      "    -V   --version         print version\n"
      "\n"
      "File-system specific options:\n"
      "    -o uid=<n>          UID of the files owner.\n"
      "    -o gid=<n>          GID of the files owner.\n"
      "    -o mojo_id=<s>      Token used to establish Mojo IPC to Chrome.\n"
      "    -t   --test         Use a fake/test backend.\n"
      "    --log-level=<l>     Log level - 0: LOG(INFO), 1: LOG(WARNING),\n"
      "                        2: LOG(ERROR), -1: VLOG(1), -2: VLOG(2), ...\n"
      "\n",
      self);
}

#define OPT_DEF(t, p, v) \
  { t, offsetof(smbfs::Options, p), v }
const struct fuse_opt options_definition[] = {
    OPT_DEF("-f", foreground, 1),
    OPT_DEF("-h", show_help, 1),
    OPT_DEF("--help", show_help, 1),
    OPT_DEF("-V", show_version, 1),
    OPT_DEF("--version", show_version, 1),
    OPT_DEF("uid=%u", uid, 0),
    OPT_DEF("gid=%u", gid, 0),
    OPT_DEF("mojo_id=%s", mojo_id, 0),
    OPT_DEF("-t", use_test, 1),
    OPT_DEF("--test", use_test, 1),
    OPT_DEF("--log-level=%d", log_level, 0),

    FUSE_OPT_END,
};
#undef OPT_DEF

int ParseOptionsCallback(void* data,
                         const char* arg,
                         int key,
                         struct fuse_args*) {
  smbfs::Options* opts = static_cast<smbfs::Options*>(data);

  switch (key) {
    case FUSE_OPT_KEY_OPT:
      return 1;

    case FUSE_OPT_KEY_NONOPT:
      if (opts->mountpoint.empty()) {
        opts->mountpoint = arg;
      } else if (opts->share_path.empty()) {
        opts->share_path = opts->mountpoint;
        opts->mountpoint = arg;
      } else {
        LOG(ERROR) << "too many arguments: " << arg;
        return -1;
      }
      return 0;

    default:
      LOG(FATAL) << "Invalid option key: " << key;
      return -1;
  }
}

}  // namespace

int main(int argc, char** argv) {
  smbfs::Options options;
  fuse_args args = FUSE_ARGS_INIT(argc, argv);
  if (fuse_opt_parse(&args, &options, options_definition,
                     ParseOptionsCallback) == -1) {
    return EX_USAGE;
  }

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);
  logging::SetMinLogLevel(options.log_level);

  if (options.show_version) {
    printf("FUSE version %d\n", fuse_version());
    return EX_OK;
  }

  if (options.show_help) {
    PrintUsage(argv[0]);
    return EX_OK;
  }

  if (options.mountpoint.empty()) {
    LOG(ERROR) << "Unspecified mount point";
    return EX_USAGE;
  }

  if (!options.use_test && options.share_path.empty() && !options.mojo_id) {
    LOG(ERROR) << "Either --test, [share_path], or mojo_id must be specified";
    return EX_USAGE;
  } else if (!options.share_path.empty() &&
             !base::StartsWith(options.share_path, "smb://",
                               base::CompareCase::SENSITIVE)) {
    LOG(ERROR) << "Share path must begin with smb://";
    return EX_USAGE;
  }

  fuse_chan* chan = fuse_mount(options.mountpoint.c_str(), &args);
  if (!chan) {
    LOG(ERROR) << "Unable to mount FUSE mountpoint";
    return EX_SOFTWARE;
  }

  fuse_daemonize(options.foreground);

  int exit_code = EX_OK;
  {
    smbfs::SmbFsDaemon daemon(chan, options);
    exit_code = daemon.Run();
  }

  fuse_unmount(options.mountpoint.c_str(), nullptr);
  return exit_code;
}
