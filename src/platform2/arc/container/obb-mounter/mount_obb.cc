// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/container/obb-mounter/mount_obb_fuse_main.h"

#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <brillo/syslog_logging.h>

int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);

  auto program = base::CommandLine::ForCurrentProcess()->GetProgram();
  auto args = base::CommandLine::ForCurrentProcess()->GetArgs();
  if (args.size() != 4) {
    LOG(ERROR) << "Usage: " << program.value()
               << " obb_filename mount_path owner_uid owner_gid";
    return 1;
  }
  const std::string& file_system_name = program.value();
  const std::string& obb_filename = args[0];
  const std::string& mount_path = args[1];
  const std::string& owner_uid = args[2];
  const std::string& owner_gid = args[3];

  return mount_obb_fuse_main(file_system_name, obb_filename, mount_path,
                             owner_uid, owner_gid);
}
