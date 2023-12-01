// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUN_OCI_CONTAINER_OPTIONS_H_
#define RUN_OCI_CONTAINER_OPTIONS_H_

#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>

namespace run_oci {

using BindMount = std::pair<base::FilePath, base::FilePath>;
using BindMounts = std::vector<BindMount>;

struct ContainerOptions {
  BindMounts bind_mounts;
  std::string cgroup_parent;
  std::vector<std::string> extra_program_args;
  bool use_current_user;
  bool run_as_init;
  base::FilePath log_file;
  std::string log_tag;
  bool sigstop_when_ready;

  ContainerOptions()
      : bind_mounts(),
        cgroup_parent(),
        extra_program_args(),
        use_current_user(false),
        run_as_init(true),
        log_file(),
        log_tag(),
        sigstop_when_ready(false) {}
};

}  // namespace run_oci

#endif  // RUN_OCI_CONTAINER_OPTIONS_H_
