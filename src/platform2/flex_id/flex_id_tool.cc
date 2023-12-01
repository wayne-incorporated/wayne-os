// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "flex_id/flex_id.h"

#include <iostream>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/syslog_logging.h>

int main() {
  brillo::InitLog(brillo::kLogToSyslog);

  flex_id::FlexIdGenerator flex_id_generator(base::FilePath("/"));
  auto flex_id = flex_id_generator.GenerateAndSaveFlexId();
  if (!flex_id) {
    LOG(ERROR) << "Couldn't save flex_id. Exiting.";
    return 1;
  }
  std::cout << flex_id.value() << std::endl;
  LOG(INFO) << "flex_id_tool ran successfully. Exiting.";
  return 0;
}
