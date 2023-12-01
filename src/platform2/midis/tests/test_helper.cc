// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "midis/tests/test_helper.h"

#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>

namespace midis {

base::FilePath CreateFakeTempSubDir(base::FilePath temp_path,
                                    const std::string& subdir_path) {
  // Create the fake dev node file to which we write.
  temp_path = temp_path.Append(subdir_path);
  base::File::Error error;

  if (!CreateDirectoryAndGetError(temp_path, &error)) {
    LOG(ERROR) << "Failed to create dir: " << temp_path.value() << ": "
               << base::File::ErrorToString(error);
    return base::FilePath();
  }

  return temp_path;
}

base::FilePath CreateDevNodeFileName(base::FilePath dev_path_base,
                                     uint32_t sys_num,
                                     uint32_t dev_num) {
  // Create a fake devnode file
  std::string node_name = base::StringPrintf("midiC%uD%u", sys_num, dev_num);
  return dev_path_base.Append(node_name);
}

}  // namespace midis
