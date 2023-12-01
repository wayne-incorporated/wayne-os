// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "typecd/port.h"

#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>

#include "fuzzer/FuzzedDataProvider.h"

class Environment {
 public:
  Environment() { logging::SetMinLogLevel(logging::LOGGING_ERROR); }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  FuzzedDataProvider data_provider(data, size);

  base::ScopedTempDir scoped_temp_dir;
  CHECK(scoped_temp_dir.CreateUniqueTempDir());
  auto temp_dir = scoped_temp_dir.GetPath();

  // Fake sysfs director for the port.
  auto port_path = temp_dir.Append("port0");
  CHECK(base::CreateDirectory(port_path));

  // Add data role and power role sysfs.
  auto val = data_provider.ConsumeRandomLengthString(20);
  CHECK_GE(
      base::WriteFile(port_path.Append("data_role"), val.c_str(), val.length()),
      0);
  val = data_provider.ConsumeRandomLengthString(20);
  CHECK_GE(base::WriteFile(port_path.Append("power_role"), val.c_str(),
                           val.length()),
           0);

  typecd::Port port(base::FilePath(port_path), 0);

  return 0;
}
