// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "typecd/cable.h"

#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include "fuzzer/FuzzedDataProvider.h"

#include "typecd/test_constants.h"
#include "typecd/test_utils.h"

class Environment {
 public:
  Environment() {}
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  FuzzedDataProvider data_provider(data, size);

  base::ScopedTempDir scoped_temp_dir;
  CHECK(scoped_temp_dir.CreateUniqueTempDir());
  base::FilePath temp_dir = scoped_temp_dir.GetPath();

  auto cable = std::make_unique<typecd::Cable>(
      base::FilePath(typecd::kFakePort0CableSysPath));

  // Create sysfs path for SOP' plug.
  auto sop_plug_path = temp_dir.Append(std::string("port0-plug0"));
  CHECK(base::CreateDirectory(sop_plug_path));

  // Fill up the ID VDOs with random values
  cable->SetPDRevision(data_provider.ConsumeEnum<typecd::PDRevision>());
  cable->SetIdHeaderVDO(data_provider.ConsumeIntegral<uint32_t>());
  cable->SetCertStatVDO(data_provider.ConsumeIntegral<uint32_t>());
  cable->SetProductVDO(data_provider.ConsumeIntegral<uint32_t>());
  cable->SetProductTypeVDO1(data_provider.ConsumeIntegral<uint32_t>());
  cable->SetProductTypeVDO2(data_provider.ConsumeIntegral<uint32_t>());
  cable->SetProductTypeVDO3(data_provider.ConsumeIntegral<uint32_t>());

  // Let's have an arbitrary number of alt modes between 0 and 5
  auto num_altmodes = data_provider.ConsumeIntegralInRange<uint32_t>(0, 5);
  cable->SetNumAltModes(num_altmodes);

  // Populate each altmode with random values.
  for (int i = 0; i < num_altmodes; i++) {
    auto amode_dir = base::StringPrintf("port0-plug0.%d", i);
    auto amode_path = sop_plug_path.Append(amode_dir);
    CHECK(typecd::CreateFakeAltMode(
        amode_path, data_provider.ConsumeIntegral<uint16_t>(),
        data_provider.ConsumeIntegral<uint32_t>(),
        // VDO index can go up to 6.
        data_provider.ConsumeIntegralInRange<uint32_t>(0, 6)));
    CHECK(cable->AddAltMode(amode_path));
  }

  // Watch the world crumble...
  cable->TBT3PDIdentityCheck();

  return 0;
}
