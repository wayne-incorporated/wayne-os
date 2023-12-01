// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>

#include <base/logging.h>

#include "arc/setup/xml/android_xml_util.h"

// Reads the specified packages.xml file and outputs info.
int main(int argc, char* argv[]) {
  logging::InitLogging(logging::LoggingSettings());
  if (argc != 2) {
    LOG(ERROR) << "Usage: " << argv[0] << " <path of packages.xml>";
    return 1;
  }
  const base::FilePath path(argv[1]);
  std::string fingerprint, sdk_version;
  if (!arc::GetFingerprintAndSdkVersionFromPackagesXml(path, &fingerprint,
                                                       &sdk_version)) {
    LOG(ERROR) << "Failed to read the specified file.";
    return 1;
  }
  std::cout << "fingerprint=" << fingerprint << std::endl;
  std::cout << "sdkVersion=" << sdk_version << std::endl;
  return 0;
}
