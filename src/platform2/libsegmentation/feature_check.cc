// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// simple executable to encapsulation libsegmentation library to check from the
// command line if a feature is enabled. The commands are purposely limited as
// this executable is installed on all images.

#include <iostream>

#include <brillo/flag_helper.h>
#include <base/logging.h>
#include <libsegmentation/feature_management.h>

int main(int argc, char* argv[]) {
  DEFINE_string(feature_name, "", "return true when the feature is supported");
  brillo::FlagHelper::Init(argc, argv, "Query the segmentation library");

  if (FLAGS_feature_name.empty()) {
    LOG(ERROR) << "feature_name is a required argument";
    return 1;
  }

  segmentation::FeatureManagement feature_management;
  std::cout << feature_management.IsFeatureEnabled(FLAGS_feature_name)
            << std::endl;

  return 0;
}
