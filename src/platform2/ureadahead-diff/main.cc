// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ureadahead-diff/ureadahead_diff.h"

#include <base/logging.h>
#include <brillo/flag_helper.h>

namespace {

constexpr char help[] =
    "Calculate difference of two ureadahead packs. Output is written into "
    "three packs.\nCommon contains the same read operations from two source "
    "packs. Difference packs\ncontain unique read operations for the "
    "corresponding source pack.";
}

int main(int argc, char* argv[]) {
  DEFINE_string(source1, "", "First source pack to process");
  DEFINE_string(source2, "", "Second source pack to process");
  DEFINE_string(common, "", "Common pack output name");
  DEFINE_string(difference1, "", "Output difference for the first pack");
  DEFINE_string(difference2, "", "Output difference for the second pack");

  brillo::FlagHelper::Init(argc, argv, help);

  if (FLAGS_source1.empty() || FLAGS_source2.empty() || FLAGS_common.empty() ||
      FLAGS_difference1.empty() || FLAGS_difference2.empty()) {
    LOG(ERROR) << "Not all arguments are provided";
    return 1;
  }

  ureadahead_diff::Pack pack1;
  ureadahead_diff::Pack pack2;

  if (!pack1.Read(FLAGS_source1)) {
    LOG(ERROR) << "Failed to read " << FLAGS_source1;
    return 2;
  }

  if (!pack2.Read(FLAGS_source2)) {
    LOG(ERROR) << "Failed to read " << FLAGS_source2;
    return 3;
  }

  ureadahead_diff::Pack common;
  ureadahead_diff::Pack::CalculateDifference(&pack1, &pack2, &common);

  if (!common.Write(FLAGS_common)) {
    LOG(ERROR) << "Failed to write " << FLAGS_common;
    return 4;
  }

  if (!pack1.Write(FLAGS_difference1)) {
    LOG(ERROR) << "Failed to write " << FLAGS_difference1;
    return 5;
  }

  if (!pack2.Write(FLAGS_difference2)) {
    LOG(ERROR) << "Failed to write " << FLAGS_difference2;
    return 6;
  }

  return 0;
}
