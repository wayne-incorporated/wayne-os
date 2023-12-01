// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HAMMERD_FUZZED_EC_IMAGE_H_
#define HAMMERD_FUZZED_EC_IMAGE_H_

#include <fuzzer/FuzzedDataProvider.h>
#include <string>

namespace hammerd {

class FuzzedEcImage {
 public:
  explicit FuzzedEcImage(FuzzedDataProvider* const fuzz)
      : fuzz_provider_(fuzz) {}

  std::string Create();

 private:
  FuzzedDataProvider* const fuzz_provider_;
};

}  // namespace hammerd
#endif  // HAMMERD_FUZZED_EC_IMAGE_H_
