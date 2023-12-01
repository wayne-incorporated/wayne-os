// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hermes/smds.h"

#include <memory>

namespace hermes {

std::unique_ptr<lpa::smds::SmdsClient> SmdsFactory::NewSmdsClient() {
  return std::make_unique<Smds>();
}

}  // namespace hermes
