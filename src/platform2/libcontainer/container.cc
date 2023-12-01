// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libcontainer/container.h"

#include <base/check.h>
#include <base/logging.h>

namespace libcontainer {

Container::Container(base::StringPiece name, const base::FilePath& rundir)
    : container_(container_new(name.data(), rundir.value().c_str())) {
  // container_new() allocates using std::nothrow, so we need to explicitly
  // call abort(2) when allocation fails.
  CHECK(container_);
}

Container::~Container() {
  container_destroy(container_);
}

}  // namespace libcontainer
