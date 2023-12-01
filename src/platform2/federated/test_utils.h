// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FEDERATED_TEST_UTILS_H_
#define FEDERATED_TEST_UTILS_H_

#include <base/time/time.h>

#include "federated/mojom/example.mojom.h"

namespace federated {

// Creates a mojom::Example Mojo struct with various nonempty fields.
chromeos::federated::mojom::ExamplePtr CreateExamplePtr();

// Returns the time struct representing s seconds after the Unix epoch.
base::Time SecondsAfterEpoch(int64_t s);

}  // namespace federated

#endif  // FEDERATED_TEST_UTILS_H_
