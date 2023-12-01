// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_COMMON_TRACING_H_
#define POWER_MANAGER_COMMON_TRACING_H_

#include <perfetto/perfetto.h>

PERFETTO_DEFINE_CATEGORIES_IN_NAMESPACE(
    power_manager,
    perfetto::Category("power").SetDescription(
        "General events from the power manager daemon"));

namespace power_manager {

// One time initialization to connect to the Perfetto tracing daemon and
// register our trace categories.
void InitTracing();

}  // namespace power_manager

#endif  // POWER_MANAGER_COMMON_TRACING_H_
