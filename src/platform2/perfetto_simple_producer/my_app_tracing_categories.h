// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PERFETTO_SIMPLE_PRODUCER_MY_APP_TRACING_CATEGORIES_H_
#define PERFETTO_SIMPLE_PRODUCER_MY_APP_TRACING_CATEGORIES_H_

#include <perfetto/perfetto.h>

PERFETTO_DEFINE_CATEGORIES(
    perfetto::Category("perfetto_simple_producer")
        .SetDescription("Events from perfetto_simple_producer"));

#endif  // PERFETTO_SIMPLE_PRODUCER_MY_APP_TRACING_CATEGORIES_H_
