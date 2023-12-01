// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HPS_DAEMON_FILTERS_FILTER_FACTORY_H_
#define HPS_DAEMON_FILTERS_FILTER_FACTORY_H_

#include <memory>

#include "hps/daemon/filters/filter.h"
#include "hps/daemon/filters/status_callback.h"
#include "hps/proto_bindings/hps_service.pb.h"

namespace hps {

std::unique_ptr<Filter> CreateFilter(const hps::FeatureConfig& config,
                                     StatusCallback signal);

}  // namespace hps

#endif  // HPS_DAEMON_FILTERS_FILTER_FACTORY_H_
