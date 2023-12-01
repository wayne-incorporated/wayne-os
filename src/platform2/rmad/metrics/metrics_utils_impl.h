// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_METRICS_METRICS_UTILS_IMPL_H_
#define RMAD_METRICS_METRICS_UTILS_IMPL_H_

#include "rmad/metrics/metrics_utils.h"

#include <base/memory/scoped_refptr.h>

#include "rmad/utils/json_store.h"

namespace rmad {

class MetricsUtilsImpl : public MetricsUtils {
 public:
  explicit MetricsUtilsImpl(bool record_to_system = true);
  ~MetricsUtilsImpl() override = default;

  bool RecordAll(scoped_refptr<JsonStore> json_store) override;
  bool RecordShimlessRmaReport(scoped_refptr<JsonStore> json_store) override;
  bool RecordReplacedComponents(scoped_refptr<JsonStore> json_store) override;
  bool RecordOccurredErrors(scoped_refptr<JsonStore> json_store) override;
  bool RecordAdditionalActivities(scoped_refptr<JsonStore> json_store) override;
  bool RecordShimlessRmaStateReport(
      scoped_refptr<JsonStore> json_store) override;

 private:
  // TODO(genechang): Update it when structured metrics can be mocked.
  // Used to skip recording to the metrics system for testing.
  bool record_to_system_;
};

}  // namespace rmad

#endif  // RMAD_METRICS_METRICS_UTILS_IMPL_H_
