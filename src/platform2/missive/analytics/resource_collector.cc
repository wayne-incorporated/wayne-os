// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/analytics/resource_collector.h"

#include <base/sequence_checker.h>
#include <base/time/time.h>
#include <base/timer/timer.h>

namespace reporting::analytics {

ResourceCollector::~ResourceCollector() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(!timer_.IsRunning())
      << "A child of ResourceCollector must stop the timer before "
         "ResourceCollector::~ResourceCollector() is called to prevent the "
         "timer from accessing destructed members of the child. This can be "
         "done by calling ResourceCollector::StopTimer(), usually in the "
         "child's destructor.";
}

ResourceCollector::ResourceCollector(base::TimeDelta interval) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  timer_.Start(FROM_HERE, interval, this, &ResourceCollector::CollectWrapper);
}

void ResourceCollector::CollectWrapper() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  Collect();
}

void ResourceCollector::StopTimer() {
  timer_.Stop();
}

}  // namespace reporting::analytics
