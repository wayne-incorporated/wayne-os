// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HAMMERD_UMA_METRIC_NAMES_H_
#define HAMMERD_UMA_METRIC_NAMES_H_

namespace hammerd {

#define DETACHABLE_BASE_PREFIX "Platform.DetachableBase."

const char kMetricROUpdateResult[] = DETACHABLE_BASE_PREFIX "ROUpdateResult";
const char kMetricRWUpdateResult[] = DETACHABLE_BASE_PREFIX "RWUpdateResult";
const char kMetricPairResult[] = DETACHABLE_BASE_PREFIX "PairResult";
const char kMetricPendingRWUpdate[] = DETACHABLE_BASE_PREFIX "PendingRWUpdate";

// Values in the enums below are persisted to logs. Entries should not
// be renumbered and numeric values should never be reused.

enum class ROUpdateResult {
  kSucceeded = 1,
  kTransferFailed = 2,

  kCount,
};

enum class RWUpdateResult {
  kSucceeded = 1,
  kTransferFailed = 2,
  kInvalidKey = 3,
  kRollbackDisallowed = 4,

  kCount,
};

enum class PairResult {
  kUnknownError = 0,
  kChallengePassed = 1,
  kChallengeFailed = 2,
  kNeedInjectEntropy = 3,

  kCount,
};

enum class PendingRWUpdate {
  kCommunicationError = 0,
  kNoUpdate = 1,
  kCriticalUpdate = 2,
  kNonCriticalUpdate = 3,

  kCount,
};

}  // namespace hammerd
#endif  // HAMMERD_UMA_METRIC_NAMES_H_
