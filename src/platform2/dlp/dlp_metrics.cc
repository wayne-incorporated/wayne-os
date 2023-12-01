// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dlp/dlp_metrics.h"

namespace dlp {

DlpMetrics::DlpMetrics() : metrics_lib_(std::make_unique<MetricsLibrary>()) {}
DlpMetrics::~DlpMetrics() = default;

void DlpMetrics::SendBooleanHistogram(const std::string& name,
                                      bool value) const {
  metrics_lib_->SendBoolToUMA(name, value);
}

void DlpMetrics::SendInitError(InitError error) const {
  metrics_lib_->SendEnumToUMA(kDlpInitErrorHistogram, error);
}

void DlpMetrics::SendFanotifyError(FanotifyError error) const {
  metrics_lib_->SendEnumToUMA(kDlpFanotifyErrorHistogram, error);
}

void DlpMetrics::SendDatabaseError(DatabaseError error) const {
  metrics_lib_->SendEnumToUMA(kDlpFileDatabaseErrorHistogram, error);
}

void DlpMetrics::SendAdaptorError(AdaptorError error) const {
  metrics_lib_->SendEnumToUMA(kDlpAdaptorErrorHistogram, error);
}

};  // namespace dlp
