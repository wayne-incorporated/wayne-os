// Copyright 2010 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_METRICS_LIBRARY_MOCK_H_
#define METRICS_METRICS_LIBRARY_MOCK_H_

#include <string>

#include "metrics/metrics_library.h"

#include <gmock/gmock.h>

class MetricsLibraryMock : public MetricsLibraryInterface {
 public:
  // TODO(chromium:940343): Remove this function.
  MOCK_METHOD(void, Init, (), (override));
  MOCK_METHOD(bool,
              SendToUMA,
              (const std::string&, int, int, int, int),
              (override));
  MOCK_METHOD(bool, SendEnumToUMA, (const std::string&, int, int), (override));
  MOCK_METHOD(bool,
              SendRepeatedEnumToUMA,
              (const std::string&, int, int, int),
              (override));
  MOCK_METHOD(bool,
              SendLinearToUMA,
              (const std::string&, int, int),
              (override));
  MOCK_METHOD(bool, SendPercentageToUMA, (const std::string&, int), (override));
  MOCK_METHOD(bool, SendBoolToUMA, (const std::string&, bool), (override));
  MOCK_METHOD(bool, SendSparseToUMA, (const std::string&, int), (override));
  MOCK_METHOD(bool, SendUserActionToUMA, (const std::string&), (override));
  MOCK_METHOD(bool, SendCrashToUMA, (const char* crash_kind), (override));
  MOCK_METHOD(bool, SendCrosEventToUMA, (const std::string& event), (override));
  MOCK_METHOD(void, SetOutputFile, (const std::string&), (override));
#if USE_METRICS_UPLOADER
  MOCK_METHOD(bool,
              SendRepeatedToUMA,
              (const std::string&, int, int, int, int, int),
              (override));
#endif
  bool AreMetricsEnabled() override { return metrics_enabled_; }
  bool IsAppSyncEnabled() override { return appsync_enabled_; }
  bool IsGuestMode() override { return guest_mode_; }

  void set_metrics_enabled(bool value) { metrics_enabled_ = value; }
  void set_appsync_enabled(bool value) { appsync_enabled_ = value; }
  void set_guest_mode(bool value) { guest_mode_ = value; }

 private:
  bool metrics_enabled_ = true;
  bool appsync_enabled_ = true;
  bool guest_mode_ = false;
};

#endif  // METRICS_METRICS_LIBRARY_MOCK_H_
