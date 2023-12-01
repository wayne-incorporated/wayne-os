// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The ARC Java collector reports Java crashes that happen in the ARC++
// container and ARC VM.

#ifndef CRASH_REPORTER_ARC_JAVA_COLLECTOR_H_
#define CRASH_REPORTER_ARC_JAVA_COLLECTOR_H_

#include <sstream>
#include <string>
#include <unordered_map>

#include <base/time/time.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "crash-reporter/arc_util.h"
#include "crash-reporter/crash_collector.h"

// Collector for Java crashes in the ARC++ container and ARC VM.
class ArcJavaCollector : public CrashCollector {
 public:
  ArcJavaCollector();
  ArcJavaCollector(const ArcJavaCollector&) = delete;
  ArcJavaCollector& operator=(const ArcJavaCollector&) = delete;

  ~ArcJavaCollector() override = default;

  // Reads a Java crash log for the given |crash_type| from standard input, or
  // closes the stream if reporting is disabled.
  // |uptime| can be zero if the value is unknown.
  bool HandleCrash(const std::string& crash_type,
                   const arc_util::BuildProperty& build_property,
                   base::TimeDelta uptime);

  static CollectorInfo GetHandlerInfo(
      const std::string& arc_java_crash,
      const arc_util::BuildProperty& build_property,
      int64_t uptime_millis);

 private:
  FRIEND_TEST(ArcJavaCollectorTest, AddArcMetaData);
  FRIEND_TEST(ArcJavaCollectorTest, CreateReportForJavaCrash);

  // CrashCollector overrides.
  std::string GetProductVersion() const override;

  // Adds the |process|, |crash_type| and Chrome version as metadata.
  // |uptime| can be zero if the value is unknown.
  void AddArcMetaData(const std::string& process,
                      const std::string& crash_type,
                      base::TimeDelta uptime);

  using CrashLogHeaderMap = std::unordered_map<std::string, std::string>;

  bool CreateReportForJavaCrash(const std::string& crash_type,
                                const arc_util::BuildProperty& build_property,
                                const CrashLogHeaderMap& map,
                                const std::string& exception_info,
                                const std::string& log,
                                base::TimeDelta uptime,
                                bool* out_of_capacity);
};

#endif  // CRASH_REPORTER_ARC_JAVA_COLLECTOR_H_
