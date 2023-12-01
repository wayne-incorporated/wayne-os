// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SECANOMALYD_DAEMON_H_
#define SECANOMALYD_DAEMON_H_

#include <cstddef>
#include <map>
#include <memory>
#include <set>
#include <string>

#include <base/files/file_path.h>

#include <brillo/daemons/dbus_daemon.h>

#include "secanomalyd/audit_log_reader.h"
#include "secanomalyd/mount_entry.h"
#include "secanomalyd/system_context.h"

namespace secanomalyd {

class Daemon : public brillo::DBusDaemon {
 public:
  explicit Daemon(bool generate_reports = false, bool dev = false)
      : brillo::DBusDaemon(), generate_reports_{generate_reports}, dev_{dev} {}
  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;

 protected:
  int OnInit() override;
  int OnEventLoopStarted() override;

 private:
  void InitAuditLogReader();

  // This is called at set intervals, dictated by |kScanInterval| and invokes
  // all the anomaly detection tasks one by one.
  void ScanForAnomalies();

  // Anomaly detection tasks below check for specific anomalous conditions and
  // invoke the appropriate reporting function if an anomaly is detected.
  void DoWXMountScan();
  void DoAuditLogScan();

  // Discovered anomalies and other security related metrics are reported to UMA
  // at set intervals, dictated by |kUmaReportInterval|.
  void ReportUmaMetrics();

  // UMA Reporting tasks are invoked by |ReportUmaMetrics()|.
  void EmitWXMountCountUma();
  void EmitMemfdExecProcCountUma();
  void EmitLandlockStatusUma();

  // Reporting tasks have rate limiting criteria built into them for uploading
  // crash reports.
  void DoAnomalousSystemReporting();

  // Used to keep track of whether this daemon has attempted to send a crash
  // report for a W+X mount observation throughout its lifetime.
  // Only one crash report upload is attempted for an anomaly of type W+X mount
  // during the lifetime of the daemon.
  bool has_attempted_wx_mount_report_ = false;

  // Used to track whether an UMA metric was emitted for the memfd execution
  // baseline metric, as we only need one emission of the metric.
  bool has_emitted_memfd_baseline_uma_ = false;

  // Landlock status should only be reported once per execution of secanomalyd,
  // as a change in the Landlock state would require a system reboot.
  bool has_emitted_landlock_status_uma_ = false;

  bool generate_reports_ = false;
  bool dev_ = false;

  std::unique_ptr<SessionManagerProxy> session_manager_proxy_;

  std::unique_ptr<SystemContext> system_context_;

  MountEntryMap wx_mounts_;

  std::set<base::FilePath> executables_attempting_memfd_exec_;

  // Used for reading and parsing the audit log file.
  std::unique_ptr<AuditLogReader> audit_log_reader_;
};

}  // namespace secanomalyd

#endif  // SECANOMALYD_DAEMON_H_
