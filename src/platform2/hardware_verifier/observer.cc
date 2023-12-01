/* Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <memory>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/logging.h>
#include <base/no_destructor.h>
#include <base/strings/strcat.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <metrics/metrics_library.h>
#include <metrics/structured_events.h>

#include <runtime_probe/proto_bindings/runtime_probe.pb.h>

#include "hardware_verifier/hardware_verifier.pb.h"
#include "hardware_verifier/observer.h"

namespace hardware_verifier {

namespace {

using StructuredComponentInfo =
    metrics::structured::events::hardware_verifier::ComponentInfo;
using StructuredHwVerificationReport =
    metrics::structured::events::hardware_verifier::HwVerificationReport;

StructuredComponentInfo CreateStructuredComponentInfo(
    const runtime_probe::Edid::Fields& device) {
  runtime_probe::Edid::Vendor vendor = runtime_probe::Edid::VENDOR_UNKNOWN;
  if (!runtime_probe::Edid::Vendor_Parse(
          base::StringPrintf("VENDOR_%s", device.vendor().c_str()), &vendor)) {
    VLOG(3) << "Unknown EDID vendor : " << device.vendor();
  }
  return StructuredComponentInfo()
      .SetComponentCategory(
          runtime_probe::ProbeRequest_SupportCategory_display_panel)
      .SetDisplayPanelVendor(vendor)
      .SetDisplayPanelProductId(device.product_id())
      .SetDisplayPanelHeight(device.height())
      .SetDisplayPanelWidth(device.width());
}

StructuredComponentInfo CreateStructuredComponentInfo(
    const runtime_probe::Storage::Fields& device) {
  auto info = StructuredComponentInfo();
  if (device.type() == "MMC") {
    info.SetComponentCategory(
            runtime_probe::ProbeRequest_SupportCategory_storage)
        .SetStorageMmcManfid(device.mmc_manfid())
        .SetStorageMmcHwrev(device.mmc_hwrev())
        .SetStorageMmcOemid(device.mmc_oemid())
        .SetStorageMmcPrv(device.mmc_prv());
  } else if (device.type() == "NVMe") {
    info.SetComponentCategory(
            runtime_probe::ProbeRequest_SupportCategory_storage)
        .SetStoragePciVendor(device.pci_vendor())
        .SetStoragePciDevice(device.pci_device())
        .SetStoragePciClass(device.pci_class());
  } else if (device.type() == "ATA") {
    // Do nothing since all fields for ATA are string type.
  }
  return info;
}

void RecordStructuredHwVerificationReport(const HwVerificationReport& report) {
  auto report_event = StructuredHwVerificationReport();
  report_event.SetIsCompliant(report.is_compliant());
  for (auto i = 0; i < report.found_component_infos_size(); i++) {
    const auto& info = report.found_component_infos(i);
    const auto& qualification_status = info.qualification_status();
    switch (info.component_category()) {
      case runtime_probe::ProbeRequest_SupportCategory_display_panel:
        report_event.SetQualificationStatusDisplayPanel(qualification_status);
        break;
      case runtime_probe::ProbeRequest_SupportCategory_storage:
        report_event.SetQualificationStatusStorage(qualification_status);
        break;
      default:
        break;
    }
  }
  report_event.Record();

  for (const auto& device : report.generic_device_info().display_panel()) {
    CreateStructuredComponentInfo(device).Record();
  }
  for (const auto& device : report.generic_device_info().storage()) {
    auto event = CreateStructuredComponentInfo(device);
    if (!event.metrics().empty())
      event.Record();
  }
}

}  // namespace

Observer* Observer::GetInstance() {
  static base::NoDestructor<Observer> instance;
  return instance.get();
}

void Observer::StartTimer(const std::string& timer_name) {
  VLOG(1) << "Start timer |" << timer_name << "|";
  timers_[timer_name] = base::TimeTicks::Now();
}

void Observer::StopTimer(const std::string& timer_name) {
  auto it = timers_.find(timer_name);

  DCHECK(it != timers_.end());

  auto start = it->second;
  timers_.erase(it);
  auto now = base::TimeTicks::Now();
  auto duration_ms = (now - start).InMilliseconds();

  VLOG(1) << "Stop timer |" << timer_name << "|, time elapsed: " << duration_ms
          << "ms.\n";

  if (metrics_) {
    metrics_->SendToUMA(timer_name, duration_ms, kTimerMinMs_, kTimerMaxMs_,
                        kTimerBuckets_);
  }
}

void Observer::SetMetricsLibrary(
    std::unique_ptr<MetricsLibraryInterface> metrics) {
  metrics_ = std::move(metrics);
}

void Observer::RecordHwVerificationReport(const HwVerificationReport& report) {
  {
    auto key = base::StrCat({kMetricVerifierReportPrefix, "IsCompliant"});
    LOG(INFO) << key << ": " << report.is_compliant();
    if (metrics_) {
      metrics_->SendBoolToUMA(key, report.is_compliant());
    }
  }

  for (auto i = 0; i < report.found_component_infos_size(); i++) {
    const auto& info = report.found_component_infos(i);
    const auto& name = runtime_probe::ProbeRequest_SupportCategory_Name(
        info.component_category());
    const auto& qualification_status = info.qualification_status();

    const std::string uma_key =
        base::StrCat({kMetricVerifierReportPrefix, name});

    LOG(INFO) << uma_key << ": "
              << QualificationStatus_Name(qualification_status);
    if (metrics_) {
      metrics_->SendEnumToUMA(uma_key, qualification_status,
                              QualificationStatus_ARRAYSIZE);
    }
  }
  RecordStructuredHwVerificationReport(report);
}

}  // namespace hardware_verifier
