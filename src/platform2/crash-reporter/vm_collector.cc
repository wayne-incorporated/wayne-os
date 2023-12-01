// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/vm_collector.h"

#include <memory>
#include <string>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>
#include <vm_protos/proto_bindings/vm_crash.grpc.pb.h>

#include "crash-reporter/constants.h"

// Disallow fallback directory -- VM collector is run in a sandbox without
// access to /home/chronos. (vm_collector is invoked via cicerone, with a
// minijail configured in platform2/vm_tools/init/vm_cicerone.conf)
VmCollector::VmCollector()
    : CrashCollector(
          "vm_collector", kAlwaysUseDaemonStore, kNormalCrashSendMode) {}

bool VmCollector::Collect(pid_t pid) {
  vm_tools::cicerone::CrashReport crash_report;
  google::protobuf::io::FileInputStream input(0 /* stdin */);
  if (!google::protobuf::TextFormat::Parse(&input, &crash_report)) {
    LOG(ERROR) << "Failed to parse crash report from stdin";
    return false;
  }

  base::FilePath crash_path;
  if (!GetCreatedCrashDirectoryByEuid(geteuid(), &crash_path, nullptr)) {
    LOG(ERROR) << "Failed to create or find crash directory";
    return false;
  }
  std::string basename = FormatDumpBasename("vm_crash", time(nullptr), pid);

  base::FilePath meta_path = GetCrashPath(crash_path, basename, "meta");
  base::FilePath proc_log_path = GetCrashPath(crash_path, basename, "proclog");
  base::FilePath minidump_path =
      GetCrashPath(crash_path, basename, constants::kMinidumpExtension);

  int bytes = crash_report.process_tree().size();
  if (WriteNewFile(proc_log_path, crash_report.process_tree()) < bytes) {
    LOG(ERROR) << "Failed to write out process tree";
    return false;
  }
  AddCrashMetaUploadFile("process_tree", proc_log_path.BaseName().value());

  bytes = crash_report.minidump().size();
  if (WriteNewFile(minidump_path, crash_report.minidump()) < bytes) {
    LOG(ERROR) << "Failed to write out minidump";
    return false;
  }
  AddCrashMetaData("payload", minidump_path.BaseName().value());

  for (const auto& pair : crash_report.metadata()) {
    AddCrashMetaData(pair.first, pair.second);
  }

  // We don't need the data collection code in CrashCollector::FinishCrash (that
  // was already done inside the VM), so just write out the metadata file
  // ourselves.
  WriteNewFile(meta_path, extra_metadata_);
  return true;
}

// static
CollectorInfo VmCollector::GetHandlerInfo(bool vm_crash, int32_t vm_pid) {
  auto vm_collector = std::make_shared<VmCollector>();
  return {.collector = vm_collector,
          .handlers = {{
              .should_handle = vm_crash,
              .cb = base::BindRepeating(&VmCollector::Collect, vm_collector,
                                        vm_pid),
          }}};
}
