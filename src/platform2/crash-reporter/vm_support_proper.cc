// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/vm_support_proper.h"

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <brillo/key_value_store.h>
#include <chromeos/constants/vm_tools.h>
#include <grpcpp/grpcpp.h>

#include <sys/socket.h>
#include <utility>

#include <google/protobuf/text_format.h>
#include <linux/vm_sockets.h>

#include "crash-reporter/constants.h"
#include "crash-reporter/crash_reporter.pb.h"
#include "crash-reporter/paths.h"
#include "crash-reporter/user_collector.h"
#include "crash-reporter/util.h"

namespace {

constexpr char kLsbBoardKey[] = "CHROMEOS_RELEASE_BOARD";
constexpr char kOsNameKey[] = "PRETTY_NAME";
constexpr char kContainerOsReleasePath[] =
    "/mnt/stateful/lxd/storage-pools/default/containers/penguin/rootfs/etc/"
    "os-release";

}  // namespace

const char VmSupportProper::kFilterConfigPath[] =
    "/etc/vm_crash_filter.textproto";

class ScopedFileDeleter {
 public:
  explicit ScopedFileDeleter(base::FilePath path) : path_(path) {}
  ~ScopedFileDeleter() {
    if (!base::DeleteFile(path_)) {
      LOG(ERROR) << "Failed to delete file " << path_.value();
    }
  }

 private:
  const base::FilePath path_;
};

VmSupportProper::VmSupportProper() {
  std::string addr = base::StringPrintf("vsock:%u:%u", VMADDR_CID_HOST,
                                        vm_tools::kCrashListenerPort);

  // It's safe to use an unencrypted/authenticated channel here because the
  // whole channel exists within a single machine, and so we can rely on the
  // kernel to provide us with confidentiality and integrity. Our usage of a
  // vsock address guarantees this.
  auto channel =
      grpc::CreateChannel(std::move(addr), grpc::InsecureChannelCredentials());
  stub_ = std::make_unique<vm_tools::cicerone::CrashListener::Stub>(
      std::move(channel));
}

void VmSupportProper::AddMetadata(UserCollector* collector) {
  std::string value;
  base::FilePath lsb_path =
      base::FilePath(paths::kEtcDirectory).Append(paths::kLsbRelease);
  util::GetCachedKeyValue(lsb_path.BaseName(), kLsbBoardKey,
                          {lsb_path.DirName()}, &value);
  collector->AddCrashMetaData("board", value);

  base::FilePath os_path = base::FilePath(kContainerOsReleasePath);
  util::GetCachedKeyValue(os_path.BaseName(), kOsNameKey, {os_path.DirName()},
                          &value);
  collector->AddCrashMetaData("upload_var_vm_os_release", value);
}

void VmSupportProper::ProcessFileData(
    const base::FilePath& crash_meta_path,
    const brillo::KeyValueStore& metadata,
    const std::string& key,
    vm_tools::cicerone::CrashReport* crash_report) {
  std::string file_name;
  metadata.GetString(key, &file_name);
  base::FilePath path = crash_meta_path.DirName().Append(file_name);
  ScopedFileDeleter file_deleter(path);

  std::string* dest = nullptr;
  if (key == "payload") {
    dest = crash_report->mutable_minidump();
  } else if (key ==
             std::string(constants::kUploadTextPrefix) + "process_tree") {
    dest = crash_report->mutable_process_tree();
  }
  if (dest && !base::ReadFileToString(path, dest)) {
    LOG(ERROR) << "Failed to read file " << file_name;
  }
}

void VmSupportProper::FinishCrash(const base::FilePath& crash_meta_path) {
  // We send crash reports outside the VM via GRPC instead of storing them on
  // disk, so we delete files as we finish processing them.
  ScopedFileDeleter metadata_deleter(crash_meta_path);
  brillo::KeyValueStore metadata;
  if (!metadata.Load(crash_meta_path)) {
    LOG(ERROR) << "Failed to read metadata file";
    return;
  }

  grpc::ClientContext ctx;
  vm_tools::cicerone::CrashReport crash_report;
  vm_tools::EmptyMessage response;
  for (const auto& key : metadata.GetKeys()) {
    // These keys store file names, not raw values, which need to be read into
    // the crash report protobuf and deleted.
    if (base::StartsWith(key, constants::kUploadFilePrefix,
                         base::CompareCase::SENSITIVE) ||
        base::StartsWith(key, constants::kUploadTextPrefix,
                         base::CompareCase::SENSITIVE) ||
        key == "payload") {
      ProcessFileData(crash_meta_path, metadata, key, &crash_report);
    } else {
      std::string value;
      metadata.GetString(key, &value);
      (*crash_report.mutable_metadata())[key] = value;
    }
  }

  grpc::Status status = stub_->SendCrashReport(&ctx, crash_report, &response);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to send crash report to cicerone: "
               << status.error_code() << ", " << status.error_message();
  }
}

bool VmSupportProper::GetMetricsConsent() {
  grpc::ClientContext ctx;
  vm_tools::EmptyMessage request;
  vm_tools::cicerone::MetricsConsentResponse response;
  grpc::Status status = stub_->CheckMetricsConsent(&ctx, request, &response);
  return status.ok() && response.consent_granted();
}

bool VmSupportProper::ShouldDump(pid_t pid, std::string* out_reason) {
  return InRootProcessNamespace(pid, out_reason) &&
         PassesFilterConfig(pid, out_reason);
}

bool VmSupportProper::InRootProcessNamespace(pid_t pid,
                                             std::string* out_reason) {
  // Namespaces are accessed via the /proc/*/ns/* set of paths. The kernel
  // guarantees that if two processes share a namespace, their corresponding
  // namespace files will have the same inode number, as reported by stat.
  //
  // For now, we are only interested in processes in the root PID
  // namespace. When invoked by the kernel in response to a crash,
  // crash_reporter will be run in the root of all the namespace hierarchies, so
  // we can easily check this by comparing the crashed process PID namespace
  // with our own.
  struct stat st;

  auto namespace_path = base::StringPrintf("/proc/%d/ns/pid", pid);
  if (stat(namespace_path.c_str(), &st) < 0) {
    *out_reason = "failed to get process PID namespace";
    return false;
  }
  ino_t inode = st.st_ino;

  if (stat("/proc/self/ns/pid", &st) < 0) {
    *out_reason = "failed to get own PID namespace";
    return false;
  }
  ino_t self_inode = st.st_ino;

  if (inode != self_inode) {
    *out_reason = "ignoring - process not in root namespace";
    return false;
  }
  return true;
}

bool VmSupportProper::PassesFilterConfig(pid_t pid, std::string* out_reason) {
  // Read and apply the filter configuration.
  // If the config is missing or invalid, fail open (report all crashes) so
  // we're alerted about the issue.
  std::string config;
  if (!base::ReadFileToString(paths::Get(kFilterConfigPath), &config)) {
    *out_reason = base::StringPrintf("failed to read %s", kFilterConfigPath);
    return true;
  }
  crash::VmCrashFilters filters;
  if (!google::protobuf::TextFormat::ParseFromString(config, &filters)) {
    *out_reason = base::StringPrintf("failed to parse %s", kFilterConfigPath);
    return true;
  }

  if (filters.filters_size() > 0) {
    base::FilePath exe_symlink =
        paths::Get(base::StringPrintf("/proc/%d/exe", pid));
    base::FilePath process_path;
    if (!ReadSymbolicLink(exe_symlink, &process_path)) {
      *out_reason = base::StringPrintf("failed to read symbolic link %s",
                                       exe_symlink.value().c_str());
      return true;  // fail open
    }
    for (auto f : filters.filters()) {
      if (!f.blocked_path().empty()) {
        auto blocked_path = base::FilePath(f.blocked_path());
        if (blocked_path.IsParent(process_path) ||
            blocked_path == process_path) {
          *out_reason =
              base::StringPrintf("ignoring - processes in %s are blocked",
                                 f.blocked_path().c_str());
          return false;
        }
      }
    }
  }

  return true;
}
