// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/untrusted_vm_utils.h"

#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_split.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/message.h>
#include <dbus/scoped_dbus_error.h>
#include <vboot/crossystem.h>

#include "vm_tools/concierge/vm_util.h"

namespace vm_tools {
namespace concierge {

namespace {

// Returns the L1TF mitigation status of the host it's run on.
UntrustedVMUtils::MitigationStatus GetL1TFMitigationStatus(
    const base::FilePath& l1tf_status_path) {
  std::string l1tf_status;
  if (!base::ReadFileToString(l1tf_status_path, &l1tf_status)) {
    LOG(ERROR) << "Failed to read L1TF status";
    return UntrustedVMUtils::MitigationStatus::VULNERABLE;
  }

  LOG(INFO) << "l1tf status: " << l1tf_status;

  std::vector<base::StringPiece> l1tf_statuses = base::SplitStringPiece(
      l1tf_status, ",;", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  const size_t num_statuses = l1tf_statuses.size();
  // The sysfs file should always return up to 3 statuses and no more.
  if (num_statuses > 3) {
    LOG(ERROR) << "Bad l1tf state";
    return UntrustedVMUtils::MitigationStatus::VULNERABLE;
  }

  const base::StringPiece& processor_mitigation_status = l1tf_statuses[0];
  if (processor_mitigation_status == "Not affected")
    return UntrustedVMUtils::MitigationStatus::NOT_VULNERABLE;
  if (processor_mitigation_status != "Mitigation: PTE Inversion")
    return UntrustedVMUtils::MitigationStatus::VULNERABLE;

  if (num_statuses >= 2) {
    const base::StringPiece& vmx_mitigation_status = l1tf_statuses[1];
    if ((vmx_mitigation_status != "VMX: cache flushes") &&
        (vmx_mitigation_status != "VMX: flush not necessary")) {
      return UntrustedVMUtils::MitigationStatus::VULNERABLE;
    }
  }

  // Only a maximum of 3 statuses are expected.
  if (num_statuses == 3) {
    const base::StringPiece& smt_mitigation_status = l1tf_statuses[2];
    if (smt_mitigation_status == "SMT vulnerable")
      return UntrustedVMUtils::MitigationStatus::VULNERABLE_DUE_TO_SMT_ENABLED;
    if (smt_mitigation_status != "SMT disabled")
      return UntrustedVMUtils::MitigationStatus::VULNERABLE;
  }

  return UntrustedVMUtils::MitigationStatus::NOT_VULNERABLE;
}

// Returns the MDS mitigation status of the host it's run on.
UntrustedVMUtils::MitigationStatus GetMDSMitigationStatus(
    const base::FilePath& mds_status_path) {
  std::string mds_status;
  if (!base::ReadFileToString(mds_status_path, &mds_status)) {
    LOG(ERROR) << "Failed to read MDS status";
    return UntrustedVMUtils::MitigationStatus::VULNERABLE;
  }

  LOG(INFO) << "mds status: " << mds_status;

  std::vector<base::StringPiece> mds_statuses = base::SplitStringPiece(
      mds_status, ";", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  const size_t num_statuses = mds_statuses.size();
  // The sysfs file should always return up to 2 statuses and no more.
  if (num_statuses > 2) {
    LOG(ERROR) << "Bad mds state";
    return UntrustedVMUtils::MitigationStatus::VULNERABLE;
  }

  const base::StringPiece& processor_mitigation_status = mds_statuses[0];
  if (processor_mitigation_status == "Not affected")
    return UntrustedVMUtils::MitigationStatus::NOT_VULNERABLE;
  if (processor_mitigation_status.find("Vulnerable") != base::StringPiece::npos)
    return UntrustedVMUtils::MitigationStatus::VULNERABLE;
  if (processor_mitigation_status != "Mitigation: Clear CPU buffers")
    return UntrustedVMUtils::MitigationStatus::VULNERABLE;

  // Only a maximum of 2 statuses are expected.
  if (num_statuses == 2) {
    const base::StringPiece& smt_mitigation_status = mds_statuses[1];
    if (smt_mitigation_status == "SMT vulnerable")
      return UntrustedVMUtils::MitigationStatus::VULNERABLE_DUE_TO_SMT_ENABLED;
    if (smt_mitigation_status == "SMT mitigated")
      return UntrustedVMUtils::MitigationStatus::VULNERABLE_DUE_TO_SMT_ENABLED;
    if (smt_mitigation_status == "SMT Host state unknown")
      return UntrustedVMUtils::MitigationStatus::VULNERABLE_DUE_TO_SMT_ENABLED;
    if (smt_mitigation_status != "SMT disabled")
      return UntrustedVMUtils::MitigationStatus::VULNERABLE;
  }

  return UntrustedVMUtils::MitigationStatus::NOT_VULNERABLE;
}

bool IsDevModeEnabled() {
  return VbGetSystemPropertyInt("cros_debug") == 1;
}

}  // namespace

UntrustedVMUtils::UntrustedVMUtils(const base::FilePath& l1tf_status_path,
                                   const base::FilePath& mds_status_path)
    : l1tf_status_path_(l1tf_status_path), mds_status_path_(mds_status_path) {
  DCHECK(!l1tf_status_path.empty());
  DCHECK(!mds_status_path.empty());
}

UntrustedVMUtils::MitigationStatus
UntrustedVMUtils::CheckUntrustedVMMitigationStatus() const {
  MitigationStatus status = GetL1TFMitigationStatus(l1tf_status_path_);
  if (status != MitigationStatus::NOT_VULNERABLE)
    return status;

  return GetMDSMitigationStatus(mds_status_path_);
}

bool UntrustedVMUtils::IsUntrustedVMAllowed(
    KernelVersionAndMajorRevision host_kernel_version,
    std::string* reason) const {
  DCHECK(reason);

  // For host >= |kMinKernelVersionForUntrustedAndNestedVM| untrusted VMs are
  // always allowed. But the host still needs to be checked for vulnerabilities,
  // even in developer mode. This is done because it'd be a huge error to not
  // have required security patches on these kernels regardless of dev or
  // production mode.
  if (host_kernel_version >= kMinKernelVersionForUntrustedAndNestedVM) {
    // Check if l1tf and mds mitigations are present on the host.
    switch (CheckUntrustedVMMitigationStatus()) {
      // If the host kernel version isn't supported or the host doesn't have
      // l1tf and mds mitigations then fail to start an untrusted VM.
      case UntrustedVMUtils::MitigationStatus::VULNERABLE:
        *reason = "Host vulnerable against untrusted VM";
        return false;

      // At this point SMT should not be a security issue. As
      // |kMinKernelVersionForUntrustedAndNestedVM| has security patches to
      // make nested VMs co-exist securely with SMT.
      case UntrustedVMUtils::MitigationStatus::VULNERABLE_DUE_TO_SMT_ENABLED:
      case UntrustedVMUtils::MitigationStatus::NOT_VULNERABLE:
        return true;
    }
  }

  // On lower kernel versions in developer mode, allow untrusted VMs without
  // any restrictions on the host having security mitigations.
  if (IsDevModeEnabled()) {
    return true;
  }

  // Lower kernel version are deemed insecure to handle untrusted VMs.
  std::stringstream ss;
  ss << "Untrusted VMs are not allowed: "
     << "the host kernel version (" << host_kernel_version.first << "."
     << host_kernel_version.second << ") must be newer than or equal to "
     << kMinKernelVersionForUntrustedAndNestedVM.first << "."
     << kMinKernelVersionForUntrustedAndNestedVM.second
     << ", or the device must be in the developer mode";
  *reason = ss.str();
  return false;
}

}  // namespace concierge
}  // namespace vm_tools
