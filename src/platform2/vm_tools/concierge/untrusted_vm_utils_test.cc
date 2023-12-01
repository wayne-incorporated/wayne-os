// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/untrusted_vm_utils.h"

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

#include "vm_tools/concierge/vm_util.h"

namespace vm_tools {
namespace concierge {

// Test fixture for actually testing the VirtualMachine functionality.
class UntrustedVMUtilsTest : public ::testing::Test {
 public:
  UntrustedVMUtilsTest() = default;
  ~UntrustedVMUtilsTest() override = default;

  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    l1tf_status_path_ = temp_dir_.GetPath().Append("l1tf");
    mds_status_path_ = temp_dir_.GetPath().Append("mds");

    // Set a kernel version that supports untrusted VMs by default. Individual
    // test cases can override this if testing for related error scenarios.
    untrusted_vm_utils_ =
        std::make_unique<UntrustedVMUtils>(l1tf_status_path_, mds_status_path_);
  }

 protected:
  // Checks if |l1tf_status| yields |expected_status| when
  // |CheckUntrustedVMMitigationStatus| is called.
  void CheckL1TFStatus(const std::string& l1tf_status,
                       UntrustedVMUtils::MitigationStatus expected_status) {
    ASSERT_EQ(base::WriteFile(l1tf_status_path_, l1tf_status.c_str(),
                              l1tf_status.size()),
              l1tf_status.size());
    EXPECT_EQ(untrusted_vm_utils_->CheckUntrustedVMMitigationStatus(),
              expected_status);
  }

  // Checks if |mds_status| yields |expected_status| when
  // |CheckUntrustedVMMitigationStatus| is called.
  void CheckMDSStatus(const std::string& mds_status,
                      UntrustedVMUtils::MitigationStatus expected_status) {
    ASSERT_EQ(base::WriteFile(mds_status_path_, mds_status.c_str(),
                              mds_status.size()),
              mds_status.size());
    EXPECT_EQ(untrusted_vm_utils_->CheckUntrustedVMMitigationStatus(),
              expected_status);
  }

  // Directory and file path used for reading test vulnerability statuses.
  base::ScopedTempDir temp_dir_;
  base::FilePath l1tf_status_path_;
  base::FilePath mds_status_path_;

  std::unique_ptr<UntrustedVMUtils> untrusted_vm_utils_;
};

// Checks mitigation status for all L1TF statuses.
TEST_F(UntrustedVMUtilsTest, CheckL1TFStatus) {
  // Set MDS status to be not vulnerable in order to check L1TF statuses below.
  std::string mds_status = "Mitigation: Clear CPU buffers; SMT disabled";
  ASSERT_EQ(
      base::WriteFile(mds_status_path_, mds_status.c_str(), mds_status.size()),
      mds_status.size());

  CheckL1TFStatus("Not affected",
                  UntrustedVMUtils::MitigationStatus::NOT_VULNERABLE);

  CheckL1TFStatus("Mitigation: PTE Inversion",
                  UntrustedVMUtils::MitigationStatus::NOT_VULNERABLE);

  CheckL1TFStatus("Some gibberish; some more gibberish",
                  UntrustedVMUtils::MitigationStatus::VULNERABLE);

  CheckL1TFStatus(
      "Mitigation: PTE Inversion; VMX: conditional cache flushes, SMT "
      "vulnerable",
      UntrustedVMUtils::MitigationStatus::VULNERABLE);

  CheckL1TFStatus(
      "Mitigation: PTE Inversion; VMX: cache flushes, SMT vulnerable",
      UntrustedVMUtils::MitigationStatus::VULNERABLE_DUE_TO_SMT_ENABLED);

  CheckL1TFStatus("Mitigation: PTE Inversion; VMX: cache flushes, SMT disabled",
                  UntrustedVMUtils::MitigationStatus::NOT_VULNERABLE);

  CheckL1TFStatus(
      "Mitigation: PTE Inversion; VMX: flush not necessary, SMT disabled",
      UntrustedVMUtils::MitigationStatus::NOT_VULNERABLE);
}

// Checks mitigation status for all MDS statuses.
TEST_F(UntrustedVMUtilsTest, CheckMDSStatus) {
  // Set L1TF status to be not vulnerable in order to check MDS statuses below.
  std::string l1tf_status =
      "Mitigation: PTE Inversion; VMX: cache flushes, SMT "
      "disabled";
  ASSERT_EQ(base::WriteFile(l1tf_status_path_, l1tf_status.c_str(),
                            l1tf_status.size()),
            l1tf_status.size());

  CheckMDSStatus("Not affected",
                 UntrustedVMUtils::MitigationStatus::NOT_VULNERABLE);

  CheckMDSStatus("Some gibberish; some more gibberish",
                 UntrustedVMUtils::MitigationStatus::VULNERABLE);

  CheckMDSStatus("Vulnerable: Clear CPU buffers attempted, no microcode",
                 UntrustedVMUtils::MitigationStatus::VULNERABLE);

  CheckMDSStatus(
      "Vulnerable: Clear CPU buffers attempted, no microcode; SMT enabled",
      UntrustedVMUtils::MitigationStatus::VULNERABLE);

  CheckMDSStatus("Vulnerable; SMT disabled",
                 UntrustedVMUtils::MitigationStatus::VULNERABLE);

  CheckMDSStatus("Mitigation: Clear CPU buffers; SMT disabled",
                 UntrustedVMUtils::MitigationStatus::NOT_VULNERABLE);

  CheckMDSStatus(
      "Mitigation: Clear CPU buffers; SMT mitigated",
      UntrustedVMUtils::MitigationStatus::VULNERABLE_DUE_TO_SMT_ENABLED);

  CheckMDSStatus(
      "Mitigation: Clear CPU buffers; SMT vulnerable",
      UntrustedVMUtils::MitigationStatus::VULNERABLE_DUE_TO_SMT_ENABLED);

  CheckMDSStatus(
      "Mitigation: Clear CPU buffers; SMT Host state unknown",
      UntrustedVMUtils::MitigationStatus::VULNERABLE_DUE_TO_SMT_ENABLED);
}

UntrustedVMUtils::UntrustedVMUtils() {}

namespace {

class FakeUntrustedVMUtils : public UntrustedVMUtils {
 public:
  explicit FakeUntrustedVMUtils(
      UntrustedVMUtils::MitigationStatus mitigation_status)
      : mitigation_status_(mitigation_status) {}
  virtual ~FakeUntrustedVMUtils() {}

  virtual MitigationStatus CheckUntrustedVMMitigationStatus() const {
    return mitigation_status_;
  }

 private:
  UntrustedVMUtils::MitigationStatus mitigation_status_;
};
}  // anonymous namespace

TEST(ServiceTest, IsUntrustedVMAllowed) {
  auto failing_untrusted_vm_utils = std::make_unique<FakeUntrustedVMUtils>(
      UntrustedVMUtils::MitigationStatus::VULNERABLE);
  auto succeeding_untrusted_vm_utils = std::make_unique<FakeUntrustedVMUtils>(
      UntrustedVMUtils::MitigationStatus::NOT_VULNERABLE);

  KernelVersionAndMajorRevision old_kernel_version{4, 4};
  KernelVersionAndMajorRevision new_kernel_version{5, 15};
  std::string reason;

  EXPECT_FALSE(succeeding_untrusted_vm_utils->IsUntrustedVMAllowed(
      old_kernel_version, &reason))
      << "Old kernel version not trusted.";
  EXPECT_FALSE(failing_untrusted_vm_utils->IsUntrustedVMAllowed(
      new_kernel_version, &reason))
      << "New enough kernel version trusted but CPU is not";
  EXPECT_TRUE(succeeding_untrusted_vm_utils->IsUntrustedVMAllowed(
      new_kernel_version, &reason))
      << "New enough kernel version trusted and CPU is great";
}

}  // namespace concierge
}  // namespace vm_tools
