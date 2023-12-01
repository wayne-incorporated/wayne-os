// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The ARC++ C++ collector reports C++ crashes that happen in the ARC++
// container. If a process crashes (not just exits abnormally), the kernel
// invokes crash_reporter via /proc/sys/kernel/core_pattern, which in turn calls
// the ARC++ C++ collector if the crash happened in that container namespace.

#ifndef CRASH_REPORTER_ARCPP_CXX_COLLECTOR_H_
#define CRASH_REPORTER_ARCPP_CXX_COLLECTOR_H_

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/time/time.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "crash-reporter/arc_util.h"
#include "crash-reporter/user_collector_base.h"

constexpr char kBoardProperty[] = "ro.product.board";
constexpr char kCpuAbiProperty[] = "ro.product.cpu.abi";
constexpr char kDevicePropertyP[] = "ro.product.device";
constexpr char kDevicePropertyR[] = "ro.product.system.device";
constexpr char kFingerprintProperty[] = "ro.build.fingerprint";

bool GetArcProperties(const base::FilePath& build_prop_path,
                      arc_util::BuildProperty* build_property);

// Collector for system crashes in the ARC container.
class ArcppCxxCollector : public UserCollectorBase {
 public:
  struct Context {
    virtual ~Context() = default;

    virtual bool GetArcPid(pid_t* pid) const = 0;
    virtual bool GetPidNamespace(pid_t pid, std::string* ns) const = 0;
    virtual bool GetExecBaseNameAndDirectory(
        pid_t pid, std::string* exec, base::FilePath* exec_directory) const = 0;
    virtual bool GetCommand(pid_t pid, std::string* command) const = 0;
    virtual bool ReadAuxvForProcess(pid_t pid, std::string* contents) const = 0;
  };

  using ContextPtr = std::unique_ptr<Context>;

  ArcppCxxCollector();
  explicit ArcppCxxCollector(ContextPtr context);
  ArcppCxxCollector(const ArcppCxxCollector&) = delete;
  ArcppCxxCollector& operator=(const ArcppCxxCollector&) = delete;

  ~ArcppCxxCollector() override = default;

  const Context& context() const { return *context_; }

  // Returns false if the query failed, which may happen during teardown of the
  // ARC container. Since the behavior of user collectors is determined by
  // IsArcProcess, there is a (rare) race condition for crashes that occur
  // during teardown.
  bool IsArcProcess(pid_t pid) const;

  static bool IsArcRunning();
  static bool GetArcPid(pid_t* arc_pid);

 private:
  FRIEND_TEST(ArcppCxxCollectorTest, CorrectlyDetectBitness);
  FRIEND_TEST(ArcppCxxCollectorTest, GetExecBaseNameForUserCrash);
  FRIEND_TEST(ArcppCxxCollectorTest, GetExecBaseNameForArcCrash);
  FRIEND_TEST(ArcppCxxCollectorTest, ShouldDump);

  // Shift for UID namespace in ARC.
  static constexpr uid_t kUserShift = 655360;

  // Upper bound for system UIDs in ARC.
  static constexpr uid_t kSystemUserEnd = kUserShift + 10000;

  class ArcContext : public Context {
   public:
    explicit ArcContext(ArcppCxxCollector* collector) : collector_(collector) {}

    bool GetArcPid(pid_t* pid) const override;
    bool GetPidNamespace(pid_t pid, std::string* ns) const override;
    bool GetExecBaseNameAndDirectory(
        pid_t pid,
        std::string* exec,
        base::FilePath* exec_directory) const override;
    bool GetCommand(pid_t pid, std::string* command) const override;
    bool ReadAuxvForProcess(pid_t pid, std::string* contents) const override;

   private:
    ArcppCxxCollector* const collector_;
  };

  // CrashCollector overrides.
  std::string GetProductVersion() const override;
  bool GetExecutableBaseNameAndDirectoryFromPid(
      pid_t pid,
      std::string* base_name,
      base::FilePath* exec_directory) override;

  // UserCollectorBase overrides.
  bool ShouldDump(pid_t pid,
                  uid_t uid,
                  const std::string& exec,
                  std::string* reason) override;

  ErrorType ConvertCoreToMinidump(pid_t pid,
                                  const base::FilePath& container_dir,
                                  const base::FilePath& core_path,
                                  const base::FilePath& minidump_path) override;

  // Adds the |process| and other ARC-related info as metadata.
  void AddArcMetaData(const std::string& process);

  // Returns whether the process identified by |pid| is 32- or 64-bit.
  ErrorType Is64BitProcess(int pid, bool* is_64_bit) const;

  const ContextPtr context_;
};

#endif  // CRASH_REPORTER_ARCPP_CXX_COLLECTOR_H_
