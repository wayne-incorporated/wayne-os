// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/executor/executor.h"

#include <bits/types/siginfo_t.h>
#include <inttypes.h>
#include <linux/capability.h>
#include <sys/capability.h>
#include <sys/types.h>
#include <unistd.h>

#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <base/task/task_traits.h>
#include <base/task/thread_pool.h>
#include <base/time/time.h>
#include <brillo/process/process.h>
#include <dlcservice/proto_bindings/dlcservice.pb.h>
// NOLINTNEXTLINE(build/include_alpha) dbus-proxies.h needs dlcservice.pb.h
#include <dlcservice/dbus-proxies.h>
#include <mojo/public/cpp/bindings/callback_helpers.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <re2/re2.h>

#include "diagnostics/base/file_utils.h"
#include "diagnostics/cros_healthd/delegate/constants.h"
#include "diagnostics/cros_healthd/executor/utils/delegate_process.h"
#include "diagnostics/cros_healthd/executor/utils/dlc_manager.h"
#include "diagnostics/cros_healthd/executor/utils/file.h"
#include "diagnostics/cros_healthd/executor/utils/process_control.h"
#include "diagnostics/cros_healthd/executor/utils/sandboxed_process.h"
#include "diagnostics/cros_healthd/mojom/executor.mojom.h"
#include "diagnostics/cros_healthd/routines/memory_and_cpu/constants.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

namespace path {
namespace {

constexpr char kEctoolBinary[] = "/usr/sbin/ectool";
constexpr char kIwBinary[] = "/usr/sbin/iw";
constexpr char kMemtesterBinary[] = "/usr/sbin/memtester";
constexpr char kHciconfigBinary[] = "/usr/bin/hciconfig";
constexpr char kCrosEcDevice[] = "/dev/cros_ec";
constexpr char kStressAppTestBinary[] = "/usr/bin/stressapptest";
constexpr char kFioCacheFile[] = "/var/cache/diagnostics/fio-test-file";
constexpr char kDrmDevice[] = "/dev/dri";
constexpr char kCrashSenderBinary[] = "/sbin/crash_sender";
constexpr char kInputDevice[] = "/dev/input";

}  // namespace
}  // namespace path

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

namespace seccomp_file {

// SECCOMP policy for evdev related routines.
constexpr char kEvdev[] = "evdev-seccomp.policy";
// SECCOMP policy for ectool pwmgetfanrpm.
constexpr char kFanSpeed[] = "ectool_pwmgetfanrpm-seccomp.policy";
// SECCOMP policy for fingerprint related routines.
constexpr char kFingerprint[] = "fingerprint-seccomp.policy";
// SECCOMP policy for hciconfig.
constexpr char kHciconfig[] = "hciconfig-seccomp.policy";
// SECCOMP policy for IW related routines.
constexpr char kIw[] = "iw-seccomp.policy";
// SECCOMP policy for LED related routines.
constexpr char kLed[] = "ec_led-seccomp.policy";
// SECCOMP policy for obtaining lid angle from EC.
constexpr char kLidAngle[] = "ec_lid_angle-seccomp.policy";
// SECCOMP policy for memtester.
constexpr char kMemtester[] = "memtester-seccomp.policy";
// SECCOMP policy for prime search.
constexpr char kPrimeSearch[] = "prime_search-seccomp.policy";
// SECCOMP policy for fetchers which only read and parse some files.
constexpr char kReadOnlyFetchers[] = "readonly-fetchers-seccomp.policy";
// SECCOMP policy for psr related routines.
constexpr char kPsr[] = "psr-seccomp.policy";
// SECCOMP policy for stressapptest.
constexpr char kStressAppTest[] = "stressapptest-seccomp.policy";
// SECCOMP policy for fio.
constexpr char kFio[] = "fio-seccomp.policy";
// SECCOMP policy for rm.
constexpr char kRm[] = "healthd_rm-seccomp.policy";
// SECCOMP policy for df.
constexpr char kFreeDiskSpace[] = "healthd_free_disk_space-seccomp.policy";
// SECCOMP policy for drm.
constexpr char kDrm[] = "drm-seccomp.policy";

}  // namespace seccomp_file

namespace user {

// The user and group for accessing fingerprint.
constexpr char kFingerprint[] = "healthd_fp";
// The user and group for accessing Evdev.
constexpr char kEvdev[] = "healthd_evdev";
// The user and group for accessing EC.
constexpr char kEc[] = "healthd_ec";
// The user and group for accessing PSR.
constexpr char kPsr[] = "healthd_psr";

}  // namespace user

namespace dlc {

// The DLC ID for fio.
constexpr char kFio[] = "fio-dlc";

}  // namespace dlc

// Amount of time we wait for a process to respond to SIGTERM before killing it.
constexpr base::TimeDelta kTerminationTimeout = base::Seconds(2);

// The ectool command used to collect fan speed in RPM.
constexpr char kGetFanRpmCommand[] = "pwmgetfanrpm";

// wireless interface name start with "wl" or "ml" and end it with a number. All
// characters are in lowercase.  Max length is 16 characters.
constexpr auto kWirelessInterfaceRegex = R"(([wm]l[a-z][a-z0-9]{1,12}[0-9]))";

// Whitelist of msr registers that can be read by the ReadMsr call.
constexpr uint32_t kMsrAccessAllowList[] = {
    cpu_msr::kIA32TmeCapability, cpu_msr::kIA32TmeActivate,
    cpu_msr::kIA32FeatureControl, cpu_msr::kVmCr};

// Error message when failing to launch delegate.
constexpr char kFailToLaunchDelegate[] = "Failed to launch delegate";

base::FilePath FileEnumToFilePath(mojom::Executor::File file_enum) {
  switch (file_enum) {
    case mojom::Executor::File::kCrashLog:
      return base::FilePath{"/var/log/chrome/Crash Reports/uploads.log"};
    // Path to the UEFI SecureBoot file. This file can be read by root only.
    // It's one of EFI globally defined variables (EFI_GLOBAL_VARIABLE, fixed
    // UUID 8be4df61-93ca-11d2-aa0d-00e098032b8c) See also:
    // https://uefi.org/sites/default/files/resources/UEFI_Spec_2_9_2021_03_18.pdf
    case mojom::Executor::File::kUEFISecureBootVariable:
      return base::FilePath{
          "/sys/firmware/efi/efivars/"
          "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"};
    case mojom::Executor::File::kUEFIPlatformSize:
      return base::FilePath{"/sys/firmware/efi/fw_platform_size"};
    case mojom::Executor::File::kWirelessPowerScheme:
      return base::FilePath{"/sys/module/iwlmvm/parameters/power_scheme"};
  }
}

// A helper to create a delegate callback which only run once and reply the
// result to a callback. This takes a delegate instance and will destruct it
// after the callback is called. If the callback is dropped (e.g. mojo
// disconnect), the `default_args` is used to reply the callback.
//
// Example:
//   auto delegate = std::make_unique<DelegateProcess>(...);
//   // Get pointer and move the delegate into the callback.
//   auto* delegate_ptr = delegate.get();
//   delegate_ptr->remote()->SomeMethod(
//     CreateOnceDelegateCallback(
//       std::move(delegate), std::move(callback), ...));
//   delegate_ptr->StartAsync();
//
template <typename Callback, typename... Args>
Callback CreateOnceDelegateCallback(std::unique_ptr<DelegateProcess> delegate,
                                    Callback callback,
                                    Args... default_args) {
  base::OnceClosure deleter = base::DoNothingWithBoundArgs(std::move(delegate));
  return mojo::WrapCallbackWithDefaultInvokeIfNotRun(
      std::move(callback).Then(std::move(deleter)), std::move(default_args)...);
}

// Convert enum to fio argument.
std::optional<std::string> Convert(mojom::DiskReadTypeEnum disk_read_type) {
  switch (disk_read_type) {
    case mojom::DiskReadTypeEnum::kLinearRead:
      return "read";
    case mojom::DiskReadTypeEnum::kRandomRead:
      return "randread";
    case mojom::DiskReadTypeEnum::kUnmappedEnumField:
      LOG(WARNING) << "DiskReadTypeEnum: UnmappedEnumField";
      return std::nullopt;
  }
}

std::optional<std::vector<std::string>> GenerateFioCommand(
    const base::FilePath& fio_path,
    ash::cros_healthd::mojom::FioJobArgumentPtr argument) {
  switch (argument->which()) {
    case mojom::FioJobArgument::Tag::kPrepare:
      return std::vector<std::string>{
          fio_path.value(),
          "--filename=" + std::string(path::kFioCacheFile),
          "--name=prepare",
          "--size=" +
              base::NumberToString(argument->get_prepare()->file_size_mb) +
              "MB",
          "--verify=md5",
          "--rw=write",
          "--end_fsync=1",
          "--verify_state_save=0",
          "--output-format=json"};
    case mojom::FioJobArgument::Tag::kRead:
      const auto& type = Convert(argument->get_read()->disk_read_type);
      if (!type.has_value()) {
        // Return null command if the type is |kUnmappedEnumField|.
        return std::nullopt;
      }
      return std::vector<std::string>{
          fio_path.value(),
          "--filename=" + std::string(path::kFioCacheFile),
          "--name=run",
          "--time_based=1",
          "--runtime=" + base::NumberToString(
                             argument->get_read()->exec_duration.InSeconds()),
          "--direct=1",
          "--rw=" + type.value(),
          "--output-format=json"};
  }
}

}  // namespace

// Exported for testing.
bool IsValidWirelessInterfaceName(const std::string& interface_name) {
  return (RE2::FullMatch(interface_name, kWirelessInterfaceRegex, nullptr));
}

Executor::Executor(
    const scoped_refptr<base::SingleThreadTaskRunner> mojo_task_runner,
    mojo::PendingReceiver<mojom::Executor> receiver,
    brillo::ProcessReaper* process_reaper,
    base::OnceClosure on_disconnect)
    : mojo_task_runner_(mojo_task_runner),
      receiver_{this /* impl */, std::move(receiver)},
      process_reaper_(process_reaper) {
  receiver_.set_disconnect_handler(std::move(on_disconnect));

  // Initialize the D-Bus connection.
  auto dbus_bus = connection_.Connect();
  CHECK(dbus_bus) << "Failed to connect to the D-Bus system bus.";

  // Used to access DLC state and install DLC.
  dlcservice_proxy_ =
      std::make_unique<org::chromium::DlcServiceInterfaceProxy>(dbus_bus);
  dlc_manager_ = std::make_unique<DlcManager>(dlcservice_proxy_.get());
  dlc_manager_->Initialize();
}

Executor::~Executor() = default;

void Executor::ReadFile(File file_enum, ReadFileCallback callback) {
  base::FilePath file = FileEnumToFilePath(file_enum);
  std::string content = "";
  if (!base::ReadFileToString(file, &content)) {
    PLOG(ERROR) << "Failed to read file " << file;
    std::move(callback).Run(std::nullopt);
    return;
  }
  std::move(callback).Run(content);
}

void Executor::ReadFilePart(File file_enum,
                            uint64_t begin,
                            std::optional<uint64_t> size,
                            ReadFilePartCallback callback) {
  std::move(callback).Run(
      diagnostics::ReadFilePart(FileEnumToFilePath(file_enum), begin, size));
}

void Executor::GetFileInfo(File file_enum, GetFileInfoCallback callback) {
  base::FilePath file = FileEnumToFilePath(file_enum);
  base::Time result;
  // We do not use `base::File::GetInfo` here because it doesn't return the real
  // file creation time. See the document of `GetCreationTime`.
  // TODO(crbug/1442014): Migrate to base::File::GetInfo() once this issue is
  // solved.
  if (!GetCreationTime(file, result)) {
    PLOG(ERROR) << "Failed to get file info " << file;
    std::move(callback).Run(nullptr);
    return;
  }
  std::move(callback).Run(mojom::FileInfo::New(
      /*creation_time=*/result));
}

void Executor::GetFanSpeed(GetFanSpeedCallback callback) {
  std::vector<std::string> command = {path::kEctoolBinary, kGetFanRpmCommand};
  auto process = std::make_unique<SandboxedProcess>(
      command, seccomp_file::kFanSpeed,
      SandboxedProcess::Options{
          .user = user::kEc,
          .capabilities_mask = CAP_TO_MASK(CAP_SYS_RAWIO),
          .readonly_mount_points = {base::FilePath(path::kCrosEcDevice)},
      });

  RunAndWaitProcess(std::move(process), std::move(callback),
                    /*combine_stdout_and_stderr=*/false);
}

void Executor::RunIw(IwCommand cmd,
                     const std::string& interface_name,
                     RunIwCallback callback) {
  // Sanitize against interface_name.
  if (cmd == IwCommand::kDev) {
    if (interface_name != "") {
      auto result = mojom::ExecutedProcessResult::New();
      result->err = "Dev subcommand doesn't take interface name.";
      LOG(ERROR) << result->err;
      result->return_code = EXIT_FAILURE;
      std::move(callback).Run(std::move(result));
      return;
    }
  } else {
    if (!IsValidWirelessInterfaceName(interface_name)) {
      auto result = mojom::ExecutedProcessResult::New();
      result->err = "Illegal interface name: " + interface_name;
      LOG(ERROR) << result->err;
      result->return_code = EXIT_FAILURE;
      std::move(callback).Run(std::move(result));
      return;
    }
  }

  std::vector<std::string> command;
  switch (cmd) {
    case IwCommand::kDev:
      command = {path::kIwBinary, "dev"};
      break;
    case IwCommand::kLink:
      command = {path::kIwBinary, interface_name, "link"};
      break;
    case IwCommand::kInfo:
      command = {path::kIwBinary, interface_name, "info"};
      break;
    case IwCommand::kScanDump:
      command = {path::kIwBinary, interface_name, "scan", "dump"};
      break;
  }

  auto process = std::make_unique<SandboxedProcess>(
      command, seccomp_file::kIw,
      SandboxedProcess::Options{
          .sandbox_option = NO_ENTER_NETWORK_NAMESPACE,
      });

  RunAndWaitProcess(std::move(process), std::move(callback),
                    /*combine_stdout_and_stderr=*/false);
}

void Executor::RunMemtester(uint32_t test_mem_kib,
                            RunMemtesterCallback callback) {
  // Run with test_mem_kib memory and run for one loop.
  std::vector<std::string> command = {
      path::kMemtesterBinary, base::StringPrintf("%uK", test_mem_kib), "1"};
  auto process = std::make_unique<SandboxedProcess>(
      command, seccomp_file::kMemtester,
      SandboxedProcess::Options{
          .capabilities_mask = CAP_TO_MASK(CAP_IPC_LOCK),
      });

  RunTrackedBinary(std::move(process), std::move(callback),
                   path::kMemtesterBinary);
}

void Executor::RunMemtesterV2(
    uint32_t test_mem_kib,
    mojo::PendingReceiver<mojom::ProcessControl> receiver) {
  // Run with test_mem_kib memory and run for 1 loop.
  std::vector<std::string> command = {
      path::kMemtesterBinary, base::StringPrintf("%uK", test_mem_kib), "1"};
  auto process = std::make_unique<SandboxedProcess>(
      command, seccomp_file::kMemtester,
      SandboxedProcess::Options{
          .capabilities_mask = CAP_TO_MASK(CAP_IPC_LOCK),
      });

  RunLongRunningProcess(std::move(process), std::move(receiver),
                        /*combine_stdout_and_stderr=*/true);
}

void Executor::KillMemtester() {
  base::AutoLock auto_lock(lock_);
  auto itr = tracked_processes_.find(path::kMemtesterBinary);
  if (itr == tracked_processes_.end())
    return;

  SandboxedProcess* process = itr->second.get();
  // If the process has ended, don't try to kill anything.
  if (!process->pid())
    return;

  // Try to terminate the process nicely, then kill it if necessary.
  if (!process->Kill(SIGTERM, kTerminationTimeout.InSeconds()))
    process->Kill(SIGKILL, kTerminationTimeout.InSeconds());
}

void Executor::GetProcessIOContents(const std::vector<uint32_t>& pids,
                                    GetProcessIOContentsCallback callback) {
  std::vector<std::pair<uint32_t, std::string>> results;

  for (const auto& pid : pids) {
    std::string result;
    if (ReadAndTrimString(base::FilePath("/proc/")
                              .Append(base::StringPrintf("%" PRId32, pid))
                              .AppendASCII("io"),
                          &result)) {
      results.push_back({pid, result});
    }
  }

  std::move(callback).Run(
      base::flat_map<uint32_t, std::string>{std::move(results)});
}

void Executor::ReadMsr(const uint32_t msr_reg,
                       uint32_t cpu_index,
                       ReadMsrCallback callback) {
  if (std::find(std::begin(kMsrAccessAllowList), std::end(kMsrAccessAllowList),
                msr_reg) == std::end(kMsrAccessAllowList)) {
    LOG(ERROR) << "MSR access not allowed";
    std::move(callback).Run(nullptr);
    return;
  }
  base::FilePath msr_path = base::FilePath("/dev/cpu")
                                .Append(base::NumberToString(cpu_index))
                                .Append("msr");
  base::File msr_fd(msr_path, base::File::FLAG_OPEN | base::File::FLAG_READ);
  if (!msr_fd.IsValid()) {
    LOG(ERROR) << "Could not open " << msr_path.value();
    std::move(callback).Run(nullptr);
    return;
  }
  uint64_t val = 0;
  // Read MSR register. See
  // https://github.com/intel/msr-tools/blob/0fcbda4e47a2aab73904e19b3fc0a7a73135c415/rdmsr.c#L235
  // for the use of reinterpret_case
  if (sizeof(val) !=
      msr_fd.Read(msr_reg, reinterpret_cast<char*>(&val), sizeof(val))) {
    LOG(ERROR) << "Could not read MSR register from " << msr_path.value();
    std::move(callback).Run(nullptr);
    return;
  }
  std::move(callback).Run(mojom::NullableUint64::New(val));
}

void Executor::GetLidAngle(GetLidAngleCallback callback) {
  auto delegate = std::make_unique<DelegateProcess>(
      seccomp_file::kLidAngle,
      SandboxedProcess::Options{
          .user = user::kEc,
          .readonly_mount_points = {base::FilePath{path::kCrosEcDevice}},
      });

  auto* delegate_ptr = delegate.get();
  delegate_ptr->remote()->GetLidAngle(CreateOnceDelegateCallback(
      std::move(delegate), std::move(callback), std::nullopt));
  delegate_ptr->StartAsync();
}

void Executor::GetFingerprintFrame(mojom::FingerprintCaptureType type,
                                   GetFingerprintFrameCallback callback) {
  auto delegate = std::make_unique<DelegateProcess>(
      seccomp_file::kFingerprint,
      SandboxedProcess::Options{
          .user = user::kFingerprint,
          .writable_mount_points = {base::FilePath{path::kCrosFpDevice}},
      });

  auto* delegate_ptr = delegate.get();
  delegate_ptr->remote()->GetFingerprintFrame(
      type, CreateOnceDelegateCallback(std::move(delegate), std::move(callback),
                                       mojom::FingerprintFrameResult::New(),
                                       kFailToLaunchDelegate));
  delegate_ptr->StartAsync();
}

void Executor::GetFingerprintInfo(GetFingerprintInfoCallback callback) {
  auto delegate = std::make_unique<DelegateProcess>(
      seccomp_file::kFingerprint,
      SandboxedProcess::Options{
          .user = user::kFingerprint,
          .writable_mount_points = {base::FilePath{path::kCrosFpDevice}},
      });

  auto* delegate_ptr = delegate.get();
  delegate_ptr->remote()->GetFingerprintInfo(CreateOnceDelegateCallback(
      std::move(delegate), std::move(callback),
      mojom::FingerprintInfoResult::New(), kFailToLaunchDelegate));
  delegate_ptr->StartAsync();
}

void Executor::GetPsr(GetPsrCallback callback) {
  auto delegate = std::make_unique<DelegateProcess>(
      seccomp_file::kPsr,
      SandboxedProcess::Options{
          .user = user::kPsr,
          .readonly_mount_points = {base::FilePath{psr::kCrosMeiPath}},
          .writable_mount_points = {base::FilePath{psr::kCrosMeiPath}},
      });

  auto* delegate_ptr = delegate.get();
  delegate_ptr->remote()->GetPsr(
      CreateOnceDelegateCallback(std::move(delegate), std::move(callback),
                                 mojom::PsrInfo::New(), kFailToLaunchDelegate));
  delegate_ptr->StartAsync();
}

void Executor::FetchCrashFromCrashSender(
    FetchCrashFromCrashSenderCallback callback) {
  // Use `brillo::ProcessImpl` instead of `SandboxedProcess` because
  // crash_sender invokes minijail on startup. See `SetUpSandboxForDryRun` in
  // platform2/crash-reporter/crash_sender.cc, which also contains a list of
  // required directories.
  auto subprocess = std::make_unique<brillo::ProcessImpl>();
  subprocess->AddArg(path::kCrashSenderBinary);
  subprocess->AddArg("--dry_run");
  RunAndWaitProcess(std::move(subprocess), std::move(callback),
                    /*combine_stdout_and_stderr=*/false);
}

void Executor::SetLedColor(mojom::LedName name,
                           mojom::LedColor color,
                           SetLedColorCallback callback) {
  auto delegate = std::make_unique<DelegateProcess>(
      seccomp_file::kLed,
      SandboxedProcess::Options{
          .user = user::kEc,
          .writable_mount_points = {base::FilePath{path::kCrosEcDevice}},
      });

  auto* delegate_ptr = delegate.get();
  delegate_ptr->remote()->SetLedColor(
      name, color,
      CreateOnceDelegateCallback(std::move(delegate), std::move(callback),
                                 kFailToLaunchDelegate));
  delegate_ptr->StartAsync();
}

void Executor::ResetLedColor(ash::cros_healthd::mojom::LedName name,
                             ResetLedColorCallback callback) {
  auto delegate = std::make_unique<DelegateProcess>(
      seccomp_file::kLed,
      SandboxedProcess::Options{
          .user = user::kEc,
          .writable_mount_points = {base::FilePath{path::kCrosEcDevice}},
      });

  auto* delegate_ptr = delegate.get();
  delegate_ptr->remote()->ResetLedColor(
      name, CreateOnceDelegateCallback(std::move(delegate), std::move(callback),
                                       kFailToLaunchDelegate));
  delegate_ptr->StartAsync();
}

void Executor::GetHciDeviceConfig(GetHciDeviceConfigCallback callback) {
  std::vector<std::string> command = {path::kHciconfigBinary, "hci0"};
  auto process = std::make_unique<SandboxedProcess>(
      command, seccomp_file::kHciconfig,
      SandboxedProcess::Options{
          .sandbox_option = NO_ENTER_NETWORK_NAMESPACE,
      });

  RunAndWaitProcess(std::move(process), std::move(callback),
                    /*combine_stdout_and_stderr=*/false);
}

void Executor::MonitorAudioJack(
    mojo::PendingRemote<mojom::AudioJackObserver> observer,
    mojo::PendingReceiver<mojom::ProcessControl> process_control_receiver) {
  auto delegate = std::make_unique<DelegateProcess>(
      seccomp_file::kEvdev,
      SandboxedProcess::Options{
          .user = user::kEvdev,
          .readonly_mount_points = {base::FilePath{path::kInputDevice}},
      });

  delegate->remote()->MonitorAudioJack(std::move(observer));
  auto controller =
      std::make_unique<ProcessControl>(std::move(delegate), process_reaper_);

  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&Executor::RunLongRunningDelegate,
                     weak_factory_.GetWeakPtr(), std::move(controller),
                     std::move(process_control_receiver)));
}

void Executor::MonitorTouchpad(
    mojo::PendingRemote<mojom::TouchpadObserver> observer,
    mojo::PendingReceiver<mojom::ProcessControl> process_control_receiver) {
  auto delegate = std::make_unique<DelegateProcess>(
      seccomp_file::kEvdev,
      SandboxedProcess::Options{
          .user = user::kEvdev,
          .readonly_mount_points = {base::FilePath{path::kInputDevice}},
      });

  delegate->remote()->MonitorTouchpad(std::move(observer));
  auto controller =
      std::make_unique<ProcessControl>(std::move(delegate), process_reaper_);

  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&Executor::RunLongRunningDelegate,
                     weak_factory_.GetWeakPtr(), std::move(controller),
                     std::move(process_control_receiver)));
}

void Executor::RunStressAppTest(
    uint32_t test_mem_mib,
    uint32_t test_seconds,
    mojom::StressAppTestType test_type,
    mojo::PendingReceiver<ash::cros_healthd::mojom::ProcessControl> receiver) {
  // Run with |test_mem_mib| memory and run for |test_seconds| seconds.
  std::vector<std::string> command = {path::kStressAppTestBinary,
                                      "-W",
                                      "-s",
                                      base::NumberToString(test_seconds),
                                      "-M",
                                      base::NumberToString(test_mem_mib)};
  if (test_type == mojom::StressAppTestType::kCpuCache) {
    command.push_back("--cc_test");
  }
  auto process = std::make_unique<SandboxedProcess>(
      command, seccomp_file::kStressAppTest,
      SandboxedProcess::Options{
          .capabilities_mask = CAP_TO_MASK(CAP_IPC_LOCK),
      });

  RunLongRunningProcess(std::move(process), std::move(receiver),
                        /*combine_stdout_and_stderr=*/true);
}

void Executor::FetchBootPerformance(FetchBootPerformanceCallback callback) {
  auto delegate = std::make_unique<DelegateProcess>(
      seccomp_file::kReadOnlyFetchers,
      SandboxedProcess::Options{
          .readonly_mount_points =
              {
                  base::FilePath{path::kBiosTimes},
                  base::FilePath{path::kPreviousPowerdLog},
                  base::FilePath{path::kProcUptime},
                  base::FilePath{path::kShutdownMetrics},
                  base::FilePath{path::kUptimeLoginPromptVisible},
              },
      });

  auto* delegate_ptr = delegate.get();
  delegate_ptr->remote()->FetchBootPerformance(CreateOnceDelegateCallback(
      std::move(delegate), std::move(callback),
      mojom::BootPerformanceResult::NewError(mojom::ProbeError::New(
          mojom::ErrorType::kSystemUtilityError, kFailToLaunchDelegate))));
  delegate_ptr->StartAsync();
}

void Executor::MonitorTouchscreen(
    mojo::PendingRemote<mojom::TouchscreenObserver> observer,
    mojo::PendingReceiver<mojom::ProcessControl> process_control_receiver) {
  auto delegate = std::make_unique<DelegateProcess>(
      seccomp_file::kEvdev,
      SandboxedProcess::Options{
          .user = user::kEvdev,
          .readonly_mount_points = {base::FilePath{path::kInputDevice}},
      });

  delegate->remote()->MonitorTouchscreen(std::move(observer));
  auto controller =
      std::make_unique<ProcessControl>(std::move(delegate), process_reaper_);

  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&Executor::RunLongRunningDelegate,
                     weak_factory_.GetWeakPtr(), std::move(controller),
                     std::move(process_control_receiver)));
}

void Executor::MonitorStylusGarage(
    mojo::PendingRemote<mojom::StylusGarageObserver> observer,
    mojo::PendingReceiver<mojom::ProcessControl> process_control_receiver) {
  auto delegate = std::make_unique<DelegateProcess>(
      seccomp_file::kEvdev,
      SandboxedProcess::Options{
          .user = user::kEvdev,
          .readonly_mount_points = {base::FilePath{path::kInputDevice}},
      });

  delegate->remote()->MonitorStylusGarage(std::move(observer));
  auto controller =
      std::make_unique<ProcessControl>(std::move(delegate), process_reaper_);

  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&Executor::RunLongRunningDelegate,
                     weak_factory_.GetWeakPtr(), std::move(controller),
                     std::move(process_control_receiver)));
}

void Executor::MonitorStylus(
    mojo::PendingRemote<mojom::StylusObserver> observer,
    mojo::PendingReceiver<mojom::ProcessControl> process_control_receiver) {
  auto delegate = std::make_unique<DelegateProcess>(
      seccomp_file::kEvdev,
      SandboxedProcess::Options{
          .user = user::kEvdev,
          .readonly_mount_points = {base::FilePath{path::kInputDevice}},
      });

  delegate->remote()->MonitorStylus(std::move(observer));
  auto controller =
      std::make_unique<ProcessControl>(std::move(delegate), process_reaper_);

  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&Executor::RunLongRunningDelegate,
                     weak_factory_.GetWeakPtr(), std::move(controller),
                     std::move(process_control_receiver)));
}

void Executor::RunFio(mojom::FioJobArgumentPtr argument,
                      mojo::PendingReceiver<mojom::ProcessControl> receiver) {
  dlc_manager_->GetBinaryRootPath(
      dlc::kFio,
      base::BindOnce(&Executor::RunFioWithDlcRoot, weak_factory_.GetWeakPtr(),
                     std::move(argument), std::move(receiver)));
}

void Executor::RunFioWithDlcRoot(
    ash::cros_healthd::mojom::FioJobArgumentPtr argument,
    mojo::PendingReceiver<ash::cros_healthd::mojom::ProcessControl> receiver,
    std::optional<base::FilePath> dlc_root_path) {
  if (!dlc_root_path.has_value()) {
    receiver.reset();
    return;
  }

  std::vector<base::FilePath> readonly_mount_points, writable_mount_points;
  switch (argument->which()) {
    case mojom::FioJobArgument::Tag::kPrepare:
      writable_mount_points.push_back(
          base::FilePath(path::kFioCacheFile).DirName());
      break;
    case mojom::FioJobArgument::Tag::kRead:
      readonly_mount_points.emplace_back(path::kFioCacheFile);
      break;
  }

  auto command = GenerateFioCommand(dlc_root_path.value().Append("bin/fio"),
                                    std::move(argument));
  if (!command.has_value()) {
    receiver.reset();
    return;
  }
  auto process = std::make_unique<SandboxedProcess>(
      command.value(), seccomp_file::kFio,
      SandboxedProcess::Options{
          .readonly_mount_points = readonly_mount_points,
          .writable_mount_points = writable_mount_points,
          .sandbox_option = MOUNT_DLC,
      });
  RunLongRunningProcess(std::move(process), std::move(receiver),
                        /*combine_stdout_and_stderr=*/false);
}

void Executor::RemoveFioTestFile(RemoveFioTestFileCallback callback) {
  std::vector<std::string> command = {"/bin/rm", "-f", path::kFioCacheFile};
  auto process = std::make_unique<SandboxedProcess>(
      command, seccomp_file::kRm,
      SandboxedProcess::Options{
          .writable_mount_points =
              {base::FilePath(path::kFioCacheFile).DirName()},
      });

  RunAndWaitProcess(std::move(process), std::move(callback),
                    /*combine_stdout_and_stderr=*/false);
}

void Executor::GetFioTestDirectoryFreeSpace(
    GetFioTestDirectoryFreeSpaceCallback callback) {
  const auto& cache_dir = base::FilePath(path::kFioCacheFile).DirName();
  auto delegate = std::make_unique<DelegateProcess>(
      seccomp_file::kFreeDiskSpace, SandboxedProcess::Options{
                                        .readonly_mount_points = {cache_dir},
                                    });

  auto* delegate_ptr = delegate.get();
  delegate_ptr->remote()->GetAmountOfFreeDiskSpace(
      cache_dir.value(),
      CreateOnceDelegateCallback(std::move(delegate), std::move(callback),
                                 std::nullopt));
  delegate_ptr->StartAsync();
}

void Executor::MonitorPowerButton(
    mojo::PendingRemote<mojom::PowerButtonObserver> observer,
    mojo::PendingReceiver<mojom::ProcessControl> process_control_receiver) {
  auto delegate = std::make_unique<DelegateProcess>(
      seccomp_file::kEvdev,
      SandboxedProcess::Options{
          .user = user::kEvdev,
          .readonly_mount_points = {base::FilePath{path::kInputDevice}},
      });

  delegate->remote()->MonitorPowerButton(std::move(observer));
  auto controller =
      std::make_unique<ProcessControl>(std::move(delegate), process_reaper_);

  base::SequencedTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::BindOnce(&Executor::RunLongRunningDelegate,
                     weak_factory_.GetWeakPtr(), std::move(controller),
                     std::move(process_control_receiver)));
}

void Executor::RunPrimeSearch(
    uint32_t duration_sec,
    uint64_t max_num,
    mojo::PendingReceiver<mojom::ProcessControl> process_control_receiver,
    RunPrimeSearchCallback callback) {
  auto delegate = std::make_unique<DelegateProcess>(
      seccomp_file::kPrimeSearch, SandboxedProcess::Options{});
  delegate->remote()->RunPrimeSearch(
      duration_sec, max_num,
      mojo::WrapCallbackWithDefaultInvokeIfNotRun(std::move(callback), false));
  auto controller =
      std::make_unique<ProcessControl>(std::move(delegate), process_reaper_);

  base::SequencedTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::BindOnce(&Executor::RunLongRunningDelegate,
                     weak_factory_.GetWeakPtr(), std::move(controller),
                     std::move(process_control_receiver)));
}

void Executor::MonitorVolumeButton(
    mojo::PendingRemote<mojom::VolumeButtonObserver> observer,
    mojo::PendingReceiver<mojom::ProcessControl> process_control_receiver) {
  auto delegate = std::make_unique<DelegateProcess>(
      seccomp_file::kEvdev,
      SandboxedProcess::Options{
          .user = user::kEvdev,
          .readonly_mount_points = {base::FilePath{path::kInputDevice}},
      });

  delegate->remote()->MonitorVolumeButton(std::move(observer));
  auto controller =
      std::make_unique<ProcessControl>(std::move(delegate), process_reaper_);

  base::SequencedTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::BindOnce(&Executor::RunLongRunningDelegate,
                     weak_factory_.GetWeakPtr(), std::move(controller),
                     std::move(process_control_receiver)));
}

void Executor::RunAndWaitProcess(
    std::unique_ptr<brillo::ProcessImpl> process,
    base::OnceCallback<void(mojom::ExecutedProcessResultPtr)> callback,
    bool combine_stdout_and_stderr) {
  process->RedirectOutputToMemory(combine_stdout_and_stderr);
  process->Start();

  process_reaper_->WatchForChild(
      FROM_HERE, process->pid(),
      base::BindOnce(&Executor::OnRunAndWaitProcessFinished,
                     weak_factory_.GetWeakPtr(), std::move(callback),
                     std::move(process)));
}

void Executor::OnRunAndWaitProcessFinished(
    base::OnceCallback<void(mojom::ExecutedProcessResultPtr)> callback,
    std::unique_ptr<brillo::ProcessImpl> process,
    const siginfo_t& siginfo) {
  auto result = mojom::ExecutedProcessResult::New();

  result->return_code = siginfo.si_status;
  result->out = process->GetOutputString(STDOUT_FILENO);
  result->err = process->GetOutputString(STDERR_FILENO);

  process->Release();
  std::move(callback).Run(std::move(result));
}

void Executor::RunTrackedBinary(
    std::unique_ptr<SandboxedProcess> process,
    base::OnceCallback<void(ash::cros_healthd::mojom::ExecutedProcessResultPtr)>
        callback,
    const std::string& binary_path) {
  DCHECK(!tracked_processes_.count(binary_path));

  base::AutoLock auto_lock(lock_);

  process->RedirectOutputToMemory(false);
  process->Start();
  pid_t pid = process->pid();

  tracked_processes_[binary_path] = std::move(process);
  process_reaper_->WatchForChild(
      FROM_HERE, pid,
      base::BindOnce(&Executor::OnTrackedBinaryFinished,
                     weak_factory_.GetWeakPtr(), std::move(callback),
                     binary_path));
}

void Executor::OnTrackedBinaryFinished(
    base::OnceCallback<void(mojom::ExecutedProcessResultPtr)> callback,
    const std::string& binary_path,
    const siginfo_t& siginfo) {
  auto result = mojom::ExecutedProcessResult::New();

  result->return_code = siginfo.si_status;
  result->out = tracked_processes_[binary_path]->GetOutputString(STDOUT_FILENO);
  result->err = tracked_processes_[binary_path]->GetOutputString(STDERR_FILENO);
  tracked_processes_[binary_path]->Release();
}

void Executor::RunLongRunningProcess(
    std::unique_ptr<SandboxedProcess> process,
    mojo::PendingReceiver<ash::cros_healthd::mojom::ProcessControl> receiver,
    bool combine_stdout_and_stderr) {
  auto controller =
      std::make_unique<ProcessControl>(std::move(process), process_reaper_);

  controller->RedirectOutputToMemory(combine_stdout_and_stderr);
  controller->StartAndWait();
  process_control_set_.Add(std::move(controller), std::move(receiver));
}

void Executor::RunLongRunningDelegate(
    std::unique_ptr<ProcessControl> process_control,
    mojo::PendingReceiver<mojom::ProcessControl> receiver) {
  process_control->StartAndWait();
  process_control_set_.Add(std::move(process_control), std::move(receiver));
}

void Executor::GetConnectedHdmiConnectors(
    GetConnectedHdmiConnectorsCallback callback) {
  auto delegate = std::make_unique<DelegateProcess>(
      seccomp_file::kDrm,
      SandboxedProcess::Options{
          .readonly_mount_points = {base::FilePath{path::kDrmDevice}},
      });
  auto* delegate_ptr = delegate.get();
  delegate_ptr->remote()->GetConnectedHdmiConnectors(CreateOnceDelegateCallback(
      std::move(delegate), std::move(callback),
      base::flat_map<uint32_t, mojom::ExternalDisplayInfoPtr>{},
      kFailToLaunchDelegate));
  delegate_ptr->StartAsync();
}

void Executor::GetPrivacyScreenInfo(GetPrivacyScreenInfoCallback callback) {
  auto delegate = std::make_unique<DelegateProcess>(
      seccomp_file::kDrm,
      SandboxedProcess::Options{
          .readonly_mount_points = {base::FilePath{path::kDrmDevice}},
      });
  auto* delegate_ptr = delegate.get();
  delegate_ptr->remote()->GetPrivacyScreenInfo(
      CreateOnceDelegateCallback(std::move(delegate), std::move(callback),
                                 false, false, kFailToLaunchDelegate));
  delegate_ptr->StartAsync();
}

void Executor::FetchDisplayInfo(FetchDisplayInfoCallback callback) {
  auto delegate = std::make_unique<DelegateProcess>(
      seccomp_file::kDrm,
      SandboxedProcess::Options{
          .readonly_mount_points = {base::FilePath{path::kDrmDevice}},
      });
  auto* delegate_ptr = delegate.get();
  delegate_ptr->remote()->FetchDisplayInfo(CreateOnceDelegateCallback(
      std::move(delegate), std::move(callback),
      mojom::DisplayResult::NewError(mojom::ProbeError::New(
          mojom::ErrorType::kSystemUtilityError, kFailToLaunchDelegate))));
  delegate_ptr->StartAsync();
}

}  // namespace diagnostics
