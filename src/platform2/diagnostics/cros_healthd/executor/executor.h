// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_EXECUTOR_EXECUTOR_H_
#define DIAGNOSTICS_CROS_HEALTHD_EXECUTOR_EXECUTOR_H_

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/memory/scoped_refptr.h>
#include <base/memory/weak_ptr.h>
#include <base/synchronization/lock.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/dbus/dbus_connection.h>
#include <brillo/process/process.h>
#include <brillo/process/process_reaper.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/unique_receiver_set.h>

#include "diagnostics/cros_healthd/executor/constants.h"
#include "diagnostics/cros_healthd/executor/utils/sandboxed_process.h"
#include "diagnostics/cros_healthd/mojom/executor.mojom.h"
#include "diagnostics/mojom/public/nullable_primitives.mojom.h"

namespace org::chromium {
class DlcServiceInterfaceProxyInterface;
}  // namespace org::chromium

namespace diagnostics {
class DlcManager;
class ProcessControl;

bool IsValidWirelessInterfaceName(const std::string& interface_name);

// Production implementation of the mojom::Executor Mojo interface.
class Executor final : public ash::cros_healthd::mojom::Executor {
 public:
  Executor(const scoped_refptr<base::SingleThreadTaskRunner> mojo_task_runner,
           mojo::PendingReceiver<ash::cros_healthd::mojom::Executor> receiver,
           brillo::ProcessReaper* process_reaper,
           base::OnceClosure on_disconnect);
  Executor(const Executor&) = delete;
  Executor& operator=(const Executor&) = delete;
  ~Executor() override;

  // ash::cros_healthd::mojom::Executor overrides:
  void ReadFile(File file_enum, ReadFileCallback callback) override;
  void ReadFilePart(File file_enum,
                    uint64_t begin,
                    std::optional<uint64_t> size,
                    ReadFilePartCallback callback) override;
  void GetFileInfo(File file_enum, GetFileInfoCallback callback) override;
  void GetFanSpeed(GetFanSpeedCallback callback) override;
  void RunIw(IwCommand cmd,
             const std::string& interface_name,
             RunIwCallback callback) override;
  void RunMemtester(uint32_t test_mem_kib,
                    RunMemtesterCallback callback) override;
  void RunMemtesterV2(
      uint32_t test_mem_kib,
      mojo::PendingReceiver<ash::cros_healthd::mojom::ProcessControl> receiver)
      override;
  void KillMemtester() override;
  void GetProcessIOContents(const std::vector<uint32_t>& pids,
                            GetProcessIOContentsCallback callback) override;
  void ReadMsr(const uint32_t msr_reg,
               uint32_t cpu_index,
               ReadMsrCallback callback) override;
  void GetLidAngle(GetLidAngleCallback callback) override;
  void GetFingerprintFrame(
      ash::cros_healthd::mojom::FingerprintCaptureType type,
      GetFingerprintFrameCallback callback) override;
  void GetFingerprintInfo(GetFingerprintInfoCallback callback) override;
  void SetLedColor(ash::cros_healthd::mojom::LedName name,
                   ash::cros_healthd::mojom::LedColor color,
                   SetLedColorCallback callback) override;
  void ResetLedColor(ash::cros_healthd::mojom::LedName name,
                     ResetLedColorCallback callback) override;
  void GetHciDeviceConfig(GetHciDeviceConfigCallback callback) override;
  void MonitorAudioJack(
      mojo::PendingRemote<ash::cros_healthd::mojom::AudioJackObserver> observer,
      mojo::PendingReceiver<ash::cros_healthd::mojom::ProcessControl>
          process_control_receiver) override;
  void MonitorTouchpad(
      mojo::PendingRemote<ash::cros_healthd::mojom::TouchpadObserver> observer,
      mojo::PendingReceiver<ash::cros_healthd::mojom::ProcessControl>
          process_control_receiver) override;
  void FetchBootPerformance(FetchBootPerformanceCallback callback) override;
  void MonitorTouchscreen(
      mojo::PendingRemote<ash::cros_healthd::mojom::TouchscreenObserver>
          observer,
      mojo::PendingReceiver<ash::cros_healthd::mojom::ProcessControl>
          process_control_receiver) override;
  void MonitorStylusGarage(
      mojo::PendingRemote<ash::cros_healthd::mojom::StylusGarageObserver>
          observer,
      mojo::PendingReceiver<ash::cros_healthd::mojom::ProcessControl>
          process_control_receiver) override;
  void MonitorStylus(
      mojo::PendingRemote<ash::cros_healthd::mojom::StylusObserver> observer,
      mojo::PendingReceiver<ash::cros_healthd::mojom::ProcessControl>
          process_control_receiver) override;
  void GetPsr(GetPsrCallback callback) override;
  void FetchCrashFromCrashSender(
      FetchCrashFromCrashSenderCallback callback) override;
  void RunStressAppTest(
      uint32_t test_mem_mib,
      uint32_t test_seconds,
      ash::cros_healthd::mojom::StressAppTestType test_type,
      mojo::PendingReceiver<ash::cros_healthd::mojom::ProcessControl> receiver)
      override;
  void RunFio(ash::cros_healthd::mojom::FioJobArgumentPtr argument,
              mojo::PendingReceiver<ash::cros_healthd::mojom::ProcessControl>
                  receiver) override;
  void RemoveFioTestFile(RemoveFioTestFileCallback callback) override;
  void GetFioTestDirectoryFreeSpace(
      GetFioTestDirectoryFreeSpaceCallback callback) override;
  void GetConnectedHdmiConnectors(
      GetConnectedHdmiConnectorsCallback callback) override;
  void GetPrivacyScreenInfo(GetPrivacyScreenInfoCallback callback) override;
  void FetchDisplayInfo(FetchDisplayInfoCallback callback) override;
  void MonitorPowerButton(
      mojo::PendingRemote<ash::cros_healthd::mojom::PowerButtonObserver>
          observer,
      mojo::PendingReceiver<ash::cros_healthd::mojom::ProcessControl>
          process_control_receiver) override;
  void RunPrimeSearch(
      uint32_t duration_sec,
      uint64_t max_num,
      mojo::PendingReceiver<ash::cros_healthd::mojom::ProcessControl>
          process_control_receiver,
      RunPrimeSearchCallback callback) override;
  void MonitorVolumeButton(
      mojo::PendingRemote<ash::cros_healthd::mojom::VolumeButtonObserver>
          observer,
      mojo::PendingReceiver<ash::cros_healthd::mojom::ProcessControl>
          process_control_receiver) override;

 private:
  // Runs the given process and wait for it to die. Does not track the process
  // it launches, so the launched process cannot be cancelled once it is
  // started. If cancelling is required, RunLongRunningProcess() should be used
  // instead.
  void RunAndWaitProcess(
      std::unique_ptr<brillo::ProcessImpl> process,
      base::OnceCallback<
          void(ash::cros_healthd::mojom::ExecutedProcessResultPtr)> callback,
      bool combine_stdout_and_stderr);
  void OnRunAndWaitProcessFinished(
      base::OnceCallback<
          void(ash::cros_healthd::mojom::ExecutedProcessResultPtr)> callback,
      std::unique_ptr<brillo::ProcessImpl> process,
      const siginfo_t& siginfo);
  // (DEPRECATED: Use RunLongRunningProcess() instead) Like RunAndWaitprocess()
  // above, but tracks the process internally so that it can be cancelled if
  // necessary.
  void RunTrackedBinary(
      std::unique_ptr<SandboxedProcess> process,
      base::OnceCallback<
          void(ash::cros_healthd::mojom::ExecutedProcessResultPtr)> callback,
      const std::string& binary_path);
  void OnTrackedBinaryFinished(
      base::OnceCallback<
          void(ash::cros_healthd::mojom::ExecutedProcessResultPtr)> callback,
      const std::string& binary_path_str,
      const siginfo_t& siginfo);

  // Runs a long running delegate process. Takes a ProcessControl which holds
  // the delegate and a receiver to connect to the ProcessControl.
  void RunLongRunningDelegate(
      std::unique_ptr<ProcessControl> process_control,
      mojo::PendingReceiver<ash::cros_healthd::mojom::ProcessControl> receiver);
  // Runs a long running process and uses process control to track binary.
  void RunLongRunningProcess(
      std::unique_ptr<SandboxedProcess> process,
      mojo::PendingReceiver<ash::cros_healthd::mojom::ProcessControl> receiver,
      bool combine_stdout_and_stderr);

  // Run fio after getting the DLC root path.
  void RunFioWithDlcRoot(
      ash::cros_healthd::mojom::FioJobArgumentPtr argument,
      mojo::PendingReceiver<ash::cros_healthd::mojom::ProcessControl> receiver,
      std::optional<base::FilePath> dlc_root_path);

  // Task runner for all Mojo callbacks.
  const scoped_refptr<base::SingleThreadTaskRunner> mojo_task_runner_;

  // Provides a Mojo endpoint that cros_healthd can call to access the
  // executor's Mojo methods.
  mojo::Receiver<ash::cros_healthd::mojom::Executor> receiver_;

  // Prevents multiple simultaneous writes to |processes_|.
  base::Lock lock_;

  // Tracks running processes owned by the executor. Used to kill processes if
  // requested.
  std::map<std::string, std::unique_ptr<SandboxedProcess>> tracked_processes_;

  // Used to hold the child process and receiver. So the remote can reset the
  // mojo connection to terminate the child process.
  mojo::UniqueReceiverSet<ash::cros_healthd::mojom::ProcessControl>
      process_control_set_;

  // Used to monitor child process status.
  brillo::ProcessReaper* process_reaper_;

  // This should be the only connection to D-Bus. Use |connection_| to get the
  // |dbus_bus|.
  brillo::DBusConnection connection_;

  // Used to access DLC state and install DLC.
  std::unique_ptr<org::chromium::DlcServiceInterfaceProxyInterface>
      dlcservice_proxy_;
  std::unique_ptr<DlcManager> dlc_manager_;

  // Must be the last member of the class.
  base::WeakPtrFactory<Executor> weak_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_EXECUTOR_EXECUTOR_H_
