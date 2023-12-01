// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/delegate/delegate_impl.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <fcntl.h>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/memory/ref_counted.h>
#include <base/posix/eintr_wrapper.h>
#include <base/system/sys_info.h>
#include <chromeos/ec/ec_commands.h>
#include <libec/fingerprint/fp_frame_command.h>
#include <libec/fingerprint/fp_info_command.h>
#include <libec/fingerprint/fp_mode_command.h>
#include <libec/get_protocol_info_command.h>
#include <libec/get_version_command.h>
#include <libec/led_control_command.h>
#include <libec/mkbp_event.h>
#include <libec/motion_sense_command_lid_angle.h>

#include "diagnostics/cros_healthd/delegate/constants.h"
#include "diagnostics/cros_healthd/delegate/fetchers/boot_performance.h"
#include "diagnostics/cros_healthd/delegate/fetchers/display_fetcher.h"
#include "diagnostics/cros_healthd/delegate/routines/prime_number_search.h"
#include "diagnostics/cros_healthd/delegate/utils/display_utils.h"
#include "diagnostics/cros_healthd/delegate/utils/evdev_utils.h"
#include "diagnostics/cros_healthd/delegate/utils/psr_cmd.h"
#include "diagnostics/cros_healthd/executor/constants.h"
#include "diagnostics/cros_healthd/mojom/executor.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

ec::FpMode ToEcFpMode(mojom::FingerprintCaptureType type) {
  switch (type) {
    case mojom::FingerprintCaptureType::kCheckerboardTest:
      return ec::FpMode(ec::FpMode::Mode::kCapturePattern0);
    case mojom::FingerprintCaptureType::kInvertedCheckerboardTest:
      return ec::FpMode(ec::FpMode::Mode::kCapturePattern1);
    case mojom::FingerprintCaptureType::kResetTest:
      return ec::FpMode(ec::FpMode::Mode::kCaptureResetTest);
  }
}

enum ec_led_id ToEcLedId(mojom::LedName name) {
  switch (name) {
    case mojom::LedName::kBattery:
      return EC_LED_ID_BATTERY_LED;
    case mojom::LedName::kPower:
      return EC_LED_ID_POWER_LED;
    case mojom::LedName::kAdapter:
      return EC_LED_ID_ADAPTER_LED;
    case mojom::LedName::kLeft:
      return EC_LED_ID_LEFT_LED;
    case mojom::LedName::kRight:
      return EC_LED_ID_RIGHT_LED;
    case mojom::LedName::kUnmappedEnumField:
      LOG(WARNING) << "LedName UnmappedEnumField";
      return EC_LED_ID_COUNT;
  }
}

enum ec_led_colors ToEcLedColor(mojom::LedColor color) {
  switch (color) {
    case mojom::LedColor::kRed:
      return EC_LED_COLOR_RED;
    case mojom::LedColor::kGreen:
      return EC_LED_COLOR_GREEN;
    case mojom::LedColor::kBlue:
      return EC_LED_COLOR_BLUE;
    case mojom::LedColor::kYellow:
      return EC_LED_COLOR_YELLOW;
    case mojom::LedColor::kWhite:
      return EC_LED_COLOR_WHITE;
    case mojom::LedColor::kAmber:
      return EC_LED_COLOR_AMBER;
    case mojom::LedColor::kUnmappedEnumField:
      LOG(WARNING) << "LedColor UnmappedEnumField";
      return EC_LED_COLOR_COUNT;
  }
}

mojom::PsrInfo::LogState LogStateToMojo(diagnostics::psr::LogState log_state) {
  switch (log_state) {
    case diagnostics::psr::LogState::kNotStarted:
      return mojom::PsrInfo::LogState::kNotStarted;
    case diagnostics::psr::LogState::kStarted:
      return mojom::PsrInfo::LogState::kStarted;
    case diagnostics::psr::LogState::kStopped:
      return mojom::PsrInfo::LogState::kStopped;
  }
}

}  // namespace

namespace diagnostics {

DelegateImpl::DelegateImpl() = default;
DelegateImpl::~DelegateImpl() = default;

void DelegateImpl::GetFingerprintFrame(mojom::FingerprintCaptureType type,
                                       GetFingerprintFrameCallback callback) {
  auto result = mojom::FingerprintFrameResult::New();
  auto cros_fd = base::ScopedFD(open(path::kCrosFpDevice, O_RDWR));

  ec::FpInfoCommand info;
  if (!info.Run(cros_fd.get())) {
    std::move(callback).Run(std::move(result),
                            "Failed to run ec::FpInfoCommand");
    return;
  }

  result->width = info.sensor_image()->width;
  result->height = info.sensor_image()->height;

  ec::MkbpEvent mkbp_event(cros_fd.get(), EC_MKBP_EVENT_FINGERPRINT);
  if (mkbp_event.Enable() != 0) {
    PLOG(ERROR) << "Failed to enable fingerprint event";
    std::move(callback).Run(std::move(result),
                            "Failed to enable fingerprint event");
    return;
  }

  ec::FpModeCommand fp_mode_cmd(ToEcFpMode(type));
  if (!fp_mode_cmd.Run(cros_fd.get())) {
    std::move(callback).Run(std::move(result), "Failed to set capture mode");
    return;
  }

  // Wait for EC fingerprint event. Once it's done, it means the "capture"
  // action is completed, so we can get fingerprint frame data safely.
  //
  // We'll wait for 5 seconds until timeout. It blocks the process here but it's
  // okay for both caller and callee.
  //   - Callee is here, the delegate process, which only does one job for each
  //   launch, once it's done, it'll be terminated from the caller side.
  //   - Caller is the executor process, which uses async interface to
  //   communicate with delegate process.
  int rv = mkbp_event.Wait(5000);
  if (rv != 1) {
    PLOG(ERROR) << "Failed to poll fingerprint event after 5 seconds";
    std::move(callback).Run(std::move(result),
                            "Failed to poll fingerprint event after 5 seconds");
    return;
  }

  ec::GetProtocolInfoCommand ec_protocol_cmd;
  if (!ec_protocol_cmd.RunWithMultipleAttempts(cros_fd.get(), 2)) {
    std::move(callback).Run(std::move(result),
                            "Failed to get EC protocol info");
    return;
  }

  uint32_t size = result->width * result->height;
  if (size == 0) {
    std::move(callback).Run(std::move(result), "Frame size is zero");
    return;
  }

  auto fp_frame_command = ec::FpFrameCommand::Create(
      FP_FRAME_INDEX_RAW_IMAGE, size, ec_protocol_cmd.MaxReadBytes());
  if (!fp_frame_command) {
    std::move(callback).Run(std::move(result),
                            "Failed to create fingerprint frame command");
    return;
  }

  if (!fp_frame_command->Run(cros_fd.get())) {
    std::move(callback).Run(std::move(result),
                            "Failed to get fingerprint frame");
    return;
  }

  result->frame = std::move(*fp_frame_command->frame());

  if (result->width * result->height != result->frame.size()) {
    std::move(callback).Run(std::move(result),
                            "Frame size is not equal to width * height");
    return;
  }

  std::move(callback).Run(std::move(result), std::nullopt);
}

void DelegateImpl::GetFingerprintInfo(GetFingerprintInfoCallback callback) {
  auto result = mojom::FingerprintInfoResult::New();
  auto cros_fd = base::ScopedFD(open(path::kCrosFpDevice, O_RDWR));

  ec::GetVersionCommand version;
  if (!version.Run(cros_fd.get())) {
    std::move(callback).Run(std::move(result),
                            "Failed to get fingerprint version");
    return;
  }

  result->rw_fw = version.Image() == EC_IMAGE_RW;

  std::move(callback).Run(std::move(result), std::nullopt);
}

void DelegateImpl::SetLedColor(mojom::LedName name,
                               mojom::LedColor color,
                               SetLedColorCallback callback) {
  auto ec_led_id = ToEcLedId(name);
  if (ec_led_id == EC_LED_ID_COUNT) {
    std::move(callback).Run("Unknown LED name");
    return;
  }
  auto ec_led_color = ToEcLedColor(color);
  if (ec_led_color == EC_LED_COLOR_COUNT) {
    std::move(callback).Run("Unknown LED color");
    return;
  }

  auto cros_fd = base::ScopedFD(open(ec::kCrosEcPath, O_RDWR));

  ec::LedControlQueryCommand query_cmd(ec_led_id);
  if (!query_cmd.Run(cros_fd.get())) {
    std::move(callback).Run("Failed to query the LED brightness range");
    return;
  }

  uint8_t max_brightness = query_cmd.BrightnessRange()[ec_led_color];
  if (max_brightness == 0) {
    std::move(callback).Run("Unsupported color");
    return;
  }

  std::array<uint8_t, EC_LED_COLOR_COUNT> brightness = {};
  brightness[ec_led_color] = max_brightness;

  ec::LedControlSetCommand set_cmd(ec_led_id, brightness);
  if (!set_cmd.Run(cros_fd.get())) {
    std::move(callback).Run("Failed to set the LED color");
    return;
  }

  std::move(callback).Run(std::nullopt);
}

void DelegateImpl::ResetLedColor(mojom::LedName name,
                                 ResetLedColorCallback callback) {
  auto ec_led_id = ToEcLedId(name);
  if (ec_led_id == EC_LED_ID_COUNT) {
    std::move(callback).Run("Unknown LED name");
    return;
  }

  auto cros_fd = base::ScopedFD(open(ec::kCrosEcPath, O_RDWR));

  ec::LedControlAutoCommand cmd(ec_led_id);
  if (!cmd.Run(cros_fd.get())) {
    std::move(callback).Run("Failed to reset LED color");
    return;
  }

  std::move(callback).Run(std::nullopt);
}

void DelegateImpl::MonitorAudioJack(
    mojo::PendingRemote<mojom::AudioJackObserver> observer) {
  auto delegate = std::make_unique<EvdevAudioJackObserver>(std::move(observer));
  // Long-run method. The following object keeps alive until the process
  // terminates.
  new EvdevUtil(std::move(delegate));
}

void DelegateImpl::MonitorTouchpad(
    mojo::PendingRemote<mojom::TouchpadObserver> observer) {
  auto delegate = std::make_unique<EvdevTouchpadObserver>(std::move(observer));
  // Long-run method. The following object keeps alive until the process
  // terminates.
  new EvdevUtil(std::move(delegate));
}

void DelegateImpl::FetchBootPerformance(FetchBootPerformanceCallback callback) {
  std::move(callback).Run(FetchBootPerformanceInfo());
}

void DelegateImpl::MonitorTouchscreen(
    mojo::PendingRemote<mojom::TouchscreenObserver> observer) {
  auto delegate =
      std::make_unique<EvdevTouchscreenObserver>(std::move(observer));
  // Long-run method. The following object keeps alive until the process
  // terminates.
  new EvdevUtil(std::move(delegate));
}

void DelegateImpl::MonitorStylusGarage(
    mojo::PendingRemote<mojom::StylusGarageObserver> observer) {
  auto delegate =
      std::make_unique<EvdevStylusGarageObserver>(std::move(observer));
  // Long-run method. The following object keeps alive until the process
  // terminates.
  new EvdevUtil(std::move(delegate));
}

void DelegateImpl::MonitorStylus(
    mojo::PendingRemote<mojom::StylusObserver> observer) {
  auto delegate = std::make_unique<EvdevStylusObserver>(std::move(observer));
  // Long-run method. The following object keeps alive until the process
  // terminates.
  new EvdevUtil(std::move(delegate));
}

void DelegateImpl::GetLidAngle(GetLidAngleCallback callback) {
  auto cros_fd = base::ScopedFD(open(ec::kCrosEcPath, O_RDWR));
  ec::MotionSenseCommandLidAngle cmd;
  if (!cmd.Run(cros_fd.get())) {
    // TODO(b/274524224): Remove the below invalid EC result handling.
    if (cmd.Result() == 1 || cmd.Result() == 3) {
      std::move(callback).Run(LID_ANGLE_UNRELIABLE);
      return;
    }
    std::move(callback).Run(std::nullopt);
    return;
  }
  std::move(callback).Run(cmd.LidAngle());
}

void DelegateImpl::GetPsr(GetPsrCallback callback) {
  auto mei_path = base::FilePath(psr::kCrosMeiPath);
  auto fd = base::ScopedFD(
      HANDLE_EINTR(open(mei_path.value().c_str(), O_RDWR, S_IRUSR | S_IWUSR)));
  auto result = mojom::PsrInfo::New();

  if (!fd.is_valid()) {
    std::move(callback).Run(std::move(result), "Failed to open /dev/mei0.");
    return;
  }

  auto psr_cmd = psr::PsrCmd(fd.get());
  psr::PsrHeciResp psr_res;
  if (!psr_cmd.GetPlatformServiceRecord(psr_res)) {
    std::move(callback).Run(std::move(result), "Get PSR is not working.");
    return;
  }

  if (psr_res.log_state == diagnostics::psr::LogState::kNotStarted) {
    std::move(callback).Run(std::move(result), "PSR has not been started.");
    return;
  }

  if (psr_res.psr_version.major != psr::kPsrVersionMajor ||
      psr_res.psr_version.minor != psr::kPsrVersionMinor) {
    std::move(callback).Run(std::move(result), "Requires PSR 2.0 version.");
    return;
  }

  result->log_state = LogStateToMojo(psr_res.log_state);
  result->uuid =
      psr_cmd.IdToHexString(psr_res.psr_record.uuid, psr::kUuidLength);
  result->upid =
      psr_cmd.IdToHexString(psr_res.psr_record.upid, psr::kUpidLength);
  result->log_start_date = psr_res.psr_record.genesis_info.genesis_date;
  result->oem_name =
      reinterpret_cast<char*>(psr_res.psr_record.genesis_info.oem_info);
  result->oem_make =
      reinterpret_cast<char*>(psr_res.psr_record.genesis_info.oem_make_info);
  result->oem_model =
      reinterpret_cast<char*>(psr_res.psr_record.genesis_info.oem_model_info);
  result->manufacture_country = reinterpret_cast<char*>(
      psr_res.psr_record.genesis_info.manufacture_country);
  result->oem_data =
      reinterpret_cast<char*>(psr_res.psr_record.genesis_info.oem_data);
  result->uptime_seconds =
      psr_res.psr_record.ledger_info
          .ledger_counter[psr::LedgerCounterIndex::kS0Seconds];
  result->s5_counter = psr_res.psr_record.ledger_info
                           .ledger_counter[psr::LedgerCounterIndex::kS0ToS5];
  result->s4_counter = psr_res.psr_record.ledger_info
                           .ledger_counter[psr::LedgerCounterIndex::kS0ToS4];
  result->s3_counter = psr_res.psr_record.ledger_info
                           .ledger_counter[psr::LedgerCounterIndex::kS0ToS3];
  result->warm_reset_counter =
      psr_res.psr_record.ledger_info
          .ledger_counter[psr::LedgerCounterIndex::kWarmReset];

  for (int i = 0; i < psr_res.psr_record.events_count; ++i) {
    auto event = psr_res.psr_record.events_info[i];
    auto tmp_event = mojom::PsrEvent::New();

    switch (event.event_type) {
      case psr::EventType::kLogStart:
        tmp_event->type = mojom::PsrEvent::EventType::kLogStart;
        break;
      case psr::EventType::kLogEnd:
        tmp_event->type = mojom::PsrEvent::EventType::kLogEnd;
        break;
      case psr::EventType::kPrtcFailure:
        tmp_event->type = mojom::PsrEvent::EventType::kPrtcFailure;
        break;
      case psr::EventType::kCsmeRecovery:
        tmp_event->type = mojom::PsrEvent::EventType::kCsmeRecovery;
        break;
      case psr::EventType::kSvnIncrease:
        tmp_event->type = mojom::PsrEvent::EventType::kSvnIncrease;
        break;
    }

    tmp_event->time = event.timestamp;
    tmp_event->data = event.data;
    result->events.push_back(std::move(tmp_event));
  }

  std::move(callback).Run(std::move(result), std::nullopt);
}

void DelegateImpl::GetAmountOfFreeDiskSpace(
    const std::string& path, GetAmountOfFreeDiskSpaceCallback callback) {
  const auto free_space =
      base::SysInfo::AmountOfFreeDiskSpace(base::FilePath(path));
  if (free_space < 0) {
    std::move(callback).Run(std::nullopt);
    return;
  }
  std::move(callback).Run(free_space);
}

void DelegateImpl::GetConnectedHdmiConnectors(
    GetConnectedHdmiConnectorsCallback callback) {
  base::flat_map<uint32_t, mojom::ExternalDisplayInfoPtr> hdmi_connectors;
  DisplayUtil display_util;
  if (!display_util.Initialize()) {
    std::move(callback).Run(std::move(hdmi_connectors),
                            "Failed to initialize DisplayUtil");
    return;
  }

  std::vector<uint32_t> hdmi_connector_ids = display_util.GetHdmiConnectorIDs();

  for (auto connector_id : hdmi_connector_ids) {
    hdmi_connectors[connector_id] =
        display_util.GetExternalDisplayInfo(connector_id);
  }

  std::move(callback).Run(std::move(hdmi_connectors), std::nullopt);
}

void DelegateImpl::GetPrivacyScreenInfo(GetPrivacyScreenInfoCallback callback) {
  DisplayUtil display_util;
  if (!display_util.Initialize()) {
    std::move(callback).Run(false, false, "Failed to initialize DisplayUtil");
    return;
  }

  std::optional<uint32_t> connector_id =
      display_util.GetEmbeddedDisplayConnectorID();
  if (!connector_id.has_value()) {
    std::move(callback).Run(false, false, "Failed to find valid display");
    return;
  }
  bool supported, enabled;
  display_util.FillPrivacyScreenInfo(connector_id.value(), &supported,
                                     &enabled);

  std::move(callback).Run(supported, enabled, std::nullopt);
}

void DelegateImpl::FetchDisplayInfo(FetchDisplayInfoCallback callback) {
  std::move(callback).Run(GetDisplayInfo());
}

void DelegateImpl::MonitorPowerButton(
    mojo::PendingRemote<mojom::PowerButtonObserver> observer) {
  auto delegate =
      std::make_unique<EvdevPowerButtonObserver>(std::move(observer));
  // Long-run method. The following object keeps alive until the process
  // terminates.
  new EvdevUtil(std::move(delegate));
}

void DelegateImpl::RunPrimeSearch(uint32_t duration_sec,
                                  uint64_t max_num,
                                  RunPrimeSearchCallback callback) {
  base::TimeTicks end_time =
      base::TimeTicks::Now() + base::Seconds(duration_sec);
  max_num = std::clamp(max_num, static_cast<uint64_t>(2),
                       PrimeNumberSearchDelegate::kMaxPrimeNumber);

  auto prime_number_search =
      std::make_unique<diagnostics::PrimeNumberSearchDelegate>(max_num);

  while (base::TimeTicks::Now() < end_time) {
    if (!prime_number_search->Run()) {
      std::move(callback).Run(false);
      return;
    }
  }

  std::move(callback).Run(true);
}

void DelegateImpl::MonitorVolumeButton(
    mojo::PendingRemote<mojom::VolumeButtonObserver> observer) {
  auto delegate =
      std::make_unique<EvdevVolumeButtonObserver>(std::move(observer));
  // Long-run method. The following object keeps alive until the process
  // terminates.
  new EvdevUtil(std::move(delegate), /*allow_multiple_devices*/ true);
}

}  // namespace diagnostics
