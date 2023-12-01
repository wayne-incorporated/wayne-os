// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lorgnette/manager.h"

#include <inttypes.h>
#include <setjmp.h>

#include <algorithm>
#include <memory>
#include <optional>
#include <utility>

#include <base/bits.h>
#include <base/check.h>
#include <base/containers/contains.h>
#include <base/files/file.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <base/strings/string_util.h>
#include <base/time/time.h>
#include <chromeos/dbus/service_constants.h>
#include <libusb.h>
#include <re2/re2.h>

#include "lorgnette/constants.h"
#include "lorgnette/daemon.h"
#include "lorgnette/enums.h"
#include "lorgnette/epson_probe.h"
#include "lorgnette/firewall_manager.h"
#include "lorgnette/guess_source.h"
#include "lorgnette/image_readers/image_reader.h"
#include "lorgnette/image_readers/jpeg_reader.h"
#include "lorgnette/image_readers/png_reader.h"
#include "lorgnette/ippusb_device.h"
#include "lorgnette/uuid_util.h"
#include "permission_broker/dbus-proxies.h"

using std::string;

namespace lorgnette {

namespace {

constexpr base::TimeDelta kDefaultProgressSignalInterval =
    base::Milliseconds(20);

std::string SerializeError(const brillo::ErrorPtr& error_ptr) {
  std::string message;
  const brillo::Error* error = error_ptr.get();
  while (error) {
    // Format error string as "domain/code:message".
    if (!message.empty())
      message += ';';
    message +=
        error->GetDomain() + '/' + error->GetCode() + ':' + error->GetMessage();
    error = error->GetInnerError();
  }
  return message;
}

// Create a ScopedFILE which refers to a copy of |fd|.
base::ScopedFILE SetupOutputFile(brillo::ErrorPtr* error,
                                 const base::ScopedFD& fd) {
  base::ScopedFILE file;
  // Dup fd since fdclose() on file will also close the contained fd.
  base::ScopedFD fd_copy(dup(fd.get()));
  if (fd_copy.get() < 0) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "Could not duplicate output FD");
    return file;
  }

  file = base::ScopedFILE(fdopen(fd_copy.get(), "w"));
  if (!file) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "Failed to open outfd");
    return file;
  }
  // Release |fd_copy| since it is owned by |file| now.
  (void)fd_copy.release();
  return file;
}

// Uses |firewall_manager| to request port access if |device_name| corresponds
// to a SANE backend that needs the access when connecting to a device. The
// caller should keep the returned object alive as long as port access is
// needed.
std::optional<PortToken> RequestPortAccessIfNeeded(
    const std::string& device_name, FirewallManager* firewall_manager) {
  if (BackendFromDeviceName(device_name) != kPixma)
    return std::nullopt;

  return firewall_manager->RequestPixmaPortAccess();
}

// Converts the |status| to a ScanFailureMode.
ScanFailureMode GetScanFailureMode(const SANE_Status& status) {
  switch (status) {
    case SANE_STATUS_DEVICE_BUSY:
      return SCAN_FAILURE_MODE_DEVICE_BUSY;
    case SANE_STATUS_JAMMED:
      return SCAN_FAILURE_MODE_ADF_JAMMED;
    case SANE_STATUS_NO_DOCS:
      return SCAN_FAILURE_MODE_ADF_EMPTY;
    case SANE_STATUS_COVER_OPEN:
      return SCAN_FAILURE_MODE_FLATBED_OPEN;
    case SANE_STATUS_IO_ERROR:
      return SCAN_FAILURE_MODE_IO_ERROR;
    default:
      return SCAN_FAILURE_MODE_UNKNOWN;
  }
}

// This function is the same as Chromium's GetScanJobFailureReason function
// in src/chrome/browser/ash/scanning/scan_service.cc
// DO NOT MAKE CHANGES TO THIS FUNCTION without first changing the original
// one.
//
// Returns a ScanJobFailureReason corresponding to the given `failure_mode`.
ScanJobFailureReason GetScanJobFailureReason(
    const ScanFailureMode failure_mode) {
  switch (failure_mode) {
    case SCAN_FAILURE_MODE_UNKNOWN:
      return ScanJobFailureReason::kUnknownScannerError;
    case SCAN_FAILURE_MODE_DEVICE_BUSY:
      return ScanJobFailureReason::kDeviceBusy;
    case SCAN_FAILURE_MODE_ADF_JAMMED:
      return ScanJobFailureReason::kAdfJammed;
    case SCAN_FAILURE_MODE_ADF_EMPTY:
      return ScanJobFailureReason::kAdfEmpty;
    case SCAN_FAILURE_MODE_FLATBED_OPEN:
      return ScanJobFailureReason::kFlatbedOpen;
    case SCAN_FAILURE_MODE_IO_ERROR:
      return ScanJobFailureReason::kIoError;
    case SCAN_FAILURE_MODE_NO_FAILURE:
      [[fallthrough]];
    case ScanFailureMode_INT_MIN_SENTINEL_DO_NOT_USE_:
      [[fallthrough]];
    case ScanFailureMode_INT_MAX_SENTINEL_DO_NOT_USE_:
      NOTREACHED();
      return ScanJobFailureReason::kUnknownScannerError;
  }
}
}  // namespace

namespace impl {

ColorMode ColorModeFromSaneString(const std::string& mode) {
  if (mode == kScanPropertyModeLineart)
    return MODE_LINEART;
  else if (mode == kScanPropertyModeGray)
    return MODE_GRAYSCALE;
  else if (mode == kScanPropertyModeColor)
    return MODE_COLOR;
  return MODE_UNSPECIFIED;
}

}  // namespace impl

const char Manager::kMetricScanRequested[] = "DocumentScan.ScanRequested";
const char Manager::kMetricScanSucceeded[] = "DocumentScan.ScanSucceeded";
const char Manager::kMetricScanFailed[] = "DocumentScan.ScanFailed";
const char Manager::kMetricScanFailedFailureReason[] =
    "DocumentScan.ScanFailureReason";

Manager::Manager(
    base::RepeatingCallback<void(base::TimeDelta)> activity_callback,
    SaneClient* sane_client)
    : activity_callback_(activity_callback),
      metrics_library_(new MetricsLibrary()),
      sane_client_(sane_client),
      progress_signal_interval_(kDefaultProgressSignalInterval) {}

Manager::~Manager() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
}

void Manager::SetFirewallManager(FirewallManager* firewall_manager) {
  firewall_manager_ = firewall_manager;
}

bool Manager::ListScanners(brillo::ErrorPtr* error,
                           ListScannersResponse* scanner_list_out) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  LOG(INFO) << "Starting ListScanners()";
  if (!sane_client_) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "No connection to SANE");
    return false;
  }

  PortToken token = firewall_manager_->RequestPixmaPortAccess();

  libusb_context* context;
  if (libusb_init(&context) != 0) {
    LOG(ERROR) << "Error initializing libusb";
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "Error initializing libusb");
    return false;
  }
  base::ScopedClosureRunner release_libusb(
      base::BindOnce([](libusb_context* ctxt) { libusb_exit(ctxt); }, context));

  std::vector<ScannerInfo> scanners;
  base::flat_set<std::string> seen_vidpid;
  base::flat_set<std::string> seen_busdev;

  LOG(INFO) << "Finding IPP-USB devices";
  std::vector<ScannerInfo> ippusb_devices = FindIppUsbDevices(context);
  activity_callback_.Run(Daemon::kNormalShutdownTimeout);
  LOG(INFO) << "Found " << ippusb_devices.size() << " possible IPP-USB devices";
  for (const ScannerInfo& scanner : ippusb_devices) {
    std::unique_ptr<SaneDevice> device =
        sane_client_->ConnectToDevice(nullptr, nullptr, scanner.name());
    activity_callback_.Run(Daemon::kNormalShutdownTimeout);

    if (!device) {
      LOG(INFO) << "IPP-USB device doesn't support eSCL: " << scanner.name();
      continue;
    }
    scanners.push_back(scanner);
    std::string vid_str, pid_str;
    int vid = 0, pid = 0;
    if (!RE2::FullMatch(
            scanner.name(),
            "ippusb:[^:]+:[^:]+:([0-9a-fA-F]{4})_([0-9a-fA-F]{4})/.*", &vid_str,
            &pid_str)) {
      LOG(ERROR) << "Problem matching ippusb name for " << scanner.name();
      brillo::Error::AddToPrintf(
          error, FROM_HERE, kDbusDomain, kManagerServiceError,
          "Problem matching ippusb name for '%s'", scanner.name().c_str());
      return false;
    }
    if (!(base::HexStringToInt(vid_str, &vid) &&
          base::HexStringToInt(pid_str, &pid))) {
      LOG(ERROR) << "Problems converting" << vid_str + ":" + pid_str
                 << "information into readable format";
      brillo::Error::AddToPrintf(
          error, FROM_HERE, kDbusDomain, kManagerServiceError,
          "Problems converting '%s':'%s' information into readable format",
          vid_str.c_str(), pid_str.c_str());
      return false;
    }
    seen_vidpid.insert(vid_str + ":" + pid_str);

    // Next open the device to get the bus and dev info.
    // libusb_open_device_with_vid_pid() is the straightforward way to
    // access and open a device given its ScannerInfo
    // It returns the first device matching the vid:pid
    // but doesn't handle multiple devices with same vid:pid but dif bus:dev
    libusb_device_handle* dev_handle =
        libusb_open_device_with_vid_pid(context, vid, pid);
    if (dev_handle) {
      libusb_device* open_dev = libusb_get_device(dev_handle);
      uint8_t bus = libusb_get_bus_number(open_dev);
      uint8_t dev = libusb_get_device_address(open_dev);
      seen_busdev.insert(base::StringPrintf("%03d:%03d", bus, dev));
      libusb_close(dev_handle);
    } else {
      LOG(ERROR) << "Dev handle returned nullptr";
    }
  }

  LOG(INFO) << "Getting list of SANE scanners.";
  std::optional<std::vector<ScannerInfo>> sane_scanners =
      sane_client_->ListDevices(error);
  if (!sane_scanners.has_value()) {
    return false;  // brillo::Error::AddTo already called.
  }
  LOG(INFO) << sane_scanners.value().size() << " scanners returned from SANE";
  // Only add sane scanners that don't have ippusb connection
  RemoveDuplicateScanners(&scanners, seen_vidpid, seen_busdev,
                          sane_scanners.value());
  LOG(INFO) << scanners.size() << " scanners in list after de-duplication";

  activity_callback_.Run(Daemon::kNormalShutdownTimeout);

  LOG(INFO) << "Probing for network scanners";
  std::vector<ScannerInfo> probed_scanners =
      epson_probe::ProbeForScanners(firewall_manager_);
  activity_callback_.Run(Daemon::kNormalShutdownTimeout);
  for (ScannerInfo& scanner : probed_scanners) {
    // Generate an 'epsonds:net:IP_ADDRESS' version of the device name.
    // Epsonds will never connect to an unsupported device, but epson2 will
    // occasionally open a device it fails to operate. If a device responds to
    // both, epsonds should be prioritized.
    std::string epsonds_name = scanner.name();
    epsonds_name = epsonds_name.replace(0, 6, "epsonds");
    std::unique_ptr<SaneDevice> epsonds_device =
        sane_client_->ConnectToDevice(nullptr, nullptr, epsonds_name);
    activity_callback_.Run(Daemon::kNormalShutdownTimeout);
    // If the device works for epsonds, replace the epson2 version the epsonds
    // device name.
    if (epsonds_device) {
      LOG(INFO) << "Found epsonds device for " << epsonds_name;
      scanner.set_name(epsonds_name);
      scanners.push_back(scanner);
      continue;
    }
    std::unique_ptr<SaneDevice> device =
        sane_client_->ConnectToDevice(nullptr, nullptr, scanner.name());
    activity_callback_.Run(Daemon::kNormalShutdownTimeout);
    if (device) {
      scanners.push_back(scanner);
    } else {
      LOG(INFO) << "Got reponse from Epson scanner " << scanner.name()
                << " that isn't usable for scanning.";
    }
  }
  LOG(INFO) << scanners.size() << " scanners in list after network scan";

  ListScannersResponse response;
  for (ScannerInfo& scanner : scanners) {
    if (!ScannerCanBeUsed(scanner)) {
      LOG(INFO) << "Removing blocked scanner from list: " << scanner.name();
      continue;
    }
    *response.add_scanners() = std::move(scanner);
  }

  if (!activity_callback_.is_null())
    activity_callback_.Run(Daemon::kNormalShutdownTimeout);

  *scanner_list_out = std::move(response);
  return true;
}

bool Manager::GetScannerCapabilities(brillo::ErrorPtr* error,
                                     const std::string& device_name,
                                     ScannerCapabilities* capabilities_out) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  LOG(INFO) << "Starting GetScannerCapabilities for device: " << device_name;
  if (!capabilities_out) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "'capabilities_out' must be non-null");
    return false;
  }

  if (!sane_client_) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "No connection to SANE");
    return false;
  }

  std::optional<PortToken> token =
      RequestPortAccessIfNeeded(device_name, firewall_manager_);
  std::unique_ptr<SaneDevice> device =
      sane_client_->ConnectToDevice(error, nullptr, device_name);
  if (!device)
    return false;  // brillo::Error::AddTo already called.

  std::optional<ValidOptionValues> options =
      device->GetValidOptionValues(error);
  if (!options.has_value())
    return false;  // brillo::Error::AddTo already called.

  // These values correspond to the values of Chromium's
  // ScanJobSettingsResolution enum in
  // src/ash/webui/scanning/scanning_uma.h. Before adding values here,
  // add them to the ScanJobSettingsResolution enum.
  const std::vector<uint32_t> supported_resolutions = {75,  100, 150,
                                                       200, 300, 600};

  ScannerCapabilities capabilities;

  // TODO(b/179492658): Once the scan app is using the resolutions from
  // DocumentSource instead of ScannerCapabilities, remove this logic.
  for (const uint32_t resolution : options->resolutions) {
    if (base::Contains(supported_resolutions, resolution))
      capabilities.add_resolutions(resolution);
  }

  for (const DocumentSource& source : options->sources) {
    if (source.type() != SOURCE_UNSPECIFIED) {
      *capabilities.add_sources() = source;
    } else {
      LOG(INFO) << "Ignoring source '" << source.name() << "' of unknown type.";
    }
  }

  // TODO(b/179492658): Once the scan app is using the color modes from
  // DocumentSource instead of ScannerCapabilities, remove this logic.
  for (const std::string& mode : options->color_modes) {
    const ColorMode color_mode = impl::ColorModeFromSaneString(mode);
    if (color_mode != MODE_UNSPECIFIED)
      capabilities.add_color_modes(color_mode);
  }

  if (!activity_callback_.is_null())
    activity_callback_.Run(Daemon::kNormalShutdownTimeout);

  *capabilities_out = std::move(capabilities);
  return true;
}

StartScanResponse Manager::StartScan(const StartScanRequest& request) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  LOG(INFO) << "Starting StartScan";
  StartScanResponse response;
  response.set_state(SCAN_STATE_FAILED);
  response.set_scan_failure_mode(SCAN_FAILURE_MODE_UNKNOWN);

  brillo::ErrorPtr error;
  ScanFailureMode failure_mode(SCAN_FAILURE_MODE_UNKNOWN);
  std::unique_ptr<SaneDevice> device;
  if (!StartScanInternal(&error, &failure_mode, request, &device)) {
    response.set_failure_reason(SerializeError(error));
    response.set_scan_failure_mode(failure_mode);
    return response;
  }

  std::optional<std::string> source_name = device->GetDocumentSource(&error);
  if (!source_name.has_value()) {
    response.set_failure_reason("Failed to get DocumentSource: " +
                                SerializeError(error));
    return response;
  }
  SourceType source_type = GuessSourceType(source_name.value());

  ScanJobState scan_state;
  scan_state.device_name = request.device_name();
  scan_state.device = std::move(device);
  scan_state.format = request.settings().image_format();

  // Set the number of pages based on the source type. If it's ADF, keep
  // scanning until an error is received.
  // Otherwise, stop scanning after one page.
  if (source_type == SOURCE_ADF_SIMPLEX || source_type == SOURCE_ADF_DUPLEX) {
    scan_state.total_pages = std::nullopt;
  } else {
    scan_state.total_pages = 1;
  }

  std::string uuid = GenerateUUID();
  active_scans_.emplace(uuid, std::move(scan_state));
  LOG(INFO) << __func__ << ": Started tracking active scan " << uuid;

  if (!activity_callback_.is_null())
    activity_callback_.Run(Daemon::kExtendedShutdownTimeout);

  response.set_scan_uuid(uuid);
  response.set_state(SCAN_STATE_IN_PROGRESS);
  response.set_scan_failure_mode(SCAN_FAILURE_MODE_NO_FAILURE);
  return response;
}

void Manager::GetNextImage(
    std::unique_ptr<DBusMethodResponse<GetNextImageResponse>> method_response,
    const GetNextImageRequest& request,
    const base::ScopedFD& out_fd) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  GetNextImageResponse response;
  response.set_success(false);
  response.set_scan_failure_mode(SCAN_FAILURE_MODE_UNKNOWN);

  std::string uuid = request.scan_uuid();
  LOG(INFO) << __func__ << ": Starting GetNextImage for " << uuid;
  if (!base::Contains(active_scans_, uuid)) {
    LOG(ERROR) << __func__ << ": No active scan found for " << uuid;
    response.set_failure_reason("No scan job with UUID " + uuid + " found");
    method_response->Return(response);
    return;
  }
  ScanJobState* scan_state = &active_scans_[uuid];

  if (scan_state->in_use) {
    LOG(ERROR) << __func__ << ": Active scan already in use for " << uuid;
    response.set_failure_reason("Scan job with UUID " + uuid +
                                " is currently busy");
    method_response->Return(response);
    return;
  }
  scan_state->in_use = true;
  base::ScopedClosureRunner release_device(base::BindOnce(
      [](base::WeakPtr<Manager> manager, const std::string& uuid) {
        if (manager) {
          auto state_entry = manager->active_scans_.find(uuid);
          if (state_entry == manager->active_scans_.end())
            return;

          ScanJobState& state = state_entry->second;
          if (state.cancelled) {
            manager->SendCancelledSignal(uuid);
            manager->active_scans_.erase(uuid);
            LOG(INFO) << __func__ << ": Stopped tracking cancelled scan "
                      << uuid;
          } else {
            state.in_use = false;
          }
        }
      },
      weak_factory_.GetWeakPtr(), uuid));

  brillo::ErrorPtr error;
  base::ScopedFILE out_file = SetupOutputFile(&error, out_fd);
  if (!out_file) {
    response.set_failure_reason("Failed to setup output file: " +
                                SerializeError(error));
    method_response->Return(response);
    return;
  }

  LOG(INFO) << __func__ << ": Finished prep to save next scanner image for "
            << uuid;
  response.set_success(true);
  response.set_scan_failure_mode(SCAN_FAILURE_MODE_NO_FAILURE);
  method_response->Return(response);

  GetNextImageInternal(uuid, scan_state, std::move(out_file));
}

CancelScanResponse Manager::CancelScan(const CancelScanRequest& request) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CancelScanResponse response;

  std::string uuid = request.scan_uuid();
  LOG(INFO) << __func__ << ": cancel requested for " << uuid;
  if (!base::Contains(active_scans_, uuid)) {
    LOG(WARNING) << __func__ << ": No active scan found for " << uuid;
    response.set_success(false);
    response.set_failure_reason("No scan job with UUID " + uuid + " found");
    return response;
  }

  ScanJobState& scan_state = active_scans_[uuid];
  if (scan_state.cancelled) {
    LOG(INFO) << __func__ << ": Already cancelled scan " << uuid;
    response.set_success(false);
    response.set_failure_reason("Job has already been cancelled");
    return response;
  }

  if (scan_state.in_use) {
    // We can't just delete the scan job entirely since it's in use.
    // sane_cancel() is required to be async safe, so we can call it even if
    // the device is actively being used.
    brillo::ErrorPtr error;
    if (!scan_state.device->CancelScan(&error)) {
      LOG(ERROR) << __func__ << ": Failed to cancel scan " << uuid;
      response.set_success(false);
      response.set_failure_reason("Failed to cancel scan: " +
                                  SerializeError(error));
      return response;
    }
    // When the job that is actively using the device finishes, it will erase
    // the job, freeing the device for use by other scans.
    scan_state.cancelled = true;
    LOG(INFO) << __func__ << ": Cancelled active scan " << uuid;
  } else {
    // If we're not actively using the device, just delete the scan job.
    SendCancelledSignal(uuid);
    active_scans_.erase(uuid);
    LOG(INFO) << __func__ << ": Stopped tracking cancelled scan " << uuid;
  }

  if (!activity_callback_.is_null())
    activity_callback_.Run(Daemon::kNormalShutdownTimeout);

  response.set_success(true);
  return response;
}

void Manager::SetProgressSignalInterval(base::TimeDelta interval) {
  progress_signal_interval_ = interval;
}

void Manager::SetScanStatusChangedSignalSender(StatusSignalSender sender) {
  status_signal_sender_ = sender;
}

void Manager::RemoveDuplicateScanners(
    std::vector<ScannerInfo>* scanners,
    base::flat_set<std::string> seen_vidpid,
    base::flat_set<std::string> seen_busdev,
    const std::vector<ScannerInfo>& sane_scanners) {
  for (const ScannerInfo& scanner : sane_scanners) {
    std::string scanner_name = scanner.name();
    std::string s_vid, s_pid, s_bus, s_dev;
    // Currently pixma only uses 'pixma' as scanner name
    // while epson has multiple formats (i.e. epsonds and epson2)
    if (RE2::FullMatch(scanner_name,
                       "pixma:([0-9a-fA-F]{4})([0-9a-fA-F]{4})_[0-9a-fA-F]*",
                       &s_vid, &s_pid)) {
      s_vid = base::ToLowerASCII(s_vid);
      s_pid = base::ToLowerASCII(s_pid);
      if (seen_vidpid.contains(s_vid + ":" + s_pid)) {
        continue;
      }
    } else if (RE2::FullMatch(scanner_name,
                              "epson(?:2|ds)?:libusb:([0-9]{3}):([0-9]{3})",
                              &s_bus, &s_dev)) {
      if (seen_busdev.contains(s_bus + ":" + s_dev)) {
        continue;
      }
    }
    scanners->push_back(scanner);
  }
}

bool Manager::ScannerCanBeUsed(const ScannerInfo& scanner) {
  if (base::StartsWith(scanner.name(), "pixma:")) {
    // Canon MF 260 can't be used with pixma (b/233012341).
    if (base::StartsWith(scanner.name(), "pixma:MF260_") ||
        scanner.model().find("MF260") != std::string::npos ||
        scanner.model().find("MF 260") != std::string::npos) {
      return false;
    }
  }

  return true;
}

bool Manager::StartScanInternal(brillo::ErrorPtr* error,
                                ScanFailureMode* failure_mode,
                                const StartScanRequest& request,
                                std::unique_ptr<SaneDevice>* device_out) {
  LOG(INFO) << "Starting StartScanInternal for device: "
            << request.device_name();
  if (!device_out) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "device_out cannot be null");
    return false;
  }

  if (request.device_name() == "") {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "A device name must be provided");
    return false;
  }

  if (!sane_client_) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "No connection to SANE");
    return false;
  }

  std::optional<PortToken> token =
      RequestPortAccessIfNeeded(request.device_name(), firewall_manager_);

  // If ConnectToDevice() fails without updating |status|, |status| will be
  // converted to an unknown failure mode.
  SANE_Status status = SANE_STATUS_GOOD;
  std::unique_ptr<SaneDevice> device =
      sane_client_->ConnectToDevice(error, &status, request.device_name());
  if (!device) {
    if (failure_mode)
      *failure_mode = GetScanFailureMode(status);

    return false;  // brillo::Error::AddTo already called.
  }

  ReportScanRequested(request.device_name());

  const ScanSettings& settings = request.settings();

  if (settings.resolution() != 0) {
    LOG(INFO) << "User requested resolution: " << settings.resolution();
    if (!device->SetScanResolution(error, settings.resolution())) {
      return false;  // brillo::Error::AddTo already called.
    }

    std::optional<int> resolution = device->GetScanResolution(error);
    if (!resolution.has_value()) {
      return false;  // brillo::Error::AddTo already called.
    }
    LOG(INFO) << "Device is using resolution: " << resolution.value();
  }

  if (!settings.source_name().empty()) {
    LOG(INFO) << "User requested document source: '" << settings.source_name()
              << "'";
    if (!device->SetDocumentSource(error, settings.source_name())) {
      return false;  // brillo::Error::AddTo already called.
    }
  }

  if (settings.color_mode() != MODE_UNSPECIFIED) {
    LOG(INFO) << "User requested color mode: '"
              << ColorMode_Name(settings.color_mode()) << "'";
    if (!device->SetColorMode(error, settings.color_mode())) {
      return false;  // brillo::Error::AddTo already called.
    }
  }

  if (settings.has_scan_region()) {
    const ScanRegion& region = settings.scan_region();
    LOG(INFO) << "User requested scan region: top-left (" << region.top_left_x()
              << ", " << region.top_left_y() << "), bottom-right ("
              << region.bottom_right_x() << ", " << region.bottom_right_y()
              << ")";
    if (!device->SetScanRegion(error, region)) {
      return false;  // brillo::Error::AddTo already called.
    }
  }

  status = device->StartScan(error);
  if (status != SANE_STATUS_GOOD) {
    brillo::Error::AddToPrintf(error, FROM_HERE, kDbusDomain,
                               kManagerServiceError, "Failed to start scan: %s",
                               sane_strstatus(status));
    if (failure_mode)
      *failure_mode = GetScanFailureMode(status);

    ReportScanFailed(request.device_name(), GetScanFailureMode(status));
    return false;
  }

  *device_out = std::move(device);
  return true;
}

void Manager::GetNextImageInternal(const std::string& uuid,
                                   ScanJobState* scan_state,
                                   base::ScopedFILE out_file) {
  brillo::ErrorPtr error;
  ScanFailureMode failure_mode(SCAN_FAILURE_MODE_UNKNOWN);
  ScanState result =
      RunScanLoop(&error, &failure_mode, scan_state, std::move(out_file), uuid);
  LOG(INFO) << __func__ << ": Scanner page read loop for " << uuid
            << " ended with status " << ScanState_Name(result);
  switch (result) {
    case SCAN_STATE_PAGE_COMPLETED:
      // Do nothing.
      break;
    case SCAN_STATE_CANCELLED:
      SendCancelledSignal(uuid);
      active_scans_.erase(uuid);
      LOG(INFO) << __func__ << ": Stopped tracking cancelled scan " << uuid;
      return;
    default:
      LOG(ERROR) << "Unexpected scan state: " << ScanState_Name(result);
      [[fallthrough]];
    case SCAN_STATE_FAILED:
      ReportScanFailed(scan_state->device_name, failure_mode);
      SendFailureSignal(uuid, SerializeError(error), failure_mode);
      active_scans_.erase(uuid);
      LOG(INFO) << __func__ << ": Stopped tracking failed scan " << uuid;
      return;
  }

  bool scanned_all_pages =
      scan_state->total_pages.has_value() &&
      scan_state->current_page == scan_state->total_pages.value();

  bool adf_scan = !scan_state->total_pages.has_value();

  SANE_Status status = SANE_STATUS_GOOD;
  if (!scanned_all_pages) {
    // Here, we call StartScan again in order to prepare for scanning the next
    // page of the scan. Additionally, if we're scanning from the ADF, this
    // lets us know if we've run out of pages so that we can signal scan
    // completion.
    status = scan_state->device->StartScan(&error);
    LOG(INFO) << __func__ << ": Start of next page scan returned status "
              << sane_strstatus(status);
  }

  bool scan_complete =
      scanned_all_pages || (status == SANE_STATUS_NO_DOCS && adf_scan);

  SendStatusSignal(uuid, SCAN_STATE_PAGE_COMPLETED, scan_state->current_page,
                   100, !scan_complete);

  // Reset activity timer back to normal now that the page is done.  If there
  // are more pages, we'll extend it again below.
  if (!activity_callback_.is_null())
    activity_callback_.Run(Daemon::kNormalShutdownTimeout);

  if (scan_complete) {
    ReportScanSucceeded(scan_state->device_name);
    SendStatusSignal(uuid, SCAN_STATE_COMPLETED, scan_state->current_page, 100,
                     false);
    LOG(INFO) << __func__ << ": Completed image scan and conversion.";

    active_scans_.erase(uuid);
    LOG(INFO) << __func__ << ": Stopped tracking completed scan " << uuid;

    return;
  }

  if (status == SANE_STATUS_CANCELLED) {
    SendCancelledSignal(uuid);
    active_scans_.erase(uuid);
    LOG(INFO) << __func__ << ": Stopped tracking cancelled scan " << uuid;
    return;
  } else if (status != SANE_STATUS_GOOD) {
    // The scan failed.
    brillo::Error::AddToPrintf(&error, FROM_HERE, kDbusDomain,
                               kManagerServiceError, "Failed to start scan: %s",
                               sane_strstatus(status));
    failure_mode = GetScanFailureMode(status);
    ReportScanFailed(scan_state->device_name, failure_mode);
    SendFailureSignal(uuid, SerializeError(error), failure_mode);
    active_scans_.erase(uuid);
    LOG(INFO) << __func__ << ": Stopped tracking failed scan " << uuid;
    return;
  }

  scan_state->current_page++;
  if (!activity_callback_.is_null())
    activity_callback_.Run(Daemon::kExtendedShutdownTimeout);
}

ScanState Manager::RunScanLoop(brillo::ErrorPtr* error,
                               ScanFailureMode* failure_mode,
                               ScanJobState* scan_state,
                               base::ScopedFILE out_file,
                               const std::string& scan_uuid) {
  DCHECK(scan_state);

  SaneDevice* device = scan_state->device.get();
  std::optional<ScanParameters> params = device->GetScanParameters(error);
  if (!params.has_value()) {
    return SCAN_STATE_FAILED;  // brillo::Error::AddTo already called.
  }

  // Get resolution value in DPI so that we can record it in the image.
  brillo::ErrorPtr resolution_error;
  std::optional<int> resolution = device->GetScanResolution(&resolution_error);
  if (!resolution.has_value()) {
    LOG(WARNING) << __func__ << ": Failed to get scan resolution: "
                 << SerializeError(resolution_error);
  }

  std::unique_ptr<ImageReader> image_reader;
  switch (scan_state->format) {
    case IMAGE_FORMAT_PNG: {
      image_reader = PngReader::Create(error, params.value(), resolution,
                                       std::move(out_file));
      break;
    }
    case IMAGE_FORMAT_JPEG: {
      image_reader = JpegReader::Create(error, params.value(), resolution,
                                        std::move(out_file));
      break;
    }
    default: {
      brillo::Error::AddToPrintf(
          error, FROM_HERE, kDbusDomain, kManagerServiceError,
          "Unrecognized image format: %d", scan_state->format);
      return SCAN_STATE_FAILED;
    }
  }

  if (!image_reader) {
    brillo::Error::AddToPrintf(
        error, FROM_HERE, kDbusDomain, kManagerServiceError,
        "Failed to create image reader for format: %d", scan_state->format);
    return SCAN_STATE_FAILED;
  }

  base::TimeTicks last_progress_sent_time = base::TimeTicks::Now();
  uint32_t last_progress_value = 0;
  size_t rows_written = 0;
  const size_t kMaxBuffer = 1024 * 1024;
  const size_t buffer_length = std::max(static_cast<size_t>(base::bits::AlignUp(
                                            params->bytes_per_line, 4 * 1024)),
                                        kMaxBuffer);
  std::vector<uint8_t> image_buffer(buffer_length, '\0');
  // The offset within image_buffer to read to. This will be used within the
  // loop for when we've read a partial image line and need to track data that
  // is saved between loop iterations.
  //
  // We maintain the invariant at the start of each loop iteration that indices
  // [0, buffer_offset) hold previously read data.
  size_t buffer_offset = 0;
  while (true) {
    // Get next chunk of scan data from the device.
    size_t read = 0;
    SANE_Status result =
        device->ReadScanData(error, image_buffer.data() + buffer_offset,
                             image_buffer.size() - buffer_offset, &read);

    // Handle non-standard results.
    if (result == SANE_STATUS_GOOD) {
      if (rows_written >= params->lines) {
        brillo::Error::AddTo(
            error, FROM_HERE, kDbusDomain, kManagerServiceError,
            "Whole image has been written, but scanner is still sending data.");
        return SCAN_STATE_FAILED;
      }
    } else if (result == SANE_STATUS_EOF) {
      break;
    } else if (result == SANE_STATUS_CANCELLED) {
      brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                           "Scan job has been cancelled.");
      LOG(INFO) << __func__ << ": Scan job has been cancelled.";
      return SCAN_STATE_CANCELLED;
    } else {
      brillo::Error::AddToPrintf(
          error, FROM_HERE, kDbusDomain, kManagerServiceError,
          "Reading scan data failed: %s", sane_strstatus(result));
      if (failure_mode)
        *failure_mode = GetScanFailureMode(result);

      return SCAN_STATE_FAILED;
    }

    // Write as many lines of the image as we can with the data we've received.
    // Indices [buffer_offset, buffer_offset + read) hold the data we just read.
    size_t bytes_available = buffer_offset + read;
    size_t bytes_converted = 0;
    while (bytes_available - bytes_converted >= params->bytes_per_line &&
           rows_written < params->lines) {
      if (!image_reader->ReadRow(error,
                                 image_buffer.data() + bytes_converted)) {
        return SCAN_STATE_FAILED;  // brillo::Error::AddTo already called.
      }
      bytes_converted += params->bytes_per_line;
      rows_written++;
      uint32_t progress = rows_written * 100 / params->lines;
      base::TimeTicks now = base::TimeTicks::Now();
      if (progress != last_progress_value &&
          now - last_progress_sent_time >= progress_signal_interval_) {
        SendStatusSignal(scan_uuid, SCAN_STATE_IN_PROGRESS,
                         scan_state->current_page, progress, false);
        last_progress_value = progress;
        last_progress_sent_time = now;
      }
    }

    // Shift any unconverted data in image_buffer to the start of image_buffer.
    size_t remaining_bytes = bytes_available - bytes_converted;
    memmove(image_buffer.data(), image_buffer.data() + bytes_converted,
            remaining_bytes);
    buffer_offset = remaining_bytes;
  }

  if (rows_written < params->lines || buffer_offset != 0) {
    brillo::Error::AddToPrintf(error, FROM_HERE, kDbusDomain,
                               kManagerServiceError,
                               "Received incomplete scan data, %zu unused "
                               "bytes, %zu of %d rows written",
                               buffer_offset, rows_written, params->lines);
    return SCAN_STATE_FAILED;
  }

  if (!image_reader->Finalize(error)) {
    return SCAN_STATE_FAILED;  // brillo::Error::AddTo already called.
  }

  return SCAN_STATE_PAGE_COMPLETED;
}

void Manager::ReportScanRequested(const std::string& device_name) {
  DocumentScanSaneBackend backend = BackendFromDeviceName(device_name);
  metrics_library_->SendEnumToUMA(kMetricScanRequested, backend);
}

void Manager::ReportScanSucceeded(const std::string& device_name) {
  DocumentScanSaneBackend backend = BackendFromDeviceName(device_name);
  metrics_library_->SendEnumToUMA(kMetricScanSucceeded, backend);
}

void Manager::ReportScanFailed(const std::string& device_name,
                               const ScanFailureMode failure_mode) {
  DocumentScanSaneBackend backend = BackendFromDeviceName(device_name);
  metrics_library_->SendEnumToUMA(kMetricScanFailed, backend);
  metrics_library_->SendEnumToUMA(kMetricScanFailedFailureReason,
                                  GetScanJobFailureReason(failure_mode));
}

void Manager::SendStatusSignal(const std::string& uuid,
                               const ScanState state,
                               const int page,
                               const int progress,
                               const bool more_pages) {
  ScanStatusChangedSignal signal;
  signal.set_scan_uuid(uuid);
  signal.set_state(state);
  signal.set_page(page);
  signal.set_progress(progress);
  signal.set_more_pages(more_pages);
  status_signal_sender_.Run(signal);
}

void Manager::SendCancelledSignal(const std::string& uuid) {
  ScanStatusChangedSignal signal;
  signal.set_scan_uuid(uuid);
  signal.set_state(SCAN_STATE_CANCELLED);
  status_signal_sender_.Run(signal);
}

void Manager::SendFailureSignal(const std::string& uuid,
                                const std::string& failure_reason,
                                const ScanFailureMode failure_mode) {
  ScanStatusChangedSignal signal;
  signal.set_scan_uuid(uuid);
  signal.set_state(SCAN_STATE_FAILED);
  signal.set_failure_reason(failure_reason);
  signal.set_scan_failure_mode(failure_mode);
  status_signal_sender_.Run(signal);
}

}  // namespace lorgnette
