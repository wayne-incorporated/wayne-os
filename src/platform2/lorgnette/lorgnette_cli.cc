// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/command_line.h>
#include <base/containers/contains.h>
#include <base/files/file.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/functional/callback_helpers.h>
#include <base/json/json_writer.h>
#include <base/run_loop.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/task/single_thread_task_executor.h>
#include <base/values.h>
#include <brillo/errors/error.h>
#include <brillo/flag_helper.h>
#include <brillo/process/process.h>
#include <brillo/syslog_logging.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <lorgnette/proto_bindings/lorgnette_service.pb.h>
#include <re2/re2.h>

#include "lorgnette/cli/discovery_handler.h"
#include "lorgnette/cli/scan_handler.h"
#include "lorgnette/dbus-proxies.h"
#include "lorgnette/guess_source.h"

using lorgnette::cli::DiscoveryHandler;
using lorgnette::cli::ScanHandler;
using org::chromium::lorgnette::ManagerProxy;

namespace {

std::optional<std::vector<std::string>> ReadLines(base::File* file) {
  std::string buf(1 << 20, '\0');
  int read = file->ReadAtCurrentPos(&buf[0], buf.size());
  if (read < 0) {
    PLOG(ERROR) << "Reading from file failed";
    return std::nullopt;
  }

  buf.resize(read);
  return base::SplitString(buf, "\n", base::KEEP_WHITESPACE,
                           base::SPLIT_WANT_ALL);
}

std::optional<lorgnette::CancelScanResponse> CancelScan(
    ManagerProxy* manager, const std::string& uuid) {
  lorgnette::CancelScanRequest request;
  request.set_scan_uuid(uuid);

  brillo::ErrorPtr error;
  lorgnette::CancelScanResponse response;
  if (!manager->CancelScan(request, &response, &error)) {
    LOG(ERROR) << "Cancelling scan failed: " << error->GetMessage();
    return std::nullopt;
  }

  return response;
}

std::optional<std::vector<std::string>> ListScanners(ManagerProxy* manager) {
  brillo::ErrorPtr error;
  lorgnette::ListScannersResponse scanner_list;
  if (!manager->ListScanners(&scanner_list, &error)) {
    LOG(ERROR) << "ListScanners failed: " << error->GetMessage();
    return std::nullopt;
  }

  std::vector<std::string> scanner_names;
  std::cout << "SANE scanners: " << std::endl;
  for (const lorgnette::ScannerInfo& scanner : scanner_list.scanners()) {
    std::cout << scanner.name() << ": " << scanner.manufacturer() << " "
              << scanner.model() << "(" << scanner.type() << ")" << std::endl;
    scanner_names.push_back(scanner.name());
  }
  std::cout << scanner_list.scanners_size() << " SANE scanners found."
            << std::endl;
  return scanner_names;
}

std::optional<lorgnette::ScannerCapabilities> GetScannerCapabilities(
    ManagerProxy* manager, const std::string& scanner_name) {
  brillo::ErrorPtr error;
  lorgnette::ScannerCapabilities capabilities;
  if (!manager->GetScannerCapabilities(scanner_name, &capabilities, &error)) {
    LOG(ERROR) << "GetScannerCapabilities failed: " << error->GetMessage();
    return std::nullopt;
  }

  return capabilities;
}

// RoundThousandth will round the input number at the thousandth place
double RoundThousandth(double num) {
  return round(num * 1000) / 1000.0;
}

void PrintScannerCapabilities(
    const lorgnette::ScannerCapabilities& capabilities) {
  std::cout << "--- Capabilities ---" << std::endl;

  std::cout << "Sources:" << std::endl;
  for (const lorgnette::DocumentSource& source : capabilities.sources()) {
    std::cout << "\t" << source.name() << " ("
              << lorgnette::SourceType_Name(source.type()) << ")" << std::endl;
    if (source.has_area()) {
      std::cout << "\t\t" << RoundThousandth(source.area().width())
                << "mm wide by " << RoundThousandth(source.area().height())
                << "mm tall" << std::endl;
    }
    std::cout << "\t\tResolutions:" << std::endl;
    for (uint32_t resolution : source.resolutions()) {
      std::cout << "\t\t\t" << resolution << std::endl;
    }
    std::cout << "\t\tColor Modes:" << std::endl;
    for (int color_mode : source.color_modes()) {
      std::cout << "\t\t\t" << lorgnette::ColorMode_Name(color_mode)
                << std::endl;
    }
  }
}

std::optional<std::vector<std::string>> ReadAirscanOutput(
    brillo::ProcessImpl* discover) {
  base::File discover_output(discover->GetPipe(STDOUT_FILENO));
  if (!discover_output.IsValid()) {
    LOG(ERROR) << "Failed to open airscan-discover output pipe";
    return std::nullopt;
  }

  int ret = discover->Wait();
  if (ret != 0) {
    LOG(ERROR) << "airscan-discover exited with error " << ret;
    return std::nullopt;
  }

  std::optional<std::vector<std::string>> lines = ReadLines(&discover_output);
  if (!lines.has_value()) {
    LOG(ERROR) << "Failed to read output from airscan-discover";
    return std::nullopt;
  }

  std::vector<std::string> scanner_names;
  for (const std::string& line : lines.value()) {
    // Line format is something like:
    // "  Lexmark MB2236adwe = https://192.168.0.15:443/eSCL/, eSCL"
    // We use '.*\S' to match the device name instead of '\S+' so that we can
    // properly match internal spaces. Since the regex is greedy by default,
    // we need to end the match group with '\S' so that it doesn't capture any
    // trailing white-space.
    std::string name, url;
    if (RE2::FullMatch(line, R"(\s*(.*\S)\s+=\s+(.+), eSCL)", &name, &url)) {
      // Replace ':' with '_' because sane-airscan uses ':' to delimit the
      // fields of the device_string (i.e."airscan:escl:MyPrinter:[url]) passed
      // to it.
      base::ReplaceChars(name, ":", "_", &name);
      scanner_names.push_back("airscan:escl:" + name + ":" + url);
    }
  }

  return scanner_names;
}

class ScanRunner {
 public:
  explicit ScanRunner(ManagerProxy* manager) : manager_(manager) {}

  void SetResolution(uint32_t resolution) { resolution_ = resolution; }
  void SetSource(lorgnette::SourceType source) { source_ = source; }
  void SetScanRegion(const lorgnette::ScanRegion& region) { region_ = region; }
  void SetColorMode(lorgnette::ColorMode color_mode) {
    color_mode_ = color_mode;
  }
  void SetImageFormat(lorgnette::ImageFormat image_format) {
    image_format_ = image_format;
  }

  bool RunScanner(const std::string& scanner,
                  const std::string& output_pattern);

 private:
  ManagerProxy* manager_;  // Not owned.
  uint32_t resolution_;
  lorgnette::SourceType source_;
  std::optional<lorgnette::ScanRegion> region_;
  lorgnette::ColorMode color_mode_;
  lorgnette::ImageFormat image_format_;
};

bool ScanRunner::RunScanner(const std::string& scanner,
                            const std::string& output_pattern) {
  std::cout << "Getting device capabilities for " << scanner << std::endl;
  std::optional<lorgnette::ScannerCapabilities> capabilities =
      GetScannerCapabilities(manager_, scanner);
  if (!capabilities.has_value())
    return false;
  PrintScannerCapabilities(capabilities.value());

  if (!base::Contains(capabilities->resolutions(), resolution_)) {
    // Many scanners will round the requested resolution to the nearest
    // supported resolution. We will attempt to scan with the given resolution
    // since it may still work.
    LOG(WARNING) << "Requested scan resolution " << resolution_
                 << " is not supported by the selected scanner. "
                    "Attempting to request it anyways.";
  }

  std::optional<lorgnette::DocumentSource> scan_source;
  for (const lorgnette::DocumentSource& source : capabilities->sources()) {
    if (source.type() == source_) {
      scan_source = source;
      break;
    }
  }

  if (!scan_source.has_value()) {
    LOG(ERROR) << "Requested scan source "
               << lorgnette::SourceType_Name(source_)
               << " is not supported by the selected scanner";
    return false;
  }

  if (region_.has_value()) {
    if (!scan_source->has_area()) {
      LOG(ERROR)
          << "Requested scan source does not support specifying a scan region.";
      return false;
    }

    if (region_->top_left_x() == -1.0)
      region_->set_top_left_x(0.0);
    if (region_->top_left_y() == -1.0)
      region_->set_top_left_y(0.0);
    if (region_->bottom_right_x() == -1.0)
      region_->set_bottom_right_x(scan_source->area().width());
    if (region_->bottom_right_y() == -1.0)
      region_->set_bottom_right_y(scan_source->area().height());
  }

  if (!base::Contains(capabilities->color_modes(), color_mode_)) {
    LOG(ERROR) << "Requested scan source does not support color mode "
               << ColorMode_Name(color_mode_);
    return false;
  }

  // Implicitly uses this thread's executor as defined in main.
  base::RunLoop run_loop;
  ScanHandler handler(run_loop.QuitClosure(), manager_, scanner,
                      output_pattern);

  if (!handler.WaitUntilConnected()) {
    return false;
  }

  std::cout << "Scanning from " << scanner << std::endl;

  if (!handler.StartScan(resolution_, scan_source.value(), region_, color_mode_,
                         image_format_)) {
    return false;
  }

  // Will run until the ScanHandler runs this RunLoop's quit_closure.
  run_loop.Run();
  return true;
}

std::vector<std::string> BuildScannerList(ManagerProxy* manager) {
  // Start the airscan-discover process immediately since it can be slightly
  // long-running. We read the output later after we've gotten a scanner list
  // from lorgnette.
  brillo::ProcessImpl discover;
  discover.AddArg("/usr/bin/airscan-discover");
  discover.RedirectUsingPipe(STDOUT_FILENO, false);
  if (!discover.Start()) {
    LOG(ERROR) << "Failed to start airscan-discover process";
    return {};
  }

  std::cout << "Getting scanner list." << std::endl;
  std::optional<std::vector<std::string>> sane_scanners = ListScanners(manager);
  if (!sane_scanners.has_value())
    return {};

  std::optional<std::vector<std::string>> airscan_scanners =
      ReadAirscanOutput(&discover);
  if (!airscan_scanners.has_value())
    return {};

  std::vector<std::string> scanners = std::move(sane_scanners.value());
  scanners.insert(scanners.end(), airscan_scanners.value().begin(),
                  airscan_scanners.value().end());
  return scanners;
}

bool DoScan(std::unique_ptr<ManagerProxy> manager,
            uint32_t scan_resolution,
            lorgnette::SourceType source_type,
            const lorgnette::ScanRegion& region,
            lorgnette::ColorMode color_mode,
            lorgnette::ImageFormat image_format,
            bool scan_from_all_scanners,
            const std::string& forced_scanner,
            const std::string& output_pattern) {
  ScanRunner runner(manager.get());
  runner.SetResolution(scan_resolution);
  runner.SetSource(source_type);
  runner.SetColorMode(color_mode);
  runner.SetImageFormat(image_format);

  if (region.top_left_x() != -1.0 || region.top_left_y() != -1.0 ||
      region.bottom_right_x() != -1.0 || region.bottom_right_y() != -1.0) {
    runner.SetScanRegion(region);
  }

  if (!forced_scanner.empty()) {
    return runner.RunScanner(forced_scanner, output_pattern);
  }

  std::vector<std::string> scanners = BuildScannerList(manager.get());
  if (scanners.empty()) {
    return false;
  }

  std::cout << "Choose a scanner (blank to quit):" << std::endl;
  for (int i = 0; i < scanners.size(); i++) {
    std::cout << i << ". " << scanners[i] << std::endl;
  }

  if (!scan_from_all_scanners) {
    int index = -1;
    std::cout << "> ";
    std::cin >> index;
    if (std::cin.fail()) {
      return 0;
    }

    std::string scanner = scanners[index];
    return runner.RunScanner(scanner, output_pattern);
  }

  std::cout << "Scanning from all scanners." << std::endl;
  std::vector<std::string> successes;
  std::vector<std::string> failures;
  for (const std::string& scanner : scanners) {
    if (runner.RunScanner(scanner, output_pattern)) {
      successes.push_back(scanner);
    } else {
      failures.push_back(scanner);
    }
  }
  std::cout << "Successful scans:" << std::endl;
  for (const std::string& scanner : successes) {
    std::cout << "  " << scanner << std::endl;
  }
  std::cout << "Failed scans:" << std::endl;
  for (const std::string& scanner : failures) {
    std::cout << "  " << scanner << std::endl;
  }

  return true;
}

std::string ScannerCapabilitiesToJson(
    const lorgnette::ScannerCapabilities& caps) {
  base::Value::Dict caps_dict;

  for (const lorgnette::DocumentSource& source : caps.sources()) {
    base::Value::Dict source_dict;
    source_dict.Set("Name", source.name());
    if (source.has_area()) {
      base::Value::Dict area_dict;
      area_dict.Set("Width", RoundThousandth(source.area().width()));
      area_dict.Set("Height", RoundThousandth(source.area().height()));
      source_dict.Set("ScannableArea", std::move(area_dict));
    }
    base::Value::List resolution_list;
    for (const uint32_t resolution : source.resolutions()) {
      resolution_list.Append(static_cast<int>(resolution));
    }
    source_dict.Set("Resolutions", std::move(resolution_list));
    base::Value::List color_mode_list;
    for (const int color_mode : source.color_modes()) {
      color_mode_list.Append(lorgnette::ColorMode_Name(color_mode));
    }
    source_dict.Set("ColorModes", std::move(color_mode_list));

    caps_dict.Set(lorgnette::SourceType_Name(source.type()),
                  std::move(source_dict));
  }

  std::string json;
  base::JSONWriter::Write(caps_dict, &json);
  return json;
}

lorgnette::SetDebugConfigResponse SetLorgnetteDebug(ManagerProxy* manager,
                                                    bool enabled) {
  lorgnette::SetDebugConfigRequest request;
  request.set_enabled(enabled);
  lorgnette::SetDebugConfigResponse response;
  brillo::ErrorPtr error;
  if (!manager->SetDebugConfig(request, &response, &error)) {
    LOG(ERROR) << "Failed to call SetDebugConfig: " << error->GetMessage();
  }
  return response;
}

}  // namespace

int main(int argc, char** argv) {
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty |
                  brillo::kLogHeader);

  // Scan options.
  DEFINE_uint32(scan_resolution, 100,
                "The scan resolution to request from the scanner");
  DEFINE_string(scan_source, "Platen",
                "The scan source to use for the scanner, (e.g. Platen, ADF "
                "Simplex, ADF Duplex)");
  DEFINE_string(color_mode, "Color",
                "The color mode to use for the scanner, (e.g. Color, Grayscale,"
                "Lineart)");
  DEFINE_bool(all, false,
              "Loop through all detected scanners instead of prompting.");
  DEFINE_double(top_left_x, -1.0,
                "Top-left X position of the scan region (mm)");
  DEFINE_double(top_left_y, -1.0,
                "Top-left Y position of the scan region (mm)");
  DEFINE_double(bottom_right_x, -1.0,
                "Bottom-right X position of the scan region (mm)");
  DEFINE_double(bottom_right_y, -1.0,
                "Bottom-right Y position of the scan region (mm)");
  DEFINE_string(output, "/tmp/scan-%s_page%n.%e",
                "Pattern for output files. If present, %s will be replaced "
                "with the scanner name, %n will be replaced with the page "
                "number, and %e will be replaced with the extension matching "
                "the selected image format.");
  DEFINE_string(image_format, "PNG",
                "Image format for the output file (PNG or JPG)");
  DEFINE_bool(debug, false,
              "Enable lorgnette debug logging for this operation.  The "
              "previous debug value will be restored when lorgnette_cli "
              "exits.");

  // Cancel Scan options
  DEFINE_string(uuid, "", "UUID of the scan job to cancel.");

  // General scanner operations options.
  DEFINE_string(scanner, "",
                "Name of the scanner whose capabilities are requested.");

  brillo::FlagHelper::Init(argc, argv,
                           "lorgnette_cli, command-line interface to "
                           "Chromium OS Scanning Daemon");

  const std::vector<std::string>& args =
      base::CommandLine::ForCurrentProcess()->GetArgs();
  if (args.size() != 1 ||
      (args[0] != "scan" && args[0] != "cancel_scan" && args[0] != "list" &&
       args[0] != "get_json_caps" && args[0] != "discover")) {
    std::cerr << "usage: lorgnette_cli [list|scan|cancel_scan|get_json_caps] "
                 "[FLAGS...]"
              << std::endl;
    return 1;
  }
  const std::string& command = args[0];

  // Create a task executor for this thread. This will automatically be bound
  // to the current thread so that it is usable by other code for posting tasks.
  base::SingleThreadTaskExecutor executor(base::MessagePumpType::IO);

  // Create a FileDescriptorWatcher instance for this thread. The libbase D-Bus
  // bindings use this internally via thread-local storage, but do not properly
  // instantiate it.
  base::FileDescriptorWatcher watcher(executor.task_runner());

  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::Bus> bus(new dbus::Bus(options));
  auto manager =
      std::make_unique<ManagerProxy>(bus, lorgnette::kManagerServiceName);

  base::ScopedClosureRunner debug_cleanup;
  if (FLAGS_debug) {
    lorgnette::SetDebugConfigResponse response =
        SetLorgnetteDebug(manager.get(), true);
    if (!response.old_enabled()) {
      debug_cleanup.ReplaceClosure(base::BindOnce(
          [](ManagerProxy* manager) { SetLorgnetteDebug(manager, false); },
          manager.get()));
    }
    if (!response.success()) {
      LOG(WARNING) << "Failed to enable lorgnette debugging.";
    }
  }

  if (command == "scan") {
    if (!FLAGS_uuid.empty()) {
      LOG(ERROR) << "--uuid flag is not supported in scan mode.";
      return 1;
    }

    std::optional<lorgnette::SourceType> source_type =
        GuessSourceType(FLAGS_scan_source);

    if (!source_type.has_value()) {
      LOG(ERROR)
          << "Unknown source type: \"" << FLAGS_scan_source
          << "\". Supported values are \"Platen\",\"ADF\", \"ADF Simplex\""
             ", and \"ADF Duplex\"";
      return 1;
    }

    lorgnette::ScanRegion region;
    region.set_top_left_x(FLAGS_top_left_x);
    region.set_top_left_y(FLAGS_top_left_y);
    region.set_bottom_right_x(FLAGS_bottom_right_x);
    region.set_bottom_right_y(FLAGS_bottom_right_y);

    std::string color_mode_string = base::ToLowerASCII(FLAGS_color_mode);
    lorgnette::ColorMode color_mode;
    if (color_mode_string == "color") {
      color_mode = lorgnette::MODE_COLOR;
    } else if (color_mode_string == "grayscale" ||
               color_mode_string == "gray") {
      color_mode = lorgnette::MODE_GRAYSCALE;
    } else if (color_mode_string == "lineart" || color_mode_string == "bw") {
      color_mode = lorgnette::MODE_LINEART;
    } else {
      LOG(ERROR) << "Unknown color mode: \"" << color_mode_string
                 << "\". Supported values are \"Color\", \"Grayscale\", and "
                    "\"Lineart\"";
      return 1;
    }

    std::string image_format_string = base::ToLowerASCII(FLAGS_image_format);
    lorgnette::ImageFormat image_format;
    if (image_format_string == "png") {
      image_format = lorgnette::IMAGE_FORMAT_PNG;
    } else if (image_format_string == "jpg") {
      image_format = lorgnette::IMAGE_FORMAT_JPEG;
    } else {
      LOG(ERROR) << "Unknown image format: \"" << image_format_string
                 << "\". Supported values are \"PNG\" and \"JPG\"";
      return 1;
    }

    bool success = DoScan(std::move(manager), FLAGS_scan_resolution,
                          source_type.value(), region, color_mode, image_format,
                          FLAGS_all, FLAGS_scanner, FLAGS_output);
    return success ? 0 : 1;
  } else if (command == "list") {
    std::vector<std::string> scanners = BuildScannerList(manager.get());

    std::cout << "Detected scanners:" << std::endl;
    for (int i = 0; i < scanners.size(); i++) {
      std::cout << scanners[i] << std::endl;
    }

  } else if (command == "discover") {
    std::cout << "Discovering scanners: " << std::endl;
    base::RunLoop run_loop;
    DiscoveryHandler handler(run_loop.QuitClosure(), manager.get());
    if (!handler.WaitUntilConnected()) {
      LOG(ERROR) << "Failed to set up ScannerListChangedSignal handler";
      return 1;
    }
    if (!handler.StartDiscovery()) {
      LOG(ERROR) << "Failed to start discovery";
      return 1;
    }
    run_loop.Run();
    return 0;

  } else if (command == "cancel_scan") {
    if (FLAGS_uuid.empty()) {
      LOG(ERROR) << "Must specify scan uuid to cancel using --uuid=[...]";
      return 1;
    }

    std::optional<lorgnette::CancelScanResponse> response =
        CancelScan(manager.get(), FLAGS_uuid);
    if (!response.has_value())
      return 1;

    if (!response->success()) {
      LOG(ERROR) << "Failed to cancel scan: " << response->failure_reason();
      return 1;
    }
    return 0;
  } else if (command == "get_json_caps") {
    if (FLAGS_scanner.empty()) {
      LOG(ERROR) << "Must specify scanner to get capabilities";
      return 1;
    }

    std::optional<lorgnette::ScannerCapabilities> capabilities =
        GetScannerCapabilities(manager.get(), FLAGS_scanner);
    if (!capabilities.has_value()) {
      LOG(ERROR) << "Received null capabilities from lorgnette";
      return 1;
    }

    std::cout << ScannerCapabilitiesToJson(capabilities.value());
    return 0;
  }
}
