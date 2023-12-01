// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lorgnette/sane_client_impl.h"

#include <optional>

#include <base/check.h>
#include <base/containers/contains.h>
#include <base/containers/flat_map.h>
#include <base/logging.h>
#include <chromeos/dbus/service_constants.h>
#include <re2/re2.h>
#include <sane/saneopts.h>
#include <sane-airscan/airscan.h>

#include "lorgnette/dbus_adaptors/org.chromium.lorgnette.Manager.h"
#include "lorgnette/guess_source.h"

static const char* kDbusDomain = brillo::errors::dbus::kDomain;
static const char* kRightJustification = "right";
static const char* kCenterJustification = "center";

namespace lorgnette {

namespace {

DocumentSource CreateDocumentSource(const std::string& name) {
  DocumentSource source;
  source.set_name(name);
  std::optional<SourceType> type = GuessSourceType(name);
  if (type.has_value()) {
    source.set_type(type.value());
  }
  return source;
}

ColorMode ColorModeFromSaneString(const std::string& mode) {
  if (mode == kScanPropertyModeLineart)
    return MODE_LINEART;
  else if (mode == kScanPropertyModeGray)
    return MODE_GRAYSCALE;
  else if (mode == kScanPropertyModeColor)
    return MODE_COLOR;
  return MODE_UNSPECIFIED;
}

}  // namespace

// static
std::unique_ptr<SaneClientImpl> SaneClientImpl::Create() {
  SANE_Status status = sane_init(nullptr, nullptr);
  if (status != SANE_STATUS_GOOD) {
    LOG(ERROR) << "Unable to initialize SANE";
    return nullptr;
  }

  // Cannot use make_unique() with a private constructor.
  return std::unique_ptr<SaneClientImpl>(new SaneClientImpl());
}

SaneClientImpl::~SaneClientImpl() {
  sane_exit();
}

std::optional<std::vector<ScannerInfo>> SaneClientImpl::ListDevices(
    brillo::ErrorPtr* error) {
  base::AutoLock auto_lock(lock_);
  const SANE_Device** device_list;
  SANE_Status status = sane_get_devices(&device_list, SANE_FALSE);
  if (status != SANE_STATUS_GOOD) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "Unable to get device list from SANE");
    return std::nullopt;
  }

  return DeviceListToScannerInfo(device_list);
}

// static
std::optional<std::vector<ScannerInfo>> SaneClientImpl::DeviceListToScannerInfo(
    const SANE_Device** device_list) {
  if (!device_list) {
    LOG(ERROR) << "'device_list' cannot be NULL";
    return std::nullopt;
  }

  std::unordered_set<std::string> names;
  std::vector<ScannerInfo> scanners;
  for (int i = 0; device_list[i]; i++) {
    const SANE_Device* dev = device_list[i];
    if (!dev->name || strcmp(dev->name, "") == 0)
      continue;

    if (names.count(dev->name) != 0) {
      LOG(ERROR) << "Duplicate device name: " << dev->name;
      return std::nullopt;
    }
    names.insert(dev->name);

    ScannerInfo info;
    info.set_name(dev->name);
    info.set_manufacturer(dev->vendor ? dev->vendor : "");
    info.set_model(dev->model ? dev->model : "");
    info.set_type(dev->type ? dev->type : "");
    scanners.push_back(info);
  }
  return scanners;
}

SaneClientImpl::SaneClientImpl()
    : open_devices_(std::make_shared<DeviceSet>()) {}

std::unique_ptr<SaneDevice> SaneClientImpl::ConnectToDeviceInternal(
    brillo::ErrorPtr* error,
    SANE_Status* sane_status,
    const std::string& device_name) {
  LOG(INFO) << "Creating connection to device: " << device_name;
  base::AutoLock auto_lock(lock_);
  SANE_Handle handle;
  {
    base::AutoLock auto_lock(open_devices_->first);
    if (open_devices_->second.count(device_name) != 0) {
      brillo::Error::AddToPrintf(
          error, FROM_HERE, kDbusDomain, kManagerServiceError,
          "Device '%s' is currently in-use", device_name.c_str());
      return nullptr;
    }

    SANE_Status status = sane_open(device_name.c_str(), &handle);
    if (status != SANE_STATUS_GOOD) {
      brillo::Error::AddToPrintf(error, FROM_HERE, kDbusDomain,
                                 kManagerServiceError,
                                 "Unable to open device '%s': %s",
                                 device_name.c_str(), sane_strstatus(status));
      if (sane_status)
        *sane_status = status;

      return nullptr;
    }

    open_devices_->second.insert(device_name);
  }

  // Cannot use make_unique() with a private constructor.
  auto device = std::unique_ptr<SaneDeviceImpl>(
      new SaneDeviceImpl(handle, device_name, open_devices_));
  device->LoadOptions(error);
  return device;
}

SaneDeviceImpl::~SaneDeviceImpl() {
  if (handle_) {
    // If a scan is running, this will call sane_cancel() first.
    sane_close(handle_);
  }
  base::AutoLock auto_lock(open_devices_->first);
  open_devices_->second.erase(name_);
}

std::optional<ValidOptionValues> SaneDeviceImpl::GetValidOptionValues(
    brillo::ErrorPtr* error) {
  if (!handle_) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "No scanner connected");
    return std::nullopt;
  }

  ValidOptionValues values;

  // TODO(b/179492658): Once the scan app is using the resolutions from
  // DocumentSource instead of ScannerCapabilities, remove this logic.
  std::optional<std::vector<uint32_t>> resolutions = GetResolutions(error);
  if (!resolutions.has_value()) {
    return std::nullopt;  // brillo::Error::AddTo already called.
  }
  values.resolutions = std::move(resolutions.value());

  if (options_.count(kSource) != 0) {
    int index = options_.at(kSource).GetIndex();
    const SANE_Option_Descriptor* descriptor =
        sane_get_option_descriptor(handle_, index);
    if (!descriptor) {
      brillo::Error::AddToPrintf(
          error, FROM_HERE, kDbusDomain, kManagerServiceError,
          "Unable to get source option at index %d", index);
      return std::nullopt;
    }

    std::optional<std::vector<std::string>> source_names =
        GetValidStringOptionValues(error, *descriptor);
    if (!source_names.has_value()) {
      brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                           "Failed to get valid values for sources setting");
      return std::nullopt;
    }

    for (const std::string& source_name : source_names.value()) {
      values.sources.push_back(CreateDocumentSource(source_name));
    }
  } else {
    // The backend doesn't expose any source options; add a special default
    // source using our special source name. We'll calculate the scannable area
    // for this default source later.
    values.sources.push_back(
        CreateDocumentSource(kUnspecifiedDefaultSourceName));
  }

  if (options_.count(kTopLeftX) != 0 && options_.count(kTopLeftY) != 0 &&
      options_.count(kBottomRightX) != 0 &&
      options_.count(kBottomRightY) != 0) {
    DCHECK(!values.sources.empty())
        << "Sources is missing default source value.";
    // We can get the capabilities for each scan source by setting the
    // document source to each possible value, and then calculating the area
    // for that source and retrieving the source's supported resolutions and
    // color modes.
    std::optional<std::string> initial_source = GetDocumentSource(error);
    if (!initial_source.has_value()) {
      return std::nullopt;  // brillo::Error::AddTo already called.
    }

    for (DocumentSource& source : values.sources) {
      if (!SetDocumentSource(error, source.name())) {
        return std::nullopt;  // brillo::Error::AddTo already called.
      }

      std::optional<ScannableArea> area = CalculateScannableArea(error);
      if (!area.has_value()) {
        return std::nullopt;  // brillo::Error::AddTo already called.
      }

      *source.mutable_area() = std::move(area.value());

      std::optional<std::vector<uint32_t>> resolutions = GetResolutions(error);
      if (!resolutions.has_value()) {
        return std::nullopt;  // brillo::Error::AddTo already called.
      }

      // These values correspond to the values of Chromium's
      // ScanJobSettingsResolution enum in
      // src/ash/webui/scanning/scanning_uma.h. Before adding values
      // here, add them to the ScanJobSettingsResolution enum.
      const std::vector<uint32_t> supported_resolutions = {75,  100, 150,
                                                           200, 300, 600};

      for (const uint32_t resolution : resolutions.value()) {
        if (base::Contains(supported_resolutions, resolution)) {
          source.add_resolutions(resolution);
        }
      }

      std::optional<std::vector<std::string>> color_modes =
          GetColorModes(error);
      if (!color_modes.has_value()) {
        return std::nullopt;  // brillo::Error::AddTo already called.
      }

      for (const std::string& mode : color_modes.value()) {
        const ColorMode color_mode = ColorModeFromSaneString(mode);
        if (color_mode != MODE_UNSPECIFIED) {
          source.add_color_modes(color_mode);
        }
      }
    }

    // Restore DocumentSource to its initial value.
    if (!SetDocumentSource(error, initial_source.value())) {
      return std::nullopt;  // brillo::Error::AddTo already called.
    }
  }

  // TODO(b/179492658): Once the scan app is using the color modes from
  // DocumentSource instead of ScannerCapabilities, remove this logic.
  std::optional<std::vector<std::string>> color_modes = GetColorModes(error);
  if (!color_modes.has_value()) {
    return std::nullopt;  // brillo::Error::AddTo already called.
  }
  values.color_modes = std::move(color_modes.value());

  return values;
}

std::optional<int> SaneDeviceImpl::GetScanResolution(brillo::ErrorPtr* error) {
  return GetOption<int>(error, kResolution);
}

bool SaneDeviceImpl::SetScanResolution(brillo::ErrorPtr* error,
                                       int resolution) {
  return SetOption(error, kResolution, resolution);
}

std::optional<std::string> SaneDeviceImpl::GetDocumentSource(
    brillo::ErrorPtr* error) {
  return GetOption<std::string>(error, kSource);
}

bool SaneDeviceImpl::SetDocumentSource(brillo::ErrorPtr* error,
                                       const std::string& source_name) {
  return SetOption(error, kSource, source_name);
}

std::optional<ColorMode> SaneDeviceImpl::GetColorMode(brillo::ErrorPtr* error) {
  std::optional<std::string> sane_color_mode =
      GetOption<std::string>(error, kScanMode);
  if (!sane_color_mode.has_value())
    return std::nullopt;  // brillo::Error::AddTo already called.

  return ColorModeFromSaneString(sane_color_mode.value());
}

bool SaneDeviceImpl::SetColorMode(brillo::ErrorPtr* error,
                                  ColorMode color_mode) {
  std::string mode_string = "";
  switch (color_mode) {
    case MODE_LINEART:
      mode_string = kScanPropertyModeLineart;
      break;
    case MODE_GRAYSCALE:
      mode_string = kScanPropertyModeGray;
      break;
    case MODE_COLOR:
      mode_string = kScanPropertyModeColor;
      break;
    default:
      brillo::Error::AddToPrintf(error, FROM_HERE, kDbusDomain,
                                 kManagerServiceError, "Invalid color mode: %s",
                                 ColorMode_Name(color_mode).c_str());
      return false;
  }

  return SetOption(error, kScanMode, mode_string);
}

bool SaneDeviceImpl::SetScanRegion(brillo::ErrorPtr* error,
                                   const ScanRegion& region) {
  // If the scanner exposes page-width and page-height options, these need to be
  // set before the main scan region coordinates will be accepted.
  if (base::Contains(options_, kPageWidth)) {
    double page_width = region.bottom_right_x() - region.top_left_x();
    if (!SetOption(error, kPageWidth, page_width)) {
      return false;  // brillo::Error::AddTo already called.
    }
  }
  if (base::Contains(options_, kPageHeight)) {
    double page_height = region.bottom_right_y() - region.top_left_y();
    if (!SetOption(error, kPageHeight, page_height)) {
      return false;  // brillo::Error::AddTo already called.
    }
  }

  // Get the offsets for X and Y so that if the device's coordinate system
  // doesn't start at (0, 0), we can translate the requested region into the
  // device's coordinates. We provide the appearance to the user that all
  // region options start at (0, 0).
  std::optional<double> x_offset = GetOptionOffset(error, kTopLeftX);
  if (!x_offset.has_value())
    return false;  // brillo::Error::AddTo already called.

  // Get ADF justification offset modification if justification is specified.
  std::optional<uint32_t> justification_x_offset =
      GetJustificationXOffset(region, error);
  if (!justification_x_offset.has_value()) {
    return false;  // brillo::Error::AddTo already called.
  }
  x_offset.value() += justification_x_offset.value();

  std::optional<double> y_offset = GetOptionOffset(error, kTopLeftY);
  if (!y_offset.has_value())
    return false;  // brillo::Error::AddTo already called.

  const base::flat_map<ScanOption, double> values{
      {kTopLeftX, region.top_left_x() + x_offset.value()},
      {kTopLeftY, region.top_left_y() + y_offset.value()},
      {kBottomRightX, region.bottom_right_x() + x_offset.value()},
      {kBottomRightY, region.bottom_right_y() + y_offset.value()},
  };

  for (const auto& kv : values) {
    ScanOption option_name = kv.first;
    double value = kv.second;

    if (!SetOption(error, option_name, value)) {
      return false;  // brillo::Error::AddTo already called.
    }
  }
  return true;
}

SANE_Status SaneDeviceImpl::StartScan(brillo::ErrorPtr* error) {
  if (scan_running_) {
    // If we haven't already reached EOF for the current image frame and we
    // try to start acquiring a new frame, SANE will fail with an unhelpful
    // error. This error message makes it a little clearer what's happening.
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "Scan is already in progress");
    return SANE_STATUS_DEVICE_BUSY;
  }

  SANE_Status status = sane_start(handle_);
  if (status == SANE_STATUS_GOOD) {
    scan_running_ = true;
  }

  return status;
}

std::optional<ScanParameters> SaneDeviceImpl::GetScanParameters(
    brillo::ErrorPtr* error) {
  if (!handle_) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "No scanner connected");
    return std::nullopt;
  }

  SANE_Parameters params;
  SANE_Status status = sane_get_parameters(handle_, &params);
  if (status != SANE_STATUS_GOOD) {
    brillo::Error::AddToPrintf(
        error, FROM_HERE, kDbusDomain, kManagerServiceError,
        "Failed to read scan parameters: %s", sane_strstatus(status));
    return std::nullopt;
  }

  ScanParameters parameters;
  switch (params.format) {
    case SANE_FRAME_GRAY:
      parameters.format = kGrayscale;
      break;
    case SANE_FRAME_RGB:
      parameters.format = kRGB;
      break;
    default:
      brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                           "Unsupported scan frame format");
      return std::nullopt;
  }

  parameters.bytes_per_line = params.bytes_per_line;
  parameters.pixels_per_line = params.pixels_per_line;
  parameters.lines = params.lines;
  parameters.depth = params.depth;
  return parameters;
}

SANE_Status SaneDeviceImpl::ReadScanData(brillo::ErrorPtr* error,
                                         uint8_t* buf,
                                         size_t count,
                                         size_t* read_out) {
  if (!handle_) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "No scanner connected");
    return SANE_STATUS_INVAL;
  }

  if (!scan_running_) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "No scan in progress");
    return SANE_STATUS_INVAL;
  }

  if (!buf || !read_out) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "'buf' and 'read' pointers cannot be null");
    return SANE_STATUS_INVAL;
  }
  SANE_Int read = 0;
  SANE_Status status = sane_read(handle_, buf, count, &read);
  // The SANE API requires that a non GOOD status will return 0 bytes read.
  *read_out = read;
  if (status != SANE_STATUS_GOOD) {
    scan_running_ = false;
  }
  return status;
}

bool SaneDeviceImpl::CancelScan(brillo::ErrorPtr* error) {
  if (!handle_) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "No scanner connected");
    return false;
  }

  scan_running_ = false;
  sane_cancel(handle_);
  return true;
}

// static
std::optional<std::vector<std::string>>
SaneDeviceImpl::GetValidStringOptionValues(brillo::ErrorPtr* error,
                                           const SANE_Option_Descriptor& opt) {
  if (opt.constraint_type != SANE_CONSTRAINT_STRING_LIST) {
    brillo::Error::AddToPrintf(
        error, FROM_HERE, kDbusDomain, kManagerServiceError,
        "Invalid option constraint type %d", opt.constraint_type);
    return std::nullopt;
  }

  std::vector<std::string> values;
  for (int i = 0; opt.constraint.string_list[i]; i++) {
    values.push_back(opt.constraint.string_list[i]);
  }

  return values;
}

// static
std::optional<std::vector<uint32_t>> SaneDeviceImpl::GetValidIntOptionValues(
    brillo::ErrorPtr* error, const SANE_Option_Descriptor& opt) {
  std::vector<uint32_t> values;
  if (opt.constraint_type == SANE_CONSTRAINT_WORD_LIST) {
    int num_values = opt.constraint.word_list[0];
    for (int i = 1; i <= num_values; i++) {
      SANE_Word w = opt.constraint.word_list[i];
      int value = opt.type == SANE_TYPE_FIXED ? SANE_UNFIX(w) : w;
      values.push_back(value);
    }
  } else if (opt.constraint_type == SANE_CONSTRAINT_RANGE) {
    const SANE_Range* range = opt.constraint.range;
    for (int i = range->min; i <= range->max; i += range->quant) {
      const int value = opt.type == SANE_TYPE_FIXED ? SANE_UNFIX(i) : i;
      values.push_back(value);
    }
  } else {
    brillo::Error::AddToPrintf(
        error, FROM_HERE, kDbusDomain, kManagerServiceError,
        "Invalid option constraint type %d", opt.constraint_type);
    return std::nullopt;
  }

  return values;
}

// static
std::optional<OptionRange> SaneDeviceImpl::GetOptionRange(
    brillo::ErrorPtr* error, const SANE_Option_Descriptor& opt) {
  if (opt.constraint_type != SANE_CONSTRAINT_RANGE) {
    brillo::Error::AddToPrintf(
        error, FROM_HERE, kDbusDomain, kManagerServiceError,
        "Expected range constraint for option %s", opt.name);
    return std::nullopt;
  }

  OptionRange option_range;
  const SANE_Range* range = opt.constraint.range;
  switch (opt.type) {
    case SANE_TYPE_INT:
      option_range.start = range->min;
      option_range.size = range->max - range->min;
      return option_range;
    case SANE_TYPE_FIXED:
      option_range.start = SANE_UNFIX(range->min);
      option_range.size = SANE_UNFIX(range->max - range->min);
      return option_range;
    default:
      brillo::Error::AddToPrintf(
          error, FROM_HERE, kDbusDomain, kManagerServiceError,
          "Unexpected option type %d for option %s", opt.type, opt.name);
      return std::nullopt;
  }
}

SaneOption::SaneOption(const SANE_Option_Descriptor& opt, int index) {
  name_ = opt.name;
  index_ = index;
  type_ = opt.type;
  if (type_ == SANE_TYPE_STRING) {
    // opt.size is the maximum size of the string option, including the null
    // terminator (which is mandatory).
    string_data_.resize(opt.size);
  }
}

bool SaneOption::Set(int i) {
  switch (type_) {
    case SANE_TYPE_INT:
      int_data_.i = i;
      return true;
    case SANE_TYPE_FIXED:
      int_data_.f = SANE_FIX(static_cast<double>(i));
      return true;
    default:
      return false;
  }
}

bool SaneOption::Set(double d) {
  switch (type_) {
    case SANE_TYPE_INT:
      int_data_.i = static_cast<int>(d);
      return true;
    case SANE_TYPE_FIXED:
      int_data_.f = SANE_FIX(d);
      return true;
    default:
      return false;
  }
}

bool SaneOption::Set(const std::string& s) {
  if (type_ != SANE_TYPE_STRING) {
    return false;
  }

  size_t size_with_null = s.size() + 1;
  if (size_with_null > string_data_.size()) {
    LOG(ERROR) << "String size " << size_with_null
               << " exceeds maximum option size " << string_data_.size();
    return false;
  }

  memcpy(string_data_.data(), s.c_str(), size_with_null);
  return true;
}

template <>
std::optional<int> SaneOption::Get() const {
  switch (type_) {
    case SANE_TYPE_INT:
      return int_data_.i;
    case SANE_TYPE_FIXED:
      return static_cast<int>(SANE_UNFIX(int_data_.f));
    default:
      return std::nullopt;
  }
}

template <>
std::optional<std::string> SaneOption::Get() const {
  if (type_ != SANE_TYPE_STRING)
    return std::nullopt;

  return std::string(string_data_.data());
}

void* SaneOption::GetPointer() {
  if (type_ == SANE_TYPE_STRING)
    return string_data_.data();
  else if (type_ == SANE_TYPE_INT)
    return &int_data_.i;
  else if (type_ == SANE_TYPE_FIXED)
    return &int_data_.f;
  else
    return nullptr;
}

int SaneOption::GetIndex() const {
  return index_;
}

std::string SaneOption::GetName() const {
  return name_;
}

std::string SaneOption::DisplayValue() const {
  switch (type_) {
    case SANE_TYPE_INT:
      return std::to_string(int_data_.i);
    case SANE_TYPE_FIXED:
      return std::to_string(static_cast<int>(SANE_UNFIX(int_data_.f)));
    case SANE_TYPE_STRING:
      return Get<std::string>().value();
    default:
      return "[invalid]";
  }
}

SaneDeviceImpl::SaneDeviceImpl(SANE_Handle handle,
                               const std::string& name,
                               std::shared_ptr<DeviceSet> open_devices)
    : handle_(handle),
      name_(name),
      open_devices_(open_devices),
      scan_running_(false) {}

bool SaneDeviceImpl::LoadOptions(brillo::ErrorPtr* error) {
  LOG(INFO) << "Loading device options";
  // First we get option descriptor 0, which contains the total count of
  // options. We don't strictly need the descriptor, but it's "Good form" to
  // do so according to 'scanimage'.
  const SANE_Option_Descriptor* desc = sane_get_option_descriptor(handle_, 0);
  if (!desc) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "Unable to get option count for device");
    return false;
  }

  SANE_Int num_options = 0;
  SANE_Status status = sane_control_option(handle_, 0, SANE_ACTION_GET_VALUE,
                                           &num_options, nullptr);
  if (status != SANE_STATUS_GOOD) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "Unable to get option count for device");
    return false;
  }

  base::flat_map<std::string, ScanOption> region_options = {
      {SANE_NAME_SCAN_TL_X, kTopLeftX},
      {SANE_NAME_SCAN_TL_Y, kTopLeftY},
      {SANE_NAME_SCAN_BR_X, kBottomRightX},
      {SANE_NAME_SCAN_BR_Y, kBottomRightY},
      {SANE_NAME_PAGE_WIDTH, kPageWidth},
      {SANE_NAME_PAGE_HEIGHT, kPageHeight},
  };

  options_.clear();
  // Start at 1, since we've already checked option 0 above.
  for (int i = 1; i < num_options; i++) {
    const SANE_Option_Descriptor* opt = sane_get_option_descriptor(handle_, i);
    if (!opt) {
      brillo::Error::AddToPrintf(error, FROM_HERE, kDbusDomain,
                                 kManagerServiceError,
                                 "Unable to get option %d for device", i);
      return false;
    }

    std::optional<ScanOption> option_name;
    if ((opt->type == SANE_TYPE_INT || opt->type == SANE_TYPE_FIXED) &&
        opt->size == sizeof(SANE_Int) && opt->unit == SANE_UNIT_DPI &&
        strcmp(opt->name, SANE_NAME_SCAN_RESOLUTION) == 0) {
      option_name = kResolution;
    } else if ((opt->type == SANE_TYPE_STRING) &&
               strcmp(opt->name, SANE_NAME_SCAN_MODE) == 0) {
      option_name = kScanMode;
    } else if ((opt->type == SANE_TYPE_STRING) &&
               strcmp(opt->name, SANE_NAME_SCAN_SOURCE) == 0) {
      option_name = kSource;
    } else if ((opt->type == SANE_TYPE_STRING) &&
               strcmp(opt->name, SANE_NAME_ADF_JUSTIFICATION_X) == 0) {
      option_name = kJustificationX;
    } else if ((opt->type == SANE_TYPE_INT || opt->type == SANE_TYPE_FIXED) &&
               opt->size == sizeof(SANE_Int)) {
      auto enum_value = region_options.find(opt->name);
      if (enum_value != region_options.end()) {
        // Do not support the case where scan dimensions are specified in
        // pixels.
        if (opt->unit != SANE_UNIT_MM) {
          LOG(WARNING) << "Found dimension option " << opt->name
                       << " with incompatible unit: " << opt->unit;
          continue;
        }
        option_name = enum_value->second;
      }
    }

    if (option_name.has_value()) {
      SaneOption sane_option(*opt, i);
      SANE_Status status = sane_control_option(
          handle_, i, SANE_ACTION_GET_VALUE, sane_option.GetPointer(), NULL);
      if (status != SANE_STATUS_GOOD) {
        brillo::Error::AddToPrintf(
            error, FROM_HERE, kDbusDomain, kManagerServiceError,
            "Unable to read value of %s option for device",
            OptionDisplayName(option_name.value()));
        return false;
      }
      options_.insert({option_name.value(), std::move(sane_option)});
    }
  }

  LOG(INFO) << "Device options loaded successfully";
  return true;
}

bool SaneDeviceImpl::UpdateDeviceOption(brillo::ErrorPtr* error,
                                        SaneOption* option) {
  SANE_Int result_flags;
  SANE_Status status =
      sane_control_option(handle_, option->GetIndex(), SANE_ACTION_SET_VALUE,
                          option->GetPointer(), &result_flags);
  if (status != SANE_STATUS_GOOD) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "Unable to set " + option->GetName() + " to " +
                             option->DisplayValue() + " : " +
                             sane_strstatus(status));
    // Reload options, to bring local value and device value back in sync.
    LoadOptions(error);
    return false;
  }

  // We also reload if we get SANE_INFO_INEXACT because we want to know
  // what value the printer changed our requested value to.
  // As an optimization, we could only reload this particular option.
  if (result_flags & (SANE_INFO_RELOAD_OPTIONS | SANE_INFO_INEXACT)) {
    return LoadOptions(error);
  }

  return true;
}

std::optional<ScannableArea> SaneDeviceImpl::CalculateScannableArea(
    brillo::ErrorPtr* error) {
  // What we know from the SANE API docs (verbatim):
  // * The unit of all four scan region options must be identical
  // * A frontend can determine the size of the scan surface by first checking
  //   that the options have range constraints associated. If a range or
  //   word-list constraints exist, the frontend can take the minimum and
  //   maximum values of one of the x and y option range-constraints to
  //   determine the scan surface size.
  //
  // Based on my examination of sane-backends, every backend that declares this
  // set of options uses a range constraint.
  //
  // Several backends also have --page-width and --page-height options that
  // define the real maximum values.  If these are present, they are handled
  // automatically in the GetXRange and GetYRange functions.
  ScannableArea area;
  std::optional<OptionRange> x_range = GetXRange(error);
  if (!x_range.has_value()) {
    return std::nullopt;  // brillo::Error::AddTo already called.
  }
  area.set_width(x_range.value().size);

  std::optional<OptionRange> y_range = GetYRange(error);
  if (!y_range.has_value()) {
    return std::nullopt;  // brillo::Error::AddTo already called.
  }
  area.set_height(y_range.value().size);
  return area;
}

// Calculates the starting value of the range for the given ScanOption.
// Requires that |options_| contains |option|, and that the corresponding
// option descriptor for |option| has a range constraint.
std::optional<double> SaneDeviceImpl::GetOptionOffset(
    brillo::ErrorPtr* error, SaneDeviceImpl::ScanOption option) {
  if (options_.count(option) == 0) {
    brillo::Error::AddToPrintf(
        error, FROM_HERE, kDbusDomain, kManagerServiceError,
        "Device is missing option %s", OptionDisplayName(option));
    return std::nullopt;
  }

  int index = options_.at(option).GetIndex();
  const SANE_Option_Descriptor* descriptor =
      sane_get_option_descriptor(handle_, index);
  if (!descriptor) {
    brillo::Error::AddToPrintf(error, FROM_HERE, kDbusDomain,
                               kManagerServiceError,
                               "Unable to get option %s at index %d",
                               OptionDisplayName(option), index);
    return std::nullopt;
  }

  std::optional<OptionRange> range = GetOptionRange(error, *descriptor);
  if (!range.has_value()) {
    brillo::Error::AddToPrintf(
        error, FROM_HERE, kDbusDomain, kManagerServiceError,
        "Failed to get range for %s option.", descriptor->name);
    return std::nullopt;
  }

  return range->start;
}

const char* SaneDeviceImpl::OptionDisplayName(ScanOption option) {
  switch (option) {
    case kResolution:
      return SANE_NAME_SCAN_RESOLUTION;
    case kScanMode:
      return SANE_NAME_SCAN_MODE;
    case kSource:
      return SANE_NAME_SCAN_SOURCE;
    case kTopLeftX:
      return SANE_NAME_SCAN_TL_X;
    case kTopLeftY:
      return SANE_NAME_SCAN_TL_Y;
    case kBottomRightX:
      return SANE_NAME_SCAN_BR_X;
    case kBottomRightY:
      return SANE_NAME_SCAN_BR_Y;
    case kJustificationX:
      return SANE_NAME_ADF_JUSTIFICATION_X;
    case kPageWidth:
      return SANE_NAME_PAGE_WIDTH;
    case kPageHeight:
      return SANE_NAME_PAGE_HEIGHT;
  }
}

template <typename T>
bool SaneDeviceImpl::SetOption(brillo::ErrorPtr* error,
                               ScanOption option_type,
                               T value) {
  if (options_.count(option_type) == 0) {
    brillo::Error::AddToPrintf(error, FROM_HERE, kDbusDomain,
                               kManagerServiceError, "No %s option found.",
                               OptionDisplayName(option_type));
    return false;
  }

  SaneOption& option = options_.at(option_type);
  if (!option.Set(value)) {
    brillo::Error::AddToPrintf(
        error, FROM_HERE, kDbusDomain, kManagerServiceError,
        "Failed to set SaneOption %s", OptionDisplayName(option_type));
    return false;
  }
  return UpdateDeviceOption(error, &option);
}

template <typename T>
std::optional<T> SaneDeviceImpl::GetOption(brillo::ErrorPtr* error,
                                           ScanOption option_type) {
  if (options_.count(option_type) == 0) {
    brillo::Error::AddToPrintf(error, FROM_HERE, kDbusDomain,
                               kManagerServiceError, "No %s option found.",
                               OptionDisplayName(option_type));
    return std::nullopt;
  }

  const SaneOption& option = options_.at(option_type);
  std::optional<T> value = option.Get<T>();
  if (!value.has_value()) {
    brillo::Error::AddTo(error, FROM_HERE, brillo::errors::dbus::kDomain,
                         kManagerServiceError,
                         option.GetName() + " is the wrong type");
  }

  return value;
}

std::optional<std::vector<uint32_t>> SaneDeviceImpl::GetResolutions(
    brillo::ErrorPtr* error) {
  if (options_.count(kResolution) == 0) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "No resolutions available");
    return std::nullopt;
  }

  int index = options_.at(kResolution).GetIndex();
  const SANE_Option_Descriptor* descriptor =
      sane_get_option_descriptor(handle_, index);
  if (!descriptor) {
    brillo::Error::AddToPrintf(
        error, FROM_HERE, kDbusDomain, kManagerServiceError,
        "Unable to get resolution option at index %d", index);
    return std::nullopt;
  }

  std::optional<std::vector<uint32_t>> resolutions =
      GetValidIntOptionValues(error, *descriptor);
  if (!resolutions.has_value()) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "Failed to get valid values for resolution setting");
    return std::nullopt;
  }
  return resolutions.value();
}

std::optional<std::vector<std::string>> SaneDeviceImpl::GetColorModes(
    brillo::ErrorPtr* error) {
  if (options_.count(kScanMode) == 0) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "No color modes available");
    return std::nullopt;
  }

  int index = options_.at(kScanMode).GetIndex();
  const SANE_Option_Descriptor* descriptor =
      sane_get_option_descriptor(handle_, index);
  if (!descriptor) {
    brillo::Error::AddToPrintf(
        error, FROM_HERE, kDbusDomain, kManagerServiceError,
        "Unable to get scan mode option at index %d", index);
    return std::nullopt;
  }

  std::optional<std::vector<std::string>> color_modes =
      GetValidStringOptionValues(error, *descriptor);

  if (!color_modes.has_value()) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "Failed to get valid values for scan modes setting");
    return std::nullopt;
  }
  return color_modes.value();
}

std::optional<uint32_t> SaneDeviceImpl::GetJustificationXOffset(
    const ScanRegion& region, brillo::ErrorPtr* error) {
  // Offset modification only necessary for ADF source at the moment.
  std::optional<std::string> current_source = GetDocumentSource(error);
  if (!current_source.has_value()) {
    return std::nullopt;  // brillo::Error::AddTo already called.
  }
  DocumentSource src = CreateDocumentSource(current_source.value());
  if (src.type() != SOURCE_ADF_SIMPLEX && src.type() != SOURCE_ADF_DUPLEX) {
    return 0;
  }

  std::optional<OptionRange> x_range = GetXRange(error);
  if (!x_range.has_value()) {
    return std::nullopt;  // brillo::Error::AddTo already called.
  }

  std::optional<std::string> x_justification =
      GetOption<std::string>(error, kJustificationX);
  if (!x_justification.has_value()) {
    return 0;
  }

  int max_width = (x_range.value().size);
  int width = region.bottom_right_x() - region.top_left_x();
  // Calculate offset based off of Epson-provided math.
  uint32_t x_offset = 0;
  if (x_justification.value() == kRightJustification) {
    x_offset = max_width - width;
  } else if (x_justification.value() == kCenterJustification) {
    x_offset = (max_width - width) / 2;
  }

  return x_offset;
}

std::optional<OptionRange> SaneDeviceImpl::GetXRange(brillo::ErrorPtr* error) {
  int index;
  if (base::Contains(options_, kPageWidth)) {
    index = options_.at(kPageWidth).GetIndex();
  } else {
    index = options_.at(kTopLeftX).GetIndex();
  }
  const SANE_Option_Descriptor* descriptor =
      sane_get_option_descriptor(handle_, index);
  if (!descriptor) {
    brillo::Error::AddToPrintf(
        error, FROM_HERE, kDbusDomain, kManagerServiceError,
        "Unable to get top-left X option at index %d", index);
    return std::nullopt;
  }

  std::optional<OptionRange> x_range = GetOptionRange(error, *descriptor);
  if (!x_range.has_value()) {
    return std::nullopt;
  }

  return x_range;
}

std::optional<OptionRange> SaneDeviceImpl::GetYRange(brillo::ErrorPtr* error) {
  int index;
  if (base::Contains(options_, kPageHeight)) {
    index = options_.at(kPageHeight).GetIndex();
  } else {
    index = options_.at(kBottomRightY).GetIndex();
  }
  const SANE_Option_Descriptor* descriptor =
      sane_get_option_descriptor(handle_, index);
  if (!descriptor) {
    brillo::Error::AddToPrintf(
        error, FROM_HERE, kDbusDomain, kManagerServiceError,
        "Unable to get bottom-right Y option at index %d", index);
    return std::nullopt;
  }

  std::optional<OptionRange> y_range = GetOptionRange(error, *descriptor);
  if (!y_range.has_value()) {
    return std::nullopt;  // brillo::Error::AddTo already called.
  }

  return y_range;
}

}  // namespace lorgnette
