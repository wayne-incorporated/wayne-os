// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "camera3_test/camera3_module_fixture.h"

#include <algorithm>
#include <iterator>
#include <optional>
#include <string>
#include <tuple>

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/containers/contains.h>
#include <base/files/file_path.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/no_destructor.h>
#include <base/strings/string_split.h>
#include <base/strings/stringprintf.h>
#include <base/system/sys_info.h>
#include <brillo/message_loops/base_message_loop.h>
#include <system/camera_metadata_hidden.h>

#include "camera3_test/camera3_device.h"
#include "camera3_test/camera3_perf_log.h"
#include "camera3_test/camera3_test_data_forwarder.h"
#include "common/utils/camera_hal_enumerator.h"
#include "cros-camera/camera_mojo_channel_manager_token.h"
#include "cros-camera/common.h"
#include "cros-camera/cros_camera_hal.h"
#include "cros-camera/device_config.h"

namespace camera3_test {

#define IGNORE_HARDWARE_LEVEL UINT8_MAX

static camera_module_t* g_cam_module = nullptr;
static cros::cros_camera_hal_t* g_cros_camera_hal = nullptr;

static cros::CameraThread& GetModuleThread() {
  static base::NoDestructor<cros::CameraThread> t("Camera3TestModuleThread");
  return *t;
}

cros::cros_camera_hal_t* GetCrosCameraHal() {
  return g_cros_camera_hal;
}

bool isHardwareLevelSupported(uint8_t actual_level, uint8_t required_level) {
  constexpr int32_t kSortedLevels[] = {
      ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_LEGACY,
      ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_EXTERNAL,
      ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_LIMITED,
      ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_FULL,
      ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_3,
  };

  for (uint8_t level : kSortedLevels) {
    if (level == required_level) {
      return true;
    } else if (level == actual_level) {
      return false;
    }
  }
  return false;
}

std::vector<std::tuple<int, int32_t, int32_t, float, bool>>
ParseRecordingParams() {
  // This parameter would be generated and passed by the camera_HAL3 autotest.
  if (!base::CommandLine::ForCurrentProcess()->HasSwitch("recording_params")) {
    LOGF(ERROR) << "Missing recording parameters in the test command";
    // Return invalid parameters to fail the test
    return {{-1, 0, 0, 0.0, false}};
  }
  std::vector<std::tuple<int, int32_t, int32_t, float, bool>> params;
  std::string params_str =
      base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII(
          "recording_params");
  // Expected video recording parameters in the format
  // "camera_id:width:height:frame_rate:support_constant_frame_rate".
  // For example:
  // "0:1280:720:30:1,0:1920:1080:30:1,1:1280:720:30:0" means camcorder profiles
  // contains 1280x720 and 1920x1080 for camera 0 and just 1280x720 for camera
  // 1. And we should skip the constant frame rate check for camera 1 under
  // 1280x720 resolution since it might be unsupported.
  const size_t kNumParamsInProfileLegacy = 4;
  const size_t kNumParamsInProfile = 5;
  enum {
    CAMERA_ID_IDX,
    WIDTH_IDX,
    HEIGHT_IDX,
    FRAME_RATE_IDX,
    SUPPORT_CONSTANT_FRAME_RATE_IDX
  };
  for (const auto& it : base::SplitString(
           params_str, ",", base::WhitespaceHandling::TRIM_WHITESPACE,
           base::SplitResult::SPLIT_WANT_ALL)) {
    auto profile =
        base::SplitString(it, ":", base::WhitespaceHandling::TRIM_WHITESPACE,
                          base::SplitResult::SPLIT_WANT_ALL);
    // TODO(b/141517606): Remove the legacy branch once we ensure all tests put
    // correct numbers of recording parameters.
    if (profile.size() == kNumParamsInProfileLegacy) {
      params.emplace_back(std::stoi(profile[CAMERA_ID_IDX]),
                          std::stoi(profile[WIDTH_IDX]),
                          std::stoi(profile[HEIGHT_IDX]),
                          std::stof(profile[FRAME_RATE_IDX]), true);
    } else if (profile.size() == kNumParamsInProfile) {
      params.emplace_back(
          std::stoi(profile[CAMERA_ID_IDX]), std::stoi(profile[WIDTH_IDX]),
          std::stoi(profile[HEIGHT_IDX]), std::stof(profile[FRAME_RATE_IDX]),
          std::stoi(profile[SUPPORT_CONSTANT_FRAME_RATE_IDX]) == 1);
    } else {
      ADD_FAILURE() << "Failed to parse video recording parameters (" << it
                    << ")";
      continue;
    }
  }

  std::set<int> param_ids;
  for (const auto& param : params) {
    param_ids.insert(std::get<CAMERA_ID_IDX>(param));
  }

  // We are going to enable usb camera hal on all boards, so there will be more
  // than one hals on many platforms just like today's nautilus.  The
  // recording_params is now generated from media_profiles.xml, where the camera
  // ids are already translated by SuperHAL.  But cros_camera_test is used to
  // test only one camera hal directly without going through the hal_adapter,
  // therefore we have to remap the ids here.
  //
  // TODO(shik): This is a temporary workaround for SuperHAL camera ids mapping
  // until we have better ground truth config file.  Here we exploit the fact
  // that there are at most one back and at most one front internal cameras for
  // now, and all cameras are sorted by facing in SuperHAL.  I feel bad when
  // implementing the following hack (sigh).
  std::vector<std::tuple<int, int32_t, int32_t, float, bool>> result;
  Camera3Module module;
  if (module.GetCameraIds().size() < param_ids.size()) {
    // SuperHAL case
    for (const auto& cam_id : module.GetTestCameraIds()) {
      camera_info info;
      EXPECT_EQ(0, Camera3Module().GetCameraInfo(cam_id, &info));
      bool found_matching_param = false;
      for (auto param : params) {
        if (std::get<CAMERA_ID_IDX>(param) == info.facing) {
          found_matching_param = true;
          std::get<CAMERA_ID_IDX>(param) = cam_id;
          result.emplace_back(param);
        }
      }
      EXPECT_TRUE(found_matching_param);
    }
  } else {
    // Single HAL case
    for (const auto& cam_id : module.GetTestCameraIds()) {
      if (std::find_if(
              params.begin(), params.end(),
              [&](const std::tuple<int, int32_t, int32_t, float, bool>& item) {
                return std::get<CAMERA_ID_IDX>(item) == cam_id;
              }) == params.end()) {
        ADD_FAILURE() << "Missing video recording parameters for camera "
                      << cam_id;
      }
    }
    result = std::move(params);
  }

  LOGF(INFO) << "The parameters will be used for recording test:";
  for (const auto& param : result) {
    LOGF(INFO) << base::StringPrintf(
        "camera id = %d, size = %dx%d, fps = %g, support_constant_frame_rate = "
        "%d",
        std::get<CAMERA_ID_IDX>(param), std::get<WIDTH_IDX>(param),
        std::get<HEIGHT_IDX>(param), std::get<FRAME_RATE_IDX>(param),
        std::get<SUPPORT_CONSTANT_FRAME_RATE_IDX>(param));
  }

  return result;
}

// static
void CameraModuleCallbacksHandler::camera_device_status_change(
    const camera_module_callbacks_t* callbacks, int camera_id, int new_status) {
  auto* aux = static_cast<const CameraModuleCallbacksAux*>(callbacks);
  aux->handler->CameraDeviceStatusChange(
      camera_id, static_cast<camera_device_status_t>(new_status));
}

// static
void CameraModuleCallbacksHandler::torch_mode_status_change(
    const camera_module_callbacks_t* callbacks,
    const char* camera_id,
    int new_status) {
  auto* aux = static_cast<const CameraModuleCallbacksAux*>(callbacks);
  aux->handler->TorchModeStatusChange(
      atoi(camera_id), static_cast<torch_mode_status_t>(new_status));
}

// static
CameraModuleCallbacksHandler* CameraModuleCallbacksHandler::GetInstance() {
  static auto* instance = new CameraModuleCallbacksHandler();
  return instance;
}

bool CameraModuleCallbacksHandler::IsExternalCameraPresent(int camera_id) {
  base::AutoLock l(lock_);
  auto it = device_status_.find(camera_id);
  return it != device_status_.end() &&
         it->second == CAMERA_DEVICE_STATUS_PRESENT;
}

// TODO(shik): Run tests on external cameras as well if detected.  We need to
// relax the requirements for them just like what CTS did.
void CameraModuleCallbacksHandler::CameraDeviceStatusChange(
    int camera_id, camera_device_status_t new_status) {
  base::AutoLock l(lock_);
  LOGF(INFO) << "camera_id = " << camera_id << ", new status = " << new_status;
  device_status_[camera_id] = new_status;
}

void CameraModuleCallbacksHandler::TorchModeStatusChange(
    int camera_id, torch_mode_status_t new_status) {
  LOGF(INFO) << "camera_id = " << camera_id << ", new status = " << new_status;
}

int32_t ResolutionInfo::Width() const {
  return width_;
}

int32_t ResolutionInfo::Height() const {
  return height_;
}

int32_t ResolutionInfo::Area() const {
  return width_ * height_;
}

bool ResolutionInfo::operator==(const ResolutionInfo& resolution) const {
  return (width_ == resolution.Width()) && (height_ == resolution.Height());
}

bool ResolutionInfo::operator<(const ResolutionInfo& resolution) const {
  // Compare by area it covers, if the areas are same, then compare the widths.
  return (Area() < resolution.Area()) ||
         (Area() == resolution.Area() && width_ < resolution.Width());
}

std::ostream& operator<<(std::ostream& out, const ResolutionInfo& info) {
  out << info.width_ << 'x' << info.height_;
  return out;
}

static std::vector<int> GetCmdLineTestCameraIds() {
  auto id_str =
      base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII("camera_ids");
  std::vector<int> ids;
  if (!id_str.empty()) {
    auto id_strs = base::SplitString(id_str, ",",
                                     base::WhitespaceHandling::TRIM_WHITESPACE,
                                     base::SplitResult::SPLIT_WANT_ALL);
    for (const auto& id : id_strs) {
      ids.push_back(stoi(id));
    }
  }
  return ids;
}

// static
CameraModuleCallbacksAux* CameraModuleCallbacksAux::GetInstance() {
  static CameraModuleCallbacksAux aux;
  return &aux;
}

CameraModuleCallbacksAux::CameraModuleCallbacksAux() {
  camera_device_status_change =
      &CameraModuleCallbacksHandler::camera_device_status_change;
  torch_mode_status_change =
      &CameraModuleCallbacksHandler::torch_mode_status_change;
  handler = CameraModuleCallbacksHandler::GetInstance();
}

static void InitCameraModuleOnThread(camera_module_t* cam_module) {
  if (cam_module->get_vendor_tag_ops) {
    static vendor_tag_ops ops = {};
    cam_module->get_vendor_tag_ops(&ops);
    ASSERT_EQ(0, set_camera_metadata_vendor_ops(&ops))
        << "Failed to set camera metadata vendor ops";
  }
  if (cam_module->init) {
    ASSERT_EQ(0, cam_module->init());
  }
  int num_builtin_cameras = cam_module->get_number_of_cameras();
  VLOGF(1) << "num_builtin_cameras = " << num_builtin_cameras;
  ASSERT_EQ(0,
            cam_module->set_callbacks(CameraModuleCallbacksAux::GetInstance()));
}

// On successfully Initialized, |cam_module_| will pointed to valid
// camera_module_t.
static void InitCameraModule(const base::FilePath& camera_hal_path,
                             cros::CameraMojoChannelManagerToken* token,
                             void** cam_hal_handle,
                             camera_module_t** cam_module,
                             cros::cros_camera_hal_t** cros_camera_hal) {
  *cam_hal_handle = dlopen(camera_hal_path.value().c_str(), RTLD_NOW);
  ASSERT_NE(nullptr, *cam_hal_handle) << "Failed to dlopen: " << dlerror();

  *cros_camera_hal = static_cast<cros::cros_camera_hal_t*>(
      dlsym(*cam_hal_handle, CROS_CAMERA_HAL_INFO_SYM_AS_STR));

  // TODO(b/151270948): We should report error here if it fails to find the
  // symbol once all camera HALs have implemented the interface.
  if (*cros_camera_hal != nullptr) {
    (*cros_camera_hal)->set_up(token);
    g_cros_camera_hal = *cros_camera_hal;
  }

  camera_module_t* module = static_cast<camera_module_t*>(
      dlsym(*cam_hal_handle, HAL_MODULE_INFO_SYM_AS_STR));
  ASSERT_NE(nullptr, module) << "Camera module is invalid";
  ASSERT_NE(nullptr, module->get_number_of_cameras)
      << "get_number_of_cameras is not implemented";
  ASSERT_NE(nullptr, module->get_camera_info)
      << "get_camera_info is not implemented";
  ASSERT_NE(nullptr, module->common.methods->open) << "open() is unimplemented";
  for (int id : GetCmdLineTestCameraIds()) {
    ASSERT_GT(module->get_number_of_cameras(), id)
        << "No such test camera id in HAL";
  }
  ASSERT_EQ(0,
            GetModuleThread().PostTaskSync(
                FROM_HERE, base::BindOnce(&InitCameraModuleOnThread, module)));
  *cam_module = module;
}

static void InitCameraModuleByHalPath(
    const base::FilePath& camera_hal_path,
    cros::CameraMojoChannelManagerToken* token,
    void** cam_hal_handle,
    cros::cros_camera_hal_t** cros_camera_hal) {
  InitCameraModule(camera_hal_path, token, cam_hal_handle, &g_cam_module,
                   cros_camera_hal);
}

static void InitCameraModuleByFacing(int facing,
                                     cros::CameraMojoChannelManagerToken* token,
                                     void** cam_hal_handle,
                                     cros::cros_camera_hal_t** cros_camera_hal,
                                     base::FilePath* camera_hal_path) {
  // Do cleanup when exit from ASSERT_XX
  struct CleanupModule {
    void operator()(void** cam_hal_handle) {
      if (*cam_hal_handle) {
        set_camera_metadata_vendor_ops(nullptr);
        ASSERT_EQ(0, dlclose(*cam_hal_handle))
            << "Failed to close camera hal when probing facing";
        g_cam_module = NULL;
        *cam_hal_handle = NULL;
      }
    }
  };
  for (const auto& hal_path : cros::GetCameraHalPaths()) {
    InitCameraModule(hal_path, token, cam_hal_handle, &g_cam_module,
                     cros_camera_hal);
    std::unique_ptr<void*, CleanupModule> cleanup_ptr(cam_hal_handle);
    if (g_cam_module != NULL) {
      Camera3Module camera_module;
      for (int i = 0; i < camera_module.GetNumberOfCameras(); i++) {
        camera_info info;
        ASSERT_EQ(0, camera_module.GetCameraInfo(i, &info));
        if (info.facing == facing) {
          auto* cmd_line = base::CommandLine::ForCurrentProcess();
          cmd_line->AppendSwitchASCII("camera_ids", std::to_string(i));
          cmd_line->AppendSwitchPath("camera_hal_path", hal_path);
          *camera_hal_path = hal_path;
          cleanup_ptr.release();
          return;
        }
      }
    }
  }
  FAIL() << "Cannot find camera with facing=" << facing;
}

static void EnableCameraFacing(int facing,
                               camera3_test::CameraHalClient* camera_hal_client,
                               base::FilePath* camera_hal_path) {
  ASSERT_NE(nullptr, camera_hal_client) << "camera_hal_client is not valid";
  for (const auto& hal_path : cros::GetCameraHalPaths()) {
    for (int i = 0; i < camera_hal_client->GetNumberOfCameras(); i++) {
      camera_info info;
      ASSERT_EQ(0, camera_hal_client->GetCameraInfo(i, &info));
      if (info.facing == facing) {
        *camera_hal_path = hal_path;
        return;
      }
    }
  }
  FAIL() << "Cannot find camera with facing=" << facing;
}

static void InitPerfLog() {
  // GetNumberOfCameras() returns the number of internal cameras, so here we
  // should not see any external cameras (facing = 2).
  const std::string facing_names[] = {"back", "front"};
  camera3_test::Camera3Module camera_module;
  int num_cameras = camera_module.GetNumberOfCameras();
  std::map<int, std::string> name_map;
  for (int i = 0; i < num_cameras; i++) {
    camera_info info;
    ASSERT_EQ(0, camera_module.GetCameraInfo(i, &info));
    ASSERT_LE(0, info.facing);
    ASSERT_LT(info.facing, std::size(facing_names));
    name_map[i] = facing_names[info.facing];
  }
  camera3_test::Camera3PerfLog::GetInstance()->SetCameraNameMap(name_map);
}

static camera_module_t* GetCameraModule() {
  return g_cam_module;
}

// Camera module

Camera3Module::Camera3Module() : test_camera_ids_(GetCmdLineTestCameraIds()) {
  if (g_cam_module != nullptr) {
    cam_module_connector_ = std::make_unique<HalModuleConnector>(
        GetCameraModule(), &GetModuleThread());
  } else {
    cam_module_connector_ =
        std::make_unique<ClientModuleConnector>(CameraHalClient::GetInstance());
  }
}

int Camera3Module::GetNumberOfCameras() {
  return cam_module_connector_->GetNumberOfCameras();
}

std::vector<int> Camera3Module::GetCameraIds() {
  int num_cams = GetNumberOfCameras();
  if (num_cams <= 0) {
    return std::vector<int>();
  }
  std::vector<int> ids(num_cams);
  for (int i = 0; i < num_cams; i++) {
    ids[i] = i;
  }

  return ids;
}

std::vector<int> Camera3Module::GetTestCameraIds() {
  return test_camera_ids_.empty() ? GetCameraIds() : test_camera_ids_;
}

void Camera3Module::GetStreamConfigEntry(int cam_id,
                                         int32_t key,
                                         camera_metadata_ro_entry_t* entry) {
  entry->count = 0;

  camera_info info;
  ASSERT_EQ(0, GetCameraInfo(cam_id, &info))
      << "Can't get info for camera " << cam_id;

  camera_metadata_ro_entry_t local_entry = {};
  ASSERT_EQ(
      0, find_camera_metadata_ro_entry(
             const_cast<camera_metadata_t*>(info.static_camera_characteristics),
             key, &local_entry))
      << "Fail to find metadata key " << get_camera_metadata_tag_name(key);
  ASSERT_NE(0u, local_entry.count) << "Camera stream configuration is empty";
  ASSERT_EQ(0u, local_entry.count % kNumOfElementsInStreamConfigEntry)
      << "Camera stream configuration parsing error";
  *entry = local_entry;
}

bool Camera3Module::IsFormatAvailable(int cam_id, int format) {
  camera_metadata_ro_entry_t available_config = {};
  GetStreamConfigEntry(cam_id, ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS,
                       &available_config);

  for (uint32_t i = 0; i < available_config.count;
       i += kNumOfElementsInStreamConfigEntry) {
    if (available_config.data.i32[i + STREAM_CONFIG_FORMAT_INDEX] == format) {
      return true;
    }
  }

  return false;
}

int Camera3Module::GetCameraInfo(int cam_id, camera_info* info) {
  return cam_module_connector_->GetCameraInfo(cam_id, info);
}

std::unique_ptr<DeviceConnector> Camera3Module::OpenDevice(int cam_id) {
  return cam_module_connector_->OpenDevice(cam_id);
}

bool Camera3Module::GetVendorTagByName(const std::string name, uint32_t* tag) {
  return cam_module_connector_->GetVendorTagByName(name, tag);
}

std::vector<int32_t> Camera3Module::GetOutputFormats(int cam_id) {
  camera_metadata_ro_entry_t available_config = {};
  GetStreamConfigEntry(cam_id, ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS,
                       &available_config);

  std::set<int32_t> available_formats;
  for (uint32_t i = 0; i < available_config.count;
       i += kNumOfElementsInStreamConfigEntry) {
    if (available_config.data.i32[i + STREAM_CONFIG_DIRECTION_INDEX] ==
        ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT) {
      available_formats.insert(
          available_config.data.i32[i + STREAM_CONFIG_FORMAT_INDEX]);
    }
  }

  return std::vector<int32_t>(available_formats.begin(),
                              available_formats.end());
}

std::vector<ResolutionInfo> Camera3Module::GetSortedOutputResolutions(
    int cam_id, int32_t format) {
  camera_metadata_ro_entry_t available_config = {};
  GetStreamConfigEntry(cam_id, ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS,
                       &available_config);

  std::vector<ResolutionInfo> available_resolutions;
  for (uint32_t i = 0; i < available_config.count;
       i += kNumOfElementsInStreamConfigEntry) {
    int32_t fmt = available_config.data.i32[i + STREAM_CONFIG_FORMAT_INDEX];
    int32_t width = available_config.data.i32[i + STREAM_CONFIG_WIDTH_INDEX];
    int32_t height = available_config.data.i32[i + STREAM_CONFIG_HEIGHT_INDEX];
    int32_t in_or_out =
        available_config.data.i32[i + STREAM_CONFIG_DIRECTION_INDEX];
    if ((fmt == format) &&
        (in_or_out == ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT)) {
      available_resolutions.emplace_back(width, height);
    }
  }
  std::sort(available_resolutions.begin(), available_resolutions.end());
  return available_resolutions;
}

int64_t Camera3Module::GetOutputKeyParameterI64(
    int cam_id,
    int32_t format,
    const ResolutionInfo& resolution,
    int32_t key,
    int32_t index) {
  camera_metadata_ro_entry_t available_config = {};
  GetStreamConfigEntry(cam_id, key, &available_config);

  for (uint32_t i = 0; i < available_config.count;
       i += kNumOfElementsInStreamConfigEntry) {
    int64_t fmt = available_config.data.i64[i + STREAM_CONFIG_FORMAT_INDEX];
    int64_t width = available_config.data.i64[i + STREAM_CONFIG_WIDTH_INDEX];
    int64_t height = available_config.data.i64[i + STREAM_CONFIG_HEIGHT_INDEX];
    if (fmt == format && width == resolution.Width() &&
        height == resolution.Height()) {
      return available_config.data.i64[i + index];
    }
  }

  return -ENODATA;
}

int64_t Camera3Module::GetOutputStallDuration(
    int cam_id, int32_t format, const ResolutionInfo& resolution) {
  int64_t value = GetOutputKeyParameterI64(
      cam_id, format, resolution, ANDROID_SCALER_AVAILABLE_STALL_DURATIONS,
      STREAM_CONFIG_STALL_DURATION_INDEX);
  return (value != -ENODATA)
             ? value
             : 0;  // Default duration is '0' (unsupported/no extra stall)
}

int64_t Camera3Module::GetOutputMinFrameDuration(
    int cam_id, int32_t format, const ResolutionInfo& resolution) {
  return GetOutputKeyParameterI64(cam_id, format, resolution,
                                  ANDROID_SCALER_AVAILABLE_MIN_FRAME_DURATIONS,
                                  STREAM_CONFIG_MIN_DURATION_INDEX);
}

// Test cases

TEST_F(Camera3ModuleFixture, NumberOfCameras) {
  base::CommandLine* cmd_line = base::CommandLine::ForCurrentProcess();
  base::FilePath camera_hal_path =
      cmd_line->GetSwitchValuePath("camera_hal_path");
  std::optional<cros::DeviceConfig> config = cros::DeviceConfig::Create();

  if (g_cam_module != nullptr &&
      strcmp(g_cam_module->common.name, "Fake Camera HAL") == 0) {
    // Ignore this test on fake HAL, since it by default have no camera.
    return;
  }

  if (config.has_value()) {
    std::optional<int> usb_count =
        config->GetCameraCount(cros::Interface::kUsb, /*detachable=*/false);
    std::optional<int> mipi_count =
        config->GetCameraCount(cros::Interface::kMipi, /*detachable=*/false);
    if (camera_hal_path.empty()) {
      if (usb_count.has_value() && mipi_count.has_value()) {
        ASSERT_EQ(cam_module_.GetNumberOfCameras(), *usb_count + *mipi_count)
            << "Incorrect number of built-in cameras";
        return;
      }
    } else if (camera_hal_path.value().find("usb") != std::string::npos) {
      if (usb_count.has_value()) {
        ASSERT_EQ(cam_module_.GetNumberOfCameras(), *usb_count)
            << "Incorrect number of USB cameras";
        return;
      }
    } else {
      if (mipi_count.has_value()) {
        ASSERT_EQ(cam_module_.GetNumberOfCameras(), *mipi_count)
            << "Incorrect number of MIPI cameras";
        return;
      }
    }
  }
  ASSERT_GT(cam_module_.GetNumberOfCameras(), 0) << "No cameras found";
  ASSERT_LE(cam_module_.GetNumberOfCameras(), kMaxNumCameras)
      << "Too many cameras found";
}

TEST_F(Camera3ModuleFixture, OpenDeviceOfBadIndices) {
  auto* callbacks_handler = CameraModuleCallbacksHandler::GetInstance();
  std::vector<int> bad_ids = {-1};
  for (int id = cam_module_.GetNumberOfCameras(); bad_ids.size() < 3; id++) {
    if (callbacks_handler->IsExternalCameraPresent(id)) {
      LOG(INFO) << "Camera " << id << " is an external camera, skip it";
      continue;
    }
    bad_ids.push_back(id);
  }
  // Possible TOCTOU race here if the external camera is plugged after
  // |IsExternalCameraPresent()|, but before |OpenDevice()|.
  for (int id : bad_ids) {
    Camera3Device cam_dev(id);
    ASSERT_NE(0, cam_dev.Initialize(&cam_module_))
        << "Open camera device of bad id " << id;
  }
}

TEST_F(Camera3ModuleFixture, IsActiveArraySizeSubsetOfPixelArraySize) {
  for (int cam_id = 0; cam_id < cam_module_.GetNumberOfCameras(); cam_id++) {
    camera_info info;
    ASSERT_EQ(0, cam_module_.GetCameraInfo(cam_id, &info))
        << "Can't get camera info for " << cam_id;

    camera_metadata_ro_entry_t entry;
    ASSERT_EQ(
        0,
        find_camera_metadata_ro_entry(
            const_cast<camera_metadata_t*>(info.static_camera_characteristics),
            ANDROID_SENSOR_INFO_PIXEL_ARRAY_SIZE, &entry))
        << "Can't find the sensor pixel array size.";
    int pixel_array_w = entry.data.i32[0];
    int pixel_array_h = entry.data.i32[1];

    ASSERT_EQ(
        0,
        find_camera_metadata_ro_entry(
            const_cast<camera_metadata_t*>(info.static_camera_characteristics),
            ANDROID_SENSOR_INFO_ACTIVE_ARRAY_SIZE, &entry))
        << "Can't find the sensor active array size.";
    int active_array_w = entry.data.i32[0];
    int active_array_h = entry.data.i32[1];

    ASSERT_LE(active_array_h, pixel_array_h);
    ASSERT_LE(active_array_w, pixel_array_w);
  }
}

TEST_F(Camera3ModuleFixture, OpenDevice) {
  for (int cam_id = 0; cam_id < cam_module_.GetNumberOfCameras(); cam_id++) {
    Camera3Device cam_dev(cam_id);
    ASSERT_EQ(0, cam_dev.Initialize(&cam_module_))
        << "Camera open device failed";
    cam_dev.Destroy();
  }
}

TEST_F(Camera3ModuleFixture, DeviceVersion) {
  camera_info info;
  for (int cam_id = 0; cam_id < cam_module_.GetNumberOfCameras(); cam_id++) {
    ASSERT_EQ(0, cam_module_.GetCameraInfo(cam_id, &info))
        << "Can't get camera info for " << cam_id;
    EXPECT_GE(info.device_version, (uint16_t)HARDWARE_MODULE_API_VERSION(3, 3))
        << "Device " << cam_id << " fails to support at least HALv3.3";
  }
}

TEST_F(Camera3ModuleFixture, OpenDeviceTwice) {
  for (int cam_id = 0; cam_id < cam_module_.GetNumberOfCameras(); cam_id++) {
    Camera3Device cam_dev(cam_id);
    ASSERT_EQ(0, cam_dev.Initialize(&cam_module_))
        << "Camera open device failed";
    // Open the device again
    Camera3Device cam_bad_dev(cam_id);
    ASSERT_NE(0, cam_bad_dev.Initialize(&cam_module_))
        << "Opening camera device twice should have failed";
  }
}

TEST_F(Camera3ModuleFixture, RequiredFormats) {
  auto IsResolutionSupported =
      [](const std::vector<ResolutionInfo>& resolution_list,
         const ResolutionInfo& resolution) {
        return std::find(resolution_list.begin(), resolution_list.end(),
                         resolution) != resolution_list.end();
      };
  auto RemoveResolution = [](std::vector<ResolutionInfo>& resolution_list,
                             const ResolutionInfo& resolution) {
    auto it =
        std::find(resolution_list.begin(), resolution_list.end(), resolution);
    if (it != resolution_list.end()) {
      resolution_list.erase(it);
    }
  };
  auto GetMaxVideoResolution = [](int cam_id) {
    auto recording_params = ParseRecordingParams();
    int32_t width = 0;
    int32_t height = 0;
    for (const auto& it : recording_params) {
      int32_t area = std::get<1>(it) * std::get<2>(it);
      if (std::get<0>(it) == cam_id &&
          (width * height < area ||
           (width * height == area && width < std::get<1>(it)))) {
        width = std::get<1>(it);
        height = std::get<2>(it);
      }
    }
    return ResolutionInfo(width, height);
  };

  for (int cam_id = 0; cam_id < cam_module_.GetNumberOfCameras(); cam_id++) {
    ASSERT_TRUE(cam_module_.IsFormatAvailable(cam_id, HAL_PIXEL_FORMAT_BLOB))
        << "Camera stream configuration does not support JPEG";
    ASSERT_TRUE(
        cam_module_.IsFormatAvailable(cam_id, HAL_PIXEL_FORMAT_YCbCr_420_888))
        << "Camera stream configuration does not support flexible YUV";

    // Reference:
    // camera2/cts/ExtendedCameraCharacteristicsTest.java#testAvailableStreamConfigs
    camera_info info;
    ASSERT_EQ(0, cam_module_.GetCameraInfo(cam_id, &info))
        << "Can't get camera info for " << cam_id;

    std::vector<ResolutionInfo> jpeg_resolutions =
        cam_module_.GetSortedOutputResolutions(cam_id, HAL_PIXEL_FORMAT_BLOB);
    std::vector<ResolutionInfo> yuv_resolutions =
        cam_module_.GetSortedOutputResolutions(cam_id,
                                               HAL_PIXEL_FORMAT_YCbCr_420_888);
    std::vector<ResolutionInfo> private_resolutions =
        cam_module_.GetSortedOutputResolutions(
            cam_id, HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED);

    const ResolutionInfo full_hd(1920, 1080), full_hd_alt(1920, 1088),
        hd(1280, 720), vga(640, 480), qvga(320, 240);

    camera_metadata_ro_entry_t entry;
    ASSERT_EQ(
        0,
        find_camera_metadata_ro_entry(
            const_cast<camera_metadata_t*>(info.static_camera_characteristics),
            ANDROID_SENSOR_INFO_ACTIVE_ARRAY_SIZE, &entry))
        << "Can't find the sensor active array size.";
    ResolutionInfo active_array(entry.data.i32[0], entry.data.i32[1]);
    if ((active_array.Width() >= full_hd.Width()) &&
        (active_array.Height() >= full_hd.Height())) {
      EXPECT_TRUE(IsResolutionSupported(jpeg_resolutions, full_hd) ||
                  IsResolutionSupported(jpeg_resolutions, full_hd_alt))
          << "Required FULLHD size not found for JPEG for camera " << cam_id;
    }
    if ((active_array.Width() >= hd.Width()) &&
        (active_array.Height() >= hd.Height())) {
      EXPECT_TRUE(IsResolutionSupported(jpeg_resolutions, hd))
          << "Required HD size not found for JPEG for camera " << cam_id;
    }
    if ((active_array.Width() >= vga.Width()) &&
        (active_array.Height() >= vga.Height())) {
      EXPECT_TRUE(IsResolutionSupported(jpeg_resolutions, vga))
          << "Required VGA size not found for JPEG for camera " << cam_id;
    }
    if ((active_array.Width() >= qvga.Width()) &&
        (active_array.Height() >= qvga.Height())) {
      EXPECT_TRUE(IsResolutionSupported(jpeg_resolutions, qvga))
          << "Required QVGA size not found for JPEG for camera " << cam_id;
    }

    ASSERT_EQ(
        0,
        find_camera_metadata_ro_entry(
            const_cast<camera_metadata_t*>(info.static_camera_characteristics),
            ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL, &entry))
        << "Cannot find the metadata ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL";
    int32_t hw_level = entry.data.i32[0];

    // Handle FullHD special case first
    if (IsResolutionSupported(jpeg_resolutions, full_hd)) {
      if (hw_level == ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_FULL) {
        EXPECT_TRUE(IsResolutionSupported(yuv_resolutions, full_hd) ||
                    IsResolutionSupported(yuv_resolutions, full_hd_alt))
            << "FullHD YUV size not found in Full device ";
        EXPECT_TRUE(IsResolutionSupported(private_resolutions, full_hd) ||
                    IsResolutionSupported(private_resolutions, full_hd_alt))
            << "FullHD private size not found in Full device ";
      }
      // Remove all FullHD or FullHD_Alt sizes for the remaining of the test
      RemoveResolution(jpeg_resolutions, full_hd);
      RemoveResolution(jpeg_resolutions, full_hd_alt);
    }

    // Check all sizes other than FullHD
    if (hw_level == ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_LIMITED) {
      // Remove all jpeg sizes larger than max video size
      auto max_video_resolution = GetMaxVideoResolution(cam_id);
      for (auto it = jpeg_resolutions.begin(); it != jpeg_resolutions.end();) {
        if (it->Width() >= max_video_resolution.Width() &&
            it->Height() >= max_video_resolution.Height()) {
          it = jpeg_resolutions.erase(it);
        } else {
          it++;
        }
      }
    }

    std::stringstream ss;
    auto PrintResolutions =
        [&](const std::vector<ResolutionInfo>& resolutions) {
          ss.str("");
          for (const auto& it : resolutions) {
            ss << (ss.str().empty() ? "" : ", ") << it.Width() << "x"
               << it.Height();
          }
          return ss.str();
        };
    if (hw_level == ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_FULL ||
        hw_level == ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_LIMITED) {
      std::vector<ResolutionInfo> diff;
      std::set_difference(jpeg_resolutions.begin(), jpeg_resolutions.end(),
                          yuv_resolutions.begin(), yuv_resolutions.end(),
                          std::inserter(diff, diff.begin()));
      EXPECT_TRUE(diff.empty())
          << "Sizes " << PrintResolutions(diff) << " not found in YUV format";
    }

    std::vector<ResolutionInfo> diff;
    std::set_difference(jpeg_resolutions.begin(), jpeg_resolutions.end(),
                        private_resolutions.begin(), private_resolutions.end(),
                        std::inserter(diff, diff.begin()));
    EXPECT_TRUE(diff.empty())
        << "Sizes " << PrintResolutions(diff) << " not found in private format";
  }
}

// TODO(hywu): test keys used by RAW, burst and reprocessing capabilities when
// full mode is supported

static bool AreAllCapabilitiesSupported(
    camera_metadata_t* characteristics,
    const std::vector<uint8_t>& capabilities) {
  std::set<uint8_t> supported_capabilities;
  camera_metadata_ro_entry_t entry;
  if (find_camera_metadata_ro_entry(characteristics,
                                    ANDROID_REQUEST_AVAILABLE_CAPABILITIES,
                                    &entry) == 0) {
    for (size_t i = 0; i < entry.count; i++) {
      if ((entry.data.u8[i] >=
           ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE) &&
          (entry.data.u8[i] <=
           ANDROID_REQUEST_AVAILABLE_CAPABILITIES_CONSTRAINED_HIGH_SPEED_VIDEO)) {  // NOLINT(whitespace/line_length)
        supported_capabilities.insert(entry.data.u8[i]);
      }
    }
  }

  for (const auto& it : capabilities) {
    if (supported_capabilities.find(it) == supported_capabilities.end()) {
      return false;
    }
  }
  return true;
}

static void ExpectKeyAvailable(camera_metadata_t* characteristics,
                               int32_t key,
                               uint8_t hw_level,
                               const std::vector<uint8_t>& capabilities) {
  camera_metadata_ro_entry_t entry;
  ASSERT_EQ(0,
            find_camera_metadata_ro_entry(
                characteristics, ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL, &entry))
      << "Cannot find the metadata ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL";
  uint8_t actual_hw_level = entry.data.u8[0];

  // For LIMITED-level targeted keys, rely on capability check, not level
  if (isHardwareLevelSupported(actual_hw_level, hw_level) &&
      hw_level != ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_LIMITED) {
    ASSERT_EQ(0, find_camera_metadata_ro_entry(characteristics, key, &entry))
        << "Key " << get_camera_metadata_tag_name(key)
        << " must be in characteristics for this hardware level ";
  } else if (AreAllCapabilitiesSupported(characteristics, capabilities)) {
    if (!(hw_level == ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_LIMITED &&
          !isHardwareLevelSupported(actual_hw_level, hw_level))) {
      // Don't enforce LIMITED-starting keys on LEGACY level, even if cap is
      // defined
      std::stringstream ss;
      auto PrintCapabilities = [&]() {
        for (const auto& it : capabilities) {
          ss << (ss.str().empty() ? "" : ", ");
          switch (it) {
            case ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE:
              ss << "BACKWARD_COMPATIBLE";
              break;
            case ANDROID_REQUEST_AVAILABLE_CAPABILITIES_MANUAL_SENSOR:
              ss << "MANUAL_SENSOR";
              break;
            case ANDROID_REQUEST_AVAILABLE_CAPABILITIES_MANUAL_POST_PROCESSING:
              ss << "MANUAL_POST_PROCESSING";
              break;
            case ANDROID_REQUEST_AVAILABLE_CAPABILITIES_RAW:
              ss << "RAW";
              break;
            case ANDROID_REQUEST_AVAILABLE_CAPABILITIES_PRIVATE_REPROCESSING:
              ss << "PRIVATE_PROCESSING";
              break;
            case ANDROID_REQUEST_AVAILABLE_CAPABILITIES_READ_SENSOR_SETTINGS:
              ss << "READ_SENSOR_SETTINGS";
              break;
            case ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BURST_CAPTURE:
              ss << "BURST_CAPTURE";
              break;
            case ANDROID_REQUEST_AVAILABLE_CAPABILITIES_YUV_REPROCESSING:
              ss << "YUV_REPROCESSING";
              break;
            case ANDROID_REQUEST_AVAILABLE_CAPABILITIES_DEPTH_OUTPUT:
              ss << "DEPTH_OUTPUT";
              break;
            case ANDROID_REQUEST_AVAILABLE_CAPABILITIES_CONSTRAINED_HIGH_SPEED_VIDEO:  // NOLINT(whitespace/line_length)
              ss << "HIGHT_SPEED_VIDEO";
              break;
            default:
              ss << "unknown(" << it << ")";
          }
        }
        return ss.str();
      };
      ASSERT_EQ(0, find_camera_metadata_ro_entry(characteristics, key, &entry))
          << "Key " << get_camera_metadata_tag_name(key)
          << " must be in characteristics for capabilities "
          << PrintCapabilities();
    }
  } else {
    if (actual_hw_level == ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_LEGACY &&
        hw_level != IGNORE_HARDWARE_LEVEL) {
      auto result = find_camera_metadata_ro_entry(characteristics, key, &entry);
      if (result == 0)
        LOGF(WARNING)
            << "Key " << get_camera_metadata_tag_name(key)
            << " is not required for LEGACY devices but still appears";
    }
    // OK: Key may or may not be present.
  }
}

static void ExpectKeyAvailable(camera_metadata_t* c,
                               int32_t key,
                               uint8_t hw_level,
                               uint8_t capability) {
  return ExpectKeyAvailable(c, key, hw_level, std::vector<uint8_t>{capability});
}

TEST_F(Camera3ModuleFixture, StaticKeysTest) {
// Reference:
// camera2/cts/ExtendedCameraCharacteristicsTest.java#testKeys
#define IGNORE_CAPABILITY -1
  for (int cam_id = 0; cam_id < cam_module_.GetNumberOfCameras(); cam_id++) {
    camera_info info;
    ASSERT_EQ(0, cam_module_.GetCameraInfo(cam_id, &info))
        << "Can't get camera info for " << cam_id;
    auto c = const_cast<camera_metadata_t*>(info.static_camera_characteristics);

    // The BACKWARD_COMPATIBLE capability must always be defined for HALv3:
    // https://source.android.com/devices/camera/versioning#camera_api2
    EXPECT_TRUE(AreAllCapabilitiesSupported(
        c, {ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE}));

    ExpectKeyAvailable(
        c, ANDROID_COLOR_CORRECTION_AVAILABLE_ABERRATION_MODES,
        IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(
        c, ANDROID_CONTROL_AVAILABLE_MODES, IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(
        c, ANDROID_CONTROL_AE_AVAILABLE_ANTIBANDING_MODES,
        IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(
        c, ANDROID_CONTROL_AE_AVAILABLE_MODES, IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(
        c, ANDROID_CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES,
        IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(
        c, ANDROID_CONTROL_AE_COMPENSATION_RANGE, IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(
        c, ANDROID_CONTROL_AE_COMPENSATION_STEP, IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(
        c, ANDROID_CONTROL_AE_LOCK_AVAILABLE, IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(
        c, ANDROID_CONTROL_AF_AVAILABLE_MODES, IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(
        c, ANDROID_CONTROL_AVAILABLE_EFFECTS, IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(
        c, ANDROID_CONTROL_AVAILABLE_SCENE_MODES, IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(
        c, ANDROID_CONTROL_AVAILABLE_VIDEO_STABILIZATION_MODES,
        IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(
        c, ANDROID_CONTROL_AWB_AVAILABLE_MODES, IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(
        c, ANDROID_CONTROL_AWB_LOCK_AVAILABLE, IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    // TODO(hywu): ANDROID_CONTROL_MAX_REGIONS_AE,
    //             ANDROID_CONTROL_MAX_REGIONS_AF,
    //             ANDROID_CONTROL_MAX_REGIONS_AWB
    ExpectKeyAvailable(c, ANDROID_EDGE_AVAILABLE_EDGE_MODES,
                       ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_FULL,
                       IGNORE_CAPABILITY);
    ExpectKeyAvailable(
        c, ANDROID_FLASH_INFO_AVAILABLE, IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(c, ANDROID_HOT_PIXEL_AVAILABLE_HOT_PIXEL_MODES,
                       IGNORE_HARDWARE_LEVEL,
                       ANDROID_REQUEST_AVAILABLE_CAPABILITIES_RAW);
    ExpectKeyAvailable(
        c, ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL, IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(
        c, ANDROID_JPEG_AVAILABLE_THUMBNAIL_SIZES, IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(
        c, ANDROID_LENS_FACING, IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(c, ANDROID_LENS_INFO_AVAILABLE_APERTURES,
                       ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_FULL,
                       ANDROID_REQUEST_AVAILABLE_CAPABILITIES_MANUAL_SENSOR);
    ExpectKeyAvailable(c, ANDROID_LENS_INFO_AVAILABLE_FILTER_DENSITIES,
                       ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_FULL,
                       ANDROID_REQUEST_AVAILABLE_CAPABILITIES_MANUAL_SENSOR);
    ExpectKeyAvailable(
        c, ANDROID_LENS_INFO_AVAILABLE_FOCAL_LENGTHS, IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(
        c, ANDROID_LENS_INFO_AVAILABLE_OPTICAL_STABILIZATION,
        ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_LIMITED,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(c, ANDROID_LENS_INFO_FOCUS_DISTANCE_CALIBRATION,
                       ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_LIMITED,
                       ANDROID_REQUEST_AVAILABLE_CAPABILITIES_MANUAL_SENSOR);
    ExpectKeyAvailable(
        c, ANDROID_LENS_INFO_HYPERFOCAL_DISTANCE,
        ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_LIMITED,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(
        c, ANDROID_LENS_INFO_MINIMUM_FOCUS_DISTANCE,
        ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_LIMITED,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(
        c, ANDROID_NOISE_REDUCTION_AVAILABLE_NOISE_REDUCTION_MODES,
        IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(
        c, ANDROID_REQUEST_AVAILABLE_CAPABILITIES, IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(
        c, ANDROID_REQUEST_MAX_NUM_INPUT_STREAMS, IGNORE_HARDWARE_LEVEL,
        std::vector<uint8_t>{
            ANDROID_REQUEST_AVAILABLE_CAPABILITIES_YUV_REPROCESSING,
            ANDROID_REQUEST_AVAILABLE_CAPABILITIES_PRIVATE_REPROCESSING});
    ExpectKeyAvailable(
        c, ANDROID_REQUEST_PARTIAL_RESULT_COUNT, IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(
        c, ANDROID_REQUEST_PIPELINE_MAX_DEPTH, IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(
        c, ANDROID_SCALER_AVAILABLE_MAX_DIGITAL_ZOOM, IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(
        c, ANDROID_SCALER_CROPPING_TYPE, IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(
        c, ANDROID_SENSOR_AVAILABLE_TEST_PATTERN_MODES, IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(c, ANDROID_SENSOR_BLACK_LEVEL_PATTERN,
                       ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_FULL,
                       std::vector<uint8_t>{
                           ANDROID_REQUEST_AVAILABLE_CAPABILITIES_MANUAL_SENSOR,
                           ANDROID_REQUEST_AVAILABLE_CAPABILITIES_RAW});
    ExpectKeyAvailable(c, ANDROID_SENSOR_CALIBRATION_TRANSFORM1,
                       IGNORE_HARDWARE_LEVEL,
                       ANDROID_REQUEST_AVAILABLE_CAPABILITIES_RAW);
    ExpectKeyAvailable(c, ANDROID_SENSOR_COLOR_TRANSFORM1,
                       IGNORE_HARDWARE_LEVEL,
                       ANDROID_REQUEST_AVAILABLE_CAPABILITIES_RAW);
    ExpectKeyAvailable(c, ANDROID_SENSOR_FORWARD_MATRIX1, IGNORE_HARDWARE_LEVEL,
                       ANDROID_REQUEST_AVAILABLE_CAPABILITIES_RAW);
    ExpectKeyAvailable(
        c, ANDROID_SENSOR_INFO_ACTIVE_ARRAY_SIZE, IGNORE_HARDWARE_LEVEL,
        std::vector<uint8_t>{
            ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE,
            ANDROID_REQUEST_AVAILABLE_CAPABILITIES_RAW});
    ExpectKeyAvailable(c, ANDROID_SENSOR_INFO_COLOR_FILTER_ARRANGEMENT,
                       ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_FULL,
                       ANDROID_REQUEST_AVAILABLE_CAPABILITIES_RAW);
    ExpectKeyAvailable(c, ANDROID_SENSOR_INFO_EXPOSURE_TIME_RANGE,
                       ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_FULL,
                       ANDROID_REQUEST_AVAILABLE_CAPABILITIES_MANUAL_SENSOR);
    ExpectKeyAvailable(c, ANDROID_SENSOR_INFO_MAX_FRAME_DURATION,
                       ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_FULL,
                       ANDROID_REQUEST_AVAILABLE_CAPABILITIES_MANUAL_SENSOR);
    ExpectKeyAvailable(
        c, ANDROID_SENSOR_INFO_PHYSICAL_SIZE, IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(
        c, ANDROID_SENSOR_INFO_PIXEL_ARRAY_SIZE, IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(c, ANDROID_SENSOR_INFO_SENSITIVITY_RANGE,
                       ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_FULL,
                       ANDROID_REQUEST_AVAILABLE_CAPABILITIES_MANUAL_SENSOR);
    ExpectKeyAvailable(c, ANDROID_SENSOR_INFO_WHITE_LEVEL,
                       IGNORE_HARDWARE_LEVEL,
                       ANDROID_REQUEST_AVAILABLE_CAPABILITIES_RAW);
    ExpectKeyAvailable(
        c, ANDROID_SENSOR_INFO_TIMESTAMP_SOURCE, IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(c, ANDROID_SENSOR_MAX_ANALOG_SENSITIVITY,
                       ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_FULL,
                       ANDROID_REQUEST_AVAILABLE_CAPABILITIES_MANUAL_SENSOR);
    ExpectKeyAvailable(
        c, ANDROID_SENSOR_ORIENTATION, IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(c, ANDROID_SENSOR_REFERENCE_ILLUMINANT1,
                       IGNORE_HARDWARE_LEVEL,
                       ANDROID_REQUEST_AVAILABLE_CAPABILITIES_RAW);
    ExpectKeyAvailable(
        c, ANDROID_SHADING_AVAILABLE_MODES,
        ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_LIMITED,
        std::vector<uint8_t>{
            ANDROID_REQUEST_AVAILABLE_CAPABILITIES_MANUAL_POST_PROCESSING,
            ANDROID_REQUEST_AVAILABLE_CAPABILITIES_RAW});
    ExpectKeyAvailable(
        c, ANDROID_STATISTICS_INFO_AVAILABLE_FACE_DETECT_MODES,
        IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(c, ANDROID_STATISTICS_INFO_AVAILABLE_HOT_PIXEL_MAP_MODES,
                       IGNORE_HARDWARE_LEVEL,
                       ANDROID_REQUEST_AVAILABLE_CAPABILITIES_RAW);
    ExpectKeyAvailable(c,
                       ANDROID_STATISTICS_INFO_AVAILABLE_LENS_SHADING_MAP_MODES,
                       ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_LIMITED,
                       ANDROID_REQUEST_AVAILABLE_CAPABILITIES_RAW);
    ExpectKeyAvailable(
        c, ANDROID_STATISTICS_INFO_MAX_FACE_COUNT, IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(
        c, ANDROID_SYNC_MAX_LATENCY, IGNORE_HARDWARE_LEVEL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
    ExpectKeyAvailable(
        c, ANDROID_TONEMAP_AVAILABLE_TONE_MAP_MODES,
        ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_FULL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_MANUAL_POST_PROCESSING);
    ExpectKeyAvailable(
        c, ANDROID_TONEMAP_MAX_CURVE_POINTS,
        ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_FULL,
        ANDROID_REQUEST_AVAILABLE_CAPABILITIES_MANUAL_POST_PROCESSING);
    camera_metadata_ro_entry_t entry;
    if (find_camera_metadata_ro_entry(c, ANDROID_SENSOR_REFERENCE_ILLUMINANT2,
                                      &entry) == 0) {
      ExpectKeyAvailable(c, ANDROID_SENSOR_REFERENCE_ILLUMINANT2,
                         IGNORE_HARDWARE_LEVEL,
                         ANDROID_REQUEST_AVAILABLE_CAPABILITIES_RAW);
      ExpectKeyAvailable(c, ANDROID_SENSOR_COLOR_TRANSFORM2,
                         IGNORE_HARDWARE_LEVEL,
                         ANDROID_REQUEST_AVAILABLE_CAPABILITIES_RAW);
      ExpectKeyAvailable(c, ANDROID_SENSOR_CALIBRATION_TRANSFORM2,
                         IGNORE_HARDWARE_LEVEL,
                         ANDROID_REQUEST_AVAILABLE_CAPABILITIES_RAW);
      ExpectKeyAvailable(c, ANDROID_SENSOR_FORWARD_MATRIX2,
                         IGNORE_HARDWARE_LEVEL,
                         ANDROID_REQUEST_AVAILABLE_CAPABILITIES_RAW);
    }
  }
}

TEST_F(Camera3ModuleFixture, StreamConfigurationMapTest) {
  // Reference:
  // camera2/cts/ExtendedCameraCharacteristicsTest.java#testStreamConfigurationMap
  const int64_t kToleranceFactor = 2;
  for (int cam_id = 0; cam_id < cam_module_.GetNumberOfCameras(); cam_id++) {
    camera_info info;
    ASSERT_EQ(0, cam_module_.GetCameraInfo(cam_id, &info))
        << "Can't get camera info for " << cam_id;

    std::vector<int32_t> available_formats =
        cam_module_.GetOutputFormats(cam_id);
    for (const auto& format : available_formats) {
      std::vector<ResolutionInfo> available_resolutions =
          cam_module_.GetSortedOutputResolutions(cam_id, format);
      size_t resolution_count = available_resolutions.size();
      for (size_t i = 0; i < resolution_count; i++) {
        int64_t stall_duration = cam_module_.GetOutputStallDuration(
            cam_id, format, available_resolutions[i]);
        if (stall_duration >= 0) {
          if (format == HAL_PIXEL_FORMAT_YCbCr_420_888) {
            EXPECT_EQ(0, stall_duration)
                << "YUV_420_888 may not have a non-zero stall duration";
          } else if (format == HAL_PIXEL_FORMAT_BLOB) {
            // Stall duration should be in a reasonable range: larger size
            // should normally have larger stall duration
            if (i > 0) {
              int64_t prev_duration = cam_module_.GetOutputStallDuration(
                  cam_id, format, available_resolutions[i - 1]);
              EXPECT_LE(prev_duration / kToleranceFactor, stall_duration)
                  << "Stall duration (format " << format << " and size "
                  << available_resolutions[i].Width() << "x"
                  << available_resolutions[i].Height()
                  << ") is not in the right range";
            }
          }
        } else {
          ADD_FAILURE() << "Negative stall duration for format " << format;
        }

        int64_t min_duration = cam_module_.GetOutputMinFrameDuration(
            cam_id, format, available_resolutions[i]);
        if (AreAllCapabilitiesSupported(
                const_cast<camera_metadata_t*>(
                    info.static_camera_characteristics),
                std::vector<uint8_t>{
                    ANDROID_REQUEST_AVAILABLE_CAPABILITIES_MANUAL_SENSOR})) {
          EXPECT_LT(0, min_duration)
              << "MANUAL_SENSOR capability, need positive min frame duration "
                 "for format "
              << format << " and size " << available_resolutions[i].Width()
              << "x" << available_resolutions[i].Height();
        } else {
          EXPECT_LE(0, min_duration)
              << "Need non-negative min frame duration for format " << format
              << " and size " << available_resolutions[i].Width() << "x"
              << available_resolutions[i].Height();
        }
      }
    }
  }
}

TEST_F(Camera3ModuleFixture, ChromeOSRequiredResolution) {
  const int required_formats[] = {HAL_PIXEL_FORMAT_BLOB,
                                  HAL_PIXEL_FORMAT_YCbCr_420_888,
                                  HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED};
  const ResolutionInfo required_resolutions[] = {ResolutionInfo(1600, 1200),
                                                 ResolutionInfo(1280, 960)};
  for (const auto& cam_id : cam_module_.GetCameraIds()) {
    camera_info info;
    ASSERT_EQ(0, cam_module_.GetCameraInfo(cam_id, &info))
        << "Can't get camera info for " << cam_id;
    camera_metadata_ro_entry_t entry;
    ASSERT_EQ(
        0,
        find_camera_metadata_ro_entry(
            const_cast<camera_metadata_t*>(info.static_camera_characteristics),
            ANDROID_SENSOR_INFO_ACTIVE_ARRAY_SIZE, &entry))
        << "Can't find the sensor active array size.";
    ASSERT_GE(entry.count, 2);
    ResolutionInfo active_array(entry.data.i32[0], entry.data.i32[1]);
    for (const auto& resolution : required_resolutions) {
      if ((active_array.Width() >= resolution.Width()) &&
          (active_array.Height() >= resolution.Height())) {
        for (const auto& format : required_formats) {
          auto resolutions =
              cam_module_.GetSortedOutputResolutions(cam_id, format);
          EXPECT_NE(resolutions.end(), std::find(resolutions.begin(),
                                                 resolutions.end(), resolution))
              << "Required size " << resolution.Width() << "x"
              << resolution.Height() << " not found for format " << format
              << " for camera " << cam_id;
        }
      }
    }
  }
}

}  // namespace camera3_test

static void AddGtestFilterNegativePattern(std::string negative) {
  using ::testing::GTEST_FLAG(filter);

  GTEST_FLAG(filter)
      .append((GTEST_FLAG(filter).find('-') == std::string::npos) ? "-" : ":")
      .append(negative);
}

// Return -ENOENT for no facing specified, -EINVAL for invalid facing name.
static int GetCmdLineTestCameraFacing(const base::CommandLine& cmd_line) {
  const std::string facing_names[] = {"back", "front"};
  const auto& facing_name = cmd_line.GetSwitchValueASCII("camera_facing");
  if (facing_name.empty())
    return -ENOENT;
  int idx = std::distance(
      facing_names,
      std::find(facing_names, facing_names + std::size(facing_names),
                facing_name));
  if (idx == std::size(facing_names)) {
    ADD_FAILURE() << "Invalid facing name: " << facing_name;
    return -EINVAL;
  }
  return idx;
}

// Return true if connect_to_camera_service is true, else false
static bool GetCmdLineTestConnectToCameraService(
    const base::CommandLine& cmd_line) {
  const auto& connect_to_camera_service =
      cmd_line.GetSwitchValueASCII("connect_to_camera_service");
  // Camera_service is connected by default if |camera_hal_path| is not
  // specified.
  if (connect_to_camera_service.empty()) {
    return cmd_line.GetSwitchValuePath("camera_hal_path").empty();
  }
  std::string str(connect_to_camera_service);
  std::transform(str.begin(), str.end(), str.begin(), ::tolower);
  if (str == "true" || str == "1") {
    return true;
  } else if (str == "false" || str == "0") {
    return false;
  } else {
    ADD_FAILURE() << "Invalid connect_to_camera_service option: "
                  << connect_to_camera_service;
    return false;
  }
}

bool InitializeTest(int* argc,
                    char*** argv,
                    cros::CameraMojoChannelManagerToken* token,
                    void** cam_hal_handle,
                    cros::cros_camera_hal_t** cros_camera_hal) {
  // Set up logging so we can enable VLOGs with -v / --vmodule.
  base::CommandLine::Init(*argc, *argv);
  logging::LoggingSettings settings;
  settings.logging_dest =
      logging::LOG_TO_SYSTEM_DEBUG_LOG | logging::LOG_TO_STDERR;
  LOG_ASSERT(logging::InitLogging(settings));

  if (geteuid() == 0) {
    LOGF(WARNING)
        << "Running tests as root might leak some root owned resources, which "
           "cannot be accessed by the user arc-camera.";
  }

  base::CommandLine* cmd_line = base::CommandLine::ForCurrentProcess();
  base::FilePath camera_hal_path =
      cmd_line->GetSwitchValuePath("camera_hal_path");
  int facing = GetCmdLineTestCameraFacing(*cmd_line);
  bool connect_to_camera_service =
      GetCmdLineTestConnectToCameraService(*cmd_line);
  if (!camera_hal_path.empty() && connect_to_camera_service) {
    LOGF(ERROR) << "Cannot specify both --camera_hal_path and "
                   "--connect_to_camera_service=true.";
    return false;
  }

  if (facing != -ENOENT) {
    if (facing == -EINVAL) {
      LOGF(ERROR) << "Invalid camera facing name.";
      return false;
    } else if (!camera_hal_path.empty() ||
               !camera3_test::GetCmdLineTestCameraIds().empty()) {
      LOGF(ERROR) << "Cannot specify both --camera_hal_path/--camera_ids and "
                     "--camera_facing.";
      return false;
    }
  } else if (camera_hal_path.empty()) {
    std::vector<base::FilePath> camera_hal_paths = cros::GetCameraHalPaths();

    LOGF(INFO) << "camera_hal_path unspecified. Connecting to the camera "
                  "service via Mojo. To test against the HAL directly, add "
                  "`--camera_hal_path=` into command line argument.";
    LOGF(INFO) << "List of possible paths:";
    for (const auto& path : camera_hal_paths) {
      LOGF(INFO) << path.value();
    }
  }

  if (!connect_to_camera_service) {
    // Open camera HAL and get module
    if (facing != -ENOENT) {
      camera3_test::GetModuleThread().Start();
      camera3_test::InitCameraModuleByFacing(facing, token, cam_hal_handle,
                                             cros_camera_hal, &camera_hal_path);
    } else if (!camera_hal_path.empty()) {
      camera3_test::GetModuleThread().Start();
      camera3_test::InitCameraModuleByHalPath(camera_hal_path, token,
                                              cam_hal_handle, cros_camera_hal);
    } else {
      LOGF(ERROR) << "Cannot specify both --camera_hal_path/--camera_ids and "
                     "--camera_facing.";
      return false;
    }
  } else {
    // Run camera3 module test through camera_service
    camera3_test::CameraHalClient* camera_hal_client =
        camera3_test::CameraHalClient::GetInstance();
    if (camera_hal_client->Start(
            camera3_test::CameraModuleCallbacksAux::GetInstance()) != 0) {
      return false;
    }
    if (facing != -ENOENT) {
      EnableCameraFacing(facing, camera_hal_client, &camera_hal_path);
    }
  }

  camera3_test::InitPerfLog();

  // Initialize gtest
  ::testing::InitGoogleTest(argc, *argv);
  if (testing::Test::HasFailure()) {
    return false;
  }

  if (camera_hal_path.value().find("usb") != std::string::npos) {
    // Skip 3A algorithm sandbox IPC tests for USB HAL
    AddGtestFilterNegativePattern("*Camera3AlgoSandboxIPCErrorTest*");
  }

  const std::vector<std::string> kIgnoreSensorOrientationTestBoards = {
      "nocturne",
      "scarlet",
  };
  const std::vector<std::string> kIgnoreSensorOrientationTestModels = {
      "collis",
      "jelboz",
      "jelboz360",
  };
  std::string board = base::SysInfo::GetLsbReleaseBoard();
  std::optional<cros::DeviceConfig> config = cros::DeviceConfig::Create();
  std::string model = config.has_value() ? config->GetModelName() : "";
  if (base::Contains(kIgnoreSensorOrientationTestBoards, board) ||
      base::Contains(kIgnoreSensorOrientationTestModels, model)) {
    LOGF(INFO) << "Ignore SensorOrientationTest on " << board << "/" << model;
    AddGtestFilterNegativePattern("*SensorOrientationTest/*");
  }

  return true;
}

#ifdef FUZZER

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
  void* cam_hal_handle = NULL;
  std::unique_ptr<cros::CameraMojoChannelManagerToken> mojo_manager_token(
      cros::CameraMojoChannelManagerToken::CreateInstance());
  cros::cros_camera_hal_t* cros_camera_hal;
  if (!InitializeTest(argc, argv, mojo_manager_token.get(), &cam_hal_handle,
                      &cros_camera_hal)) {
    exit(EXIT_FAILURE);
  }

  ::testing::TestEventListeners& listeners =
      ::testing::UnitTest::GetInstance()->listeners();
  delete listeners.Release(listeners.default_result_printer());
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  camera3_test::Camera3TestDataForwarder::GetInstance()->SetData(Data, Size);
  std::ignore = RUN_ALL_TESTS();
  return 0;
}

#else
int main(int argc, char** argv) {
  // We have to make it leaky until the lifetime conflict in b/119926433 is
  // resolved.
  base::NoDestructor<base::AtExitManager> leaky_at_exit_manager;
  int result = EXIT_FAILURE;
  void* cam_hal_handle = NULL;

  brillo::BaseMessageLoop message_loop;
  message_loop.SetAsCurrent();

  cros::cros_camera_hal_t* cros_camera_hal = nullptr;
  std::unique_ptr<cros::CameraMojoChannelManagerToken> mojo_manager_token(
      cros::CameraMojoChannelManagerToken::CreateInstance());
  if (InitializeTest(&argc, &argv, mojo_manager_token.get(), &cam_hal_handle,
                     &cros_camera_hal)) {
    result = RUN_ALL_TESTS();
  }

  camera3_test::GetModuleThread().Stop();

  // TODO(b/151270948): We should report error here if it fails to find the
  // symbol once all camera HALs have implemented the interface.
  if (cros_camera_hal != nullptr) {
    cros_camera_hal->tear_down();
  }
  mojo_manager_token.reset();

  // Close Camera HAL
  if (cam_hal_handle && dlclose(cam_hal_handle) != 0) {
    PLOGF(ERROR) << "Failed to dlclose(cam_hal_handle)";
    result = EXIT_FAILURE;
  }

  return result;
}
#endif
