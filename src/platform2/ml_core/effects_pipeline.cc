// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml_core/effects_pipeline.h"

#include <optional>
#include <utility>

#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/scoped_native_library.h>
#include <ml_core/effects_pipeline_bindings.h>
#include <session_manager/dbus-proxies.h>

#include "ml_core/opencl_caching/constants.h"

namespace {

using org::chromium::SessionManagerInterfaceProxy;

constexpr char kLibraryName[] = "libcros_ml_core_internal.so";

std::optional<base::ScopedNativeLibrary> g_library;
cros_ml_effects_CreateEffectsPipelineFn g_create_fn = nullptr;
cros_ml_effects_DeleteEffectsPipelineFn g_delete_fn = nullptr;
cros_ml_effects_ProcessFrameFn g_process_fn = nullptr;
cros_ml_effects_WaitFn g_wait_fn = nullptr;
cros_ml_effects_SetRenderedImageObserverFn g_set_rendered_image_observer_fn =
    nullptr;
cros_ml_effects_SetEffectFn g_set_effect_fn = nullptr;
cros_ml_effects_SetLogObserverFn g_set_log_observer_fn = nullptr;

bool EnsurePipelineLibraryLoaded(const base::FilePath& dlc_root_path) {
  if (g_library && g_library->is_valid()) {
    return true;
  }

#ifdef USE_LOCAL_ML_CORE_INTERNAL
  // This should be /usr/local/lib on boards with 32-bit ARM userspace, but
  // currently we only enable the feature on 64-bit boards.
  base::FilePath lib_path =
      base::FilePath("/usr/local/lib64").Append(kLibraryName);
#else
  base::FilePath lib_path = dlc_root_path.Append(kLibraryName);
#endif
  base::NativeLibraryOptions native_library_options;
  base::NativeLibraryLoadError load_error;
  native_library_options.prefer_own_symbols = true;
  g_library.emplace(base::LoadNativeLibraryWithOptions(
      lib_path, native_library_options, &load_error));

  if (!g_library->is_valid()) {
    LOG(ERROR) << "Pipeline library load error: " << load_error.ToString();
    return false;
  }

  LOG(INFO) << "Loading pipeline library from: " << lib_path;

  g_create_fn = reinterpret_cast<cros_ml_effects_CreateEffectsPipelineFn>(
      g_library->GetFunctionPointer("cros_ml_effects_CreateEffectsPipeline"));
  g_delete_fn = reinterpret_cast<cros_ml_effects_DeleteEffectsPipelineFn>(
      g_library->GetFunctionPointer("cros_ml_effects_DeleteEffectsPipeline"));
  g_process_fn = reinterpret_cast<cros_ml_effects_ProcessFrameFn>(
      g_library->GetFunctionPointer("cros_ml_effects_ProcessFrame"));
  g_wait_fn = reinterpret_cast<cros_ml_effects_WaitFn>(
      g_library->GetFunctionPointer("cros_ml_effects_Wait"));
  g_set_rendered_image_observer_fn =
      reinterpret_cast<cros_ml_effects_SetRenderedImageObserverFn>(
          g_library->GetFunctionPointer(
              "cros_ml_effects_SetRenderedImageObserver"));
  g_set_effect_fn = reinterpret_cast<cros_ml_effects_SetEffectFn>(
      g_library->GetFunctionPointer("cros_ml_effects_SetEffect"));
  g_set_log_observer_fn = reinterpret_cast<cros_ml_effects_SetLogObserverFn>(
      g_library->GetFunctionPointer("cros_ml_effects_SetLogObserver"));

  bool load_ok = (g_create_fn != nullptr) && (g_delete_fn != nullptr) &&
                 (g_process_fn != nullptr) && (g_wait_fn != nullptr) &&
                 (g_set_rendered_image_observer_fn != nullptr) &&
                 (g_set_effect_fn != nullptr);

  if (!load_ok) {
    DLOG(ERROR) << "g_create_fn: " << g_create_fn;
    DLOG(ERROR) << "g_delete_fn: " << g_delete_fn;
    DLOG(ERROR) << "g_process_fn: " << g_process_fn;
    DLOG(ERROR) << "g_wait_fn: " << g_wait_fn;
    DLOG(ERROR) << "g_set_rendered_image_observer_fn: "
                << g_set_rendered_image_observer_fn;
    DLOG(ERROR) << "g_set_effect_fn: " << g_set_effect_fn;
    DLOG(ERROR) << "g_set_log_observer_fn: " << g_set_log_observer_fn;

    LOG(ERROR) << "Pipeline cannot load the expected functions";
    g_library.reset();
    return false;
  }

  return true;
}

class EffectsPipelineImpl : public cros::EffectsPipeline {
 public:
  ~EffectsPipelineImpl() override {
    if (pipeline_ && g_delete_fn) {
      g_delete_fn(pipeline_);
    }
  }

  bool ProcessFrame(int64_t timestamp,
                    GLuint frame_texture,
                    uint32_t frame_width,
                    uint32_t frame_height) override {
    CHECK(g_process_fn);
    frames_started_ = true;
    return g_process_fn(pipeline_, timestamp, frame_texture, frame_width,
                        frame_height);
  }

  bool Wait() override {
    CHECK(g_wait_fn);
    return g_wait_fn(pipeline_);
  }

  bool SetRenderedImageObserver(
      std::unique_ptr<cros::ProcessedFrameObserver> observer) override {
    if (!frames_started_) {
      rendered_image_observer_ = std::move(observer);
      return true;
    }
    return false;
  }

  // TODO(b:237964122) Consider converting effects_config to a protobuf
  void SetEffect(cros::EffectsConfig* effects_config,
                 void (*callback)(bool)) override {
    CHECK(g_set_effect_fn);
    g_set_effect_fn(pipeline_, effects_config, callback);
  }

 protected:
  EffectsPipelineImpl() {}
  bool Initialize(const base::FilePath& dlc_root_path,
                  EGLContext share_context,
                  const base::FilePath& caching_dir_override) {
    if (!EnsurePipelineLibraryLoaded(dlc_root_path)) {
      return false;
    }

    std::string cache_dir(caching_dir_override.empty()
                              ? cros::kOpenCLCachingDir
                              : caching_dir_override.value());
    pipeline_ = g_create_fn(share_context, cache_dir.c_str());
    LOG(INFO) << "Pipeline created, cache_dir: " << cache_dir;
    g_set_rendered_image_observer_fn(
        pipeline_, this, &EffectsPipelineImpl::RenderedImageFrameHandler);
    g_set_log_observer_fn(pipeline_, &EffectsPipelineImpl::OnLogMessage);

    return true;
  }

 private:
  static void RenderedImageFrameHandler(void* handler,
                                        int64_t timestamp,
                                        GLuint frame_texture,
                                        uint32_t frame_width,
                                        uint32_t frame_height) {
    EffectsPipelineImpl* pipeline = static_cast<EffectsPipelineImpl*>(handler);
    if (pipeline->rendered_image_observer_) {
      pipeline->rendered_image_observer_->OnFrameProcessed(
          timestamp, frame_texture, frame_width, frame_height);
    }
  }

  static void OnLogMessage(cros_ml_effects_LogSeverity severity,
                           const char* msg,
                           size_t len) {
    switch (severity) {
      default:
        [[fallthrough]];
      case cros_ml_effects_LogSeverity_Info:
        LOG(INFO) << std::string(msg, len);
        break;
      case cros_ml_effects_LogSeverity_Warning:
        LOG(WARNING) << std::string(msg, len);
        break;
      case cros_ml_effects_LogSeverity_Error:
        LOG(ERROR) << std::string(msg, len);
        break;
      case cros_ml_effects_LogSeverity_Fatal:
        LOG(FATAL) << std::string(msg, len);
        break;
    }
  }

  void* pipeline_ = nullptr;
  bool frames_started_ = false;

  std::unique_ptr<cros::ProcessedFrameObserver> rendered_image_observer_;

  friend class EffectsPipeline;
};

}  // namespace

namespace cros {

std::unique_ptr<EffectsPipeline> EffectsPipeline::Create(
    const base::FilePath& dlc_root_path,
    EGLContext share_context,
    const base::FilePath& caching_dir_override) {
  auto pipeline =
      std::unique_ptr<EffectsPipelineImpl>(new EffectsPipelineImpl());
  if (!pipeline->Initialize(dlc_root_path, share_context,
                            caching_dir_override)) {
    return nullptr;
  }
  return pipeline;
}

}  // namespace cros
