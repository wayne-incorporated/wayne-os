// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/libvda/encode/gpu/gpu_vea_impl.h"

#include <utility>

#include <base/check.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <mojo/public/cpp/system/platform_handle.h>

#include "arc/vm/libvda/gbm_util.h"
#include "arc/vm/libvda/gpu/format_util.h"
#include "arc/vm/libvda/gpu/mojom/video_common.mojom.h"
#include "arc/vm/libvda/gpu/mojom/video_encode_accelerator.mojom.h"

namespace arc {
namespace {

inline arc::mojom::VideoPixelFormat ConvertInputFormatToMojoFormat(
    video_pixel_format_t format) {
  switch (format) {
    case YV12:
      return arc::mojom::VideoPixelFormat::PIXEL_FORMAT_YV12;
    case NV12:
      return arc::mojom::VideoPixelFormat::PIXEL_FORMAT_NV12;
    default:
      NOTREACHED();
  }
}

inline vea_error_t ConvertMojoError(
    arc::mojom::VideoEncodeAccelerator::Error error) {
  switch (error) {
    case arc::mojom::VideoEncodeAccelerator::Error::kIllegalStateError:
      return ILLEGAL_STATE_ERROR;
    case arc::mojom::VideoEncodeAccelerator::Error::kInvalidArgumentError:
      return INVALID_ARGUMENT_ERROR;
    case arc::mojom::VideoEncodeAccelerator::Error::kPlatformFailureError:
      return PLATFORM_FAILURE_ERROR;
    default:
      NOTREACHED();
  }
}

inline arc::mojom::BitratePtr ConvertToMojoBitrate(
    const vea_bitrate_t& vea_bitrate) {
  arc::mojom::BitratePtr bitrate;
  switch (vea_bitrate.mode) {
    case VBR: {
      arc::mojom::VariableBitratePtr variable_bitrate =
          arc::mojom::VariableBitrate::New();
      variable_bitrate->target = vea_bitrate.target;
      variable_bitrate->peak = vea_bitrate.peak;
      bitrate = arc::mojom::Bitrate::NewVariable(std::move(variable_bitrate));
      break;
    }
    case CBR: {
      arc::mojom::ConstantBitratePtr constant_bitrate =
          arc::mojom::ConstantBitrate::New();
      constant_bitrate->target = vea_bitrate.target;
      bitrate = arc::mojom::Bitrate::NewConstant(std::move(constant_bitrate));
      break;
    }
    default:
      NOTREACHED();
      break;
  }
  return bitrate;
}

class GpuVeaContext : public VeaContext, arc::mojom::VideoEncodeClient {
 public:
  // Create a new GpuVeaContext. Must be called on |ipc_task_runner|.
  GpuVeaContext(
      const scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner,
      mojo::Remote<arc::mojom::VideoEncodeAccelerator> remote_vea);
  ~GpuVeaContext();

  using InitializeCallback = base::OnceCallback<void(bool)>;

  // Initializes the VDA context object. When complete, callback is called with
  // the boolean parameter set to true. Must be called on |ipc_task_runner_|.
  void Initialize(vea_config_t* config, InitializeCallback callback);

  // VeaContext overrides.
  int Encode(vea_input_buffer_id_t input_buffer_id,
             base::ScopedFD fd,
             size_t num_planes,
             video_frame_plane_t* planes,
             uint64_t timestamp,
             bool force_keyframe) override;

  int UseOutputBuffer(vea_output_buffer_id_t output_buffer_id,
                      base::ScopedFD fd,
                      uint32_t offset,
                      uint32_t size) override;

  int RequestEncodingParamsChange(vea_bitrate_t bitrate,
                                  uint32_t framerate) override;

  int Flush() override;

  // arc::mojom::VideoEncodeClient overrides.
  void RequireBitstreamBuffers(uint32_t input_count,
                               arc::mojom::SizePtr input_coded_size,
                               uint32_t output_buffer_size) override;

  void NotifyError(arc::mojom::VideoEncodeAccelerator::Error error) override;

 private:
  // Callback for VideoEncodeAccelerator connection errors.
  void OnVeaError(uint32_t custom_reason, const std::string& description);

  // Callback for VideoEncodeClient connection errors.
  void OnVeaClientError(uint32_t custom_reason, const std::string& description);

  // Callback invoked when VideoEncodeAccelerator::Initialize completes.
  void OnInitialized(InitializeCallback,
                     arc::mojom::VideoEncodeAccelerator::Result result);

  void OnInputBufferProcessed(vea_input_buffer_id_t input_buffer_id);
  void OnOutputBufferFilled(vea_output_buffer_id_t output_buffer_id,
                            uint32_t payload_size,
                            bool key_frame,
                            int64_t timestamp);
  void OnFlushDone(bool flush_done);

  void EncodeOnIpcThread(vea_input_buffer_id_t input_buffer_id,
                         base::ScopedFD fd,
                         std::vector<video_frame_plane_t> planes,
                         uint64_t timestamp,
                         bool force_keyframe);

  void UseOutputBufferOnIpcThread(vea_output_buffer_id_t output_buffer_id,
                                  base::ScopedFD fd,
                                  uint32_t offset,
                                  uint32_t size);
  void RequestEncodingParamsChangeOnIpcThread(vea_bitrate_t bitrate,
                                              uint32_t framerate);
  void FlushOnIpcThread();

  scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner_;
  THREAD_CHECKER(ipc_thread_checker_);
  mojo::Remote<arc::mojom::VideoEncodeAccelerator> remote_vea_;
  mojo::Receiver<arc::mojom::VideoEncodeClient> receiver_;

  arc::mojom::VideoPixelFormat default_mojo_input_format_;
};

GpuVeaContext::GpuVeaContext(
    const scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner,
    mojo::Remote<arc::mojom::VideoEncodeAccelerator> remote_vea)
    : ipc_task_runner_(std::move(ipc_task_runner)),
      remote_vea_(std::move(remote_vea)),
      receiver_(this) {
  // Since ipc_thread_checker_ binds to whichever thread it's created on, check
  // that we're on the correct thread first using BelongsToCurrentThread.
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  remote_vea_.set_disconnect_with_reason_handler(
      base::BindRepeating(&GpuVeaContext::OnVeaError, base::Unretained(this)));

  DLOG(INFO) << "Created new GPU context";
}

GpuVeaContext::~GpuVeaContext() {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
}

void GpuVeaContext::Initialize(vea_config_t* config,
                               InitializeCallback callback) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  mojo::PendingRemote<arc::mojom::VideoEncodeClient> remote_client =
      receiver_.BindNewPipeAndPassRemote();
  receiver_.set_disconnect_with_reason_handler(base::BindRepeating(
      &GpuVeaContext::OnVeaClientError, base::Unretained(this)));

  arc::mojom::VideoEncodeAcceleratorConfigPtr mojo_config =
      arc::mojom::VideoEncodeAcceleratorConfig::New();

  default_mojo_input_format_ =
      ConvertInputFormatToMojoFormat(config->input_format);

  mojo_config->input_format = default_mojo_input_format_;
  mojo_config->input_visible_size = arc::mojom::Size::New();
  mojo_config->input_visible_size->width = config->input_visible_width;
  mojo_config->input_visible_size->height = config->input_visible_height;

  mojo_config->output_profile =
      ConvertCodecProfileToMojoProfile(config->output_profile);
  mojo_config->initial_framerate = config->initial_framerate;
  mojo_config->has_initial_framerate = config->has_initial_framerate;
  mojo_config->h264_output_level = config->h264_output_level;
  mojo_config->has_h264_output_level = config->has_h264_output_level;
  mojo_config->storage_type = arc::mojom::VideoFrameStorageType::DMABUF;

  mojo_config->bitrate = ConvertToMojoBitrate(config->bitrate);

  remote_vea_->Initialize(
      std::move(mojo_config), std::move(remote_client),
      base::BindOnce(&GpuVeaContext::OnInitialized, base::Unretained(this),
                     std::move(callback)));
}

void GpuVeaContext::OnInitialized(
    InitializeCallback callback,
    arc::mojom::VideoEncodeAccelerator::Result result) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  // TODO(b/174967467): propagate result to client.
  bool success = (result == mojom::VideoEncodeAccelerator::Result::kSuccess);
  std::move(callback).Run(success);
}

void GpuVeaContext::OnVeaError(uint32_t custom_reason,
                               const std::string& description) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  DLOG(ERROR) << "VideoEncodeAccelerator mojo connection error. custom_reason="
              << custom_reason << " description=" << description;
}

void GpuVeaContext::OnVeaClientError(uint32_t custom_reason,
                                     const std::string& description) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  DLOG(ERROR) << "VideoEncodeClient mojo connection error. custom_reason="
              << custom_reason << " description=" << description;
}

int GpuVeaContext::Encode(vea_input_buffer_id_t input_buffer_id,
                          base::ScopedFD fd,
                          size_t num_planes,
                          video_frame_plane_t* planes,
                          uint64_t timestamp,
                          bool force_keyframe) {
  std::vector<video_frame_plane_t> planes_vector(planes, planes + num_planes);
  ipc_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&GpuVeaContext::EncodeOnIpcThread, base::Unretained(this),
                     input_buffer_id, std::move(fd), std::move(planes_vector),
                     timestamp, force_keyframe));
  return 0;
}

void GpuVeaContext::EncodeOnIpcThread(vea_input_buffer_id_t input_buffer_id,
                                      base::ScopedFD fd,
                                      std::vector<video_frame_plane_t> planes,
                                      uint64_t timestamp,
                                      bool force_keyframe) {
  mojo::ScopedHandle handle_fd = mojo::WrapPlatformFile(std::move(fd));
  if (!handle_fd.is_valid()) {
    LOG(ERROR) << "Invalid input buffer handle.";
    return;
  }

  std::vector<arc::mojom::VideoFramePlanePtr> mojo_planes;
  for (const auto& plane : planes) {
    arc::mojom::VideoFramePlanePtr mojo_plane =
        arc::mojom::VideoFramePlane::New();
    mojo_plane->offset = plane.offset;
    mojo_plane->stride = plane.stride;
    mojo_planes.push_back(std::move(mojo_plane));
  }

  remote_vea_->Encode(default_mojo_input_format_, std::move(handle_fd),
                      std::move(mojo_planes), timestamp, force_keyframe,
                      base::BindOnce(&GpuVeaContext::OnInputBufferProcessed,
                                     base::Unretained(this), input_buffer_id));
}

void GpuVeaContext::OnInputBufferProcessed(
    vea_input_buffer_id_t input_buffer_id) {
  DispatchProcessedInputBuffer(input_buffer_id);
}

int GpuVeaContext::UseOutputBuffer(vea_output_buffer_id_t output_buffer_id,
                                   base::ScopedFD fd,
                                   uint32_t offset,
                                   uint32_t size) {
  ipc_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&GpuVeaContext::UseOutputBufferOnIpcThread,
                                base::Unretained(this), output_buffer_id,
                                std::move(fd), offset, size));
  return 0;
}

void GpuVeaContext::UseOutputBufferOnIpcThread(
    vea_output_buffer_id_t output_buffer_id,
    base::ScopedFD fd,
    uint32_t offset,
    uint32_t size) {
  mojo::ScopedHandle handle_fd = mojo::WrapPlatformFile(std::move(fd));
  if (!handle_fd.is_valid()) {
    LOG(ERROR) << "Invalid output buffer handle.";
    return;
  }

  remote_vea_->UseBitstreamBuffer(
      std::move(handle_fd), offset, size,
      base::BindOnce(&GpuVeaContext::OnOutputBufferFilled,
                     base::Unretained(this), output_buffer_id));
}

void GpuVeaContext::OnOutputBufferFilled(
    vea_output_buffer_id_t output_buffer_id,
    uint32_t payload_size,
    bool key_frame,
    int64_t timestamp) {
  DispatchProcessedOutputBuffer(output_buffer_id, payload_size, key_frame,
                                timestamp);
}

int GpuVeaContext::RequestEncodingParamsChange(vea_bitrate_t bitrate,
                                               uint32_t framerate) {
  ipc_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&GpuVeaContext::RequestEncodingParamsChangeOnIpcThread,
                     base::Unretained(this), bitrate, framerate));
  return 0;
}

void GpuVeaContext::RequestEncodingParamsChangeOnIpcThread(
    vea_bitrate_t bitrate, uint32_t framerate) {
  remote_vea_->RequestEncodingParametersChange(ConvertToMojoBitrate(bitrate),
                                               framerate);
}

int GpuVeaContext::Flush() {
  ipc_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&GpuVeaContext::FlushOnIpcThread, base::Unretained(this)));
  return 0;
}

void GpuVeaContext::FlushOnIpcThread() {
  remote_vea_->Flush(
      base::BindOnce(&GpuVeaContext::OnFlushDone, base::Unretained(this)));
}

void GpuVeaContext::OnFlushDone(bool flush_done) {
  DispatchFlushResponse(flush_done);
}

// VideoEncodeClient implementation function.
void GpuVeaContext::RequireBitstreamBuffers(
    uint32_t input_count,
    arc::mojom::SizePtr input_coded_size,
    uint32_t output_buffer_size) {
  DispatchRequireInputBuffers(input_count, input_coded_size->width,
                              input_coded_size->height, output_buffer_size);
}

// VideoEncodeClient implementation function.
void GpuVeaContext::NotifyError(
    arc::mojom::VideoEncodeAccelerator::Error error) {
  DispatchNotifyError(ConvertMojoError(error));
}

}  // namespace

// static
GpuVeaImpl* GpuVeaImpl::Create(VafConnection* conn) {
  auto impl = std::make_unique<GpuVeaImpl>(conn);
  if (!impl->Initialize()) {
    LOG(ERROR) << "Could not initialize GpuVeaImpl.";
    return nullptr;
  }

  return impl.release();
}

GpuVeaImpl::GpuVeaImpl(VafConnection* conn) : connection_(conn) {
  DLOG(INFO) << "Created GpuVeaImpl.";
}

GpuVeaImpl::~GpuVeaImpl() {
  DLOG(INFO) << "Destroyed GpuVeaImpl.";
}

bool GpuVeaImpl::Initialize() {
  input_formats_ = GetSupportedRawFormats(GbmUsageType::ENCODE);
  if (input_formats_.empty())
    return false;

  ipc_task_runner_ = connection_->GetIpcTaskRunner();
  CHECK(!ipc_task_runner_->BelongsToCurrentThread());

  base::WaitableEvent init_complete_event(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);

  ipc_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&GpuVeaImpl::InitializeOnIpcThread,
                                base::Unretained(this), &init_complete_event));
  init_complete_event.Wait();

  if (output_formats_.empty())
    return false;

  capabilities_.num_input_formats = input_formats_.size();
  capabilities_.input_formats = input_formats_.data();
  capabilities_.num_output_formats = output_formats_.size();
  capabilities_.output_formats = output_formats_.data();

  return true;
}

void GpuVeaImpl::InitializeOnIpcThread(
    base::WaitableEvent* init_complete_event) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  DETACH_FROM_THREAD(ipc_thread_checker_);

  mojo::Remote<arc::mojom::VideoEncodeAccelerator> remote_vea =
      connection_->CreateEncodeAccelerator();

  remote_vea->GetSupportedProfiles(base::BindOnce(
      &GpuVeaImpl::OnGetSupportedProfiles, base::Unretained(this),
      std::move(remote_vea), init_complete_event));
}

void GpuVeaImpl::OnGetSupportedProfiles(
    mojo::Remote<arc::mojom::VideoEncodeAccelerator> remote_vea,
    base::WaitableEvent* init_complete_event,
    std::vector<arc::mojom::VideoEncodeProfilePtr> profiles) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  output_formats_.clear();
  for (const auto& profile : profiles) {
    vea_profile_t p;
    p.profile = ConvertMojoProfileToCodecProfile(profile->profile);
    const auto& max_resolution = profile->max_resolution;
    p.max_width = max_resolution->width;
    p.max_height = max_resolution->height;
    p.max_framerate_numerator = profile->max_framerate_numerator;
    p.max_framerate_denominator = profile->max_framerate_denominator;
    output_formats_.push_back(std::move(p));
  }
  init_complete_event->Signal();
}

VeaContext* GpuVeaImpl::InitEncodeSession(vea_config_t* config) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  output_formats_.clear();

  if (!connection_) {
    DLOG(FATAL) << "InitEncodeSession called before successful Initialize().";
    return nullptr;
  }

  DLOG(INFO) << "Initializing encode session";

  base::WaitableEvent init_complete_event(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);
  VeaContext* context = nullptr;
  ipc_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&GpuVeaImpl::InitEncodeSessionOnIpcThread,
                                base::Unretained(this), config,
                                &init_complete_event, &context));
  init_complete_event.Wait();
  return context;
}

void GpuVeaImpl::InitEncodeSessionOnIpcThread(
    vea_config_t* config,
    base::WaitableEvent* init_complete_event,
    VeaContext** out_context) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  output_formats_.clear();

  mojo::Remote<arc::mojom::VideoEncodeAccelerator> remote_vea =
      connection_->CreateEncodeAccelerator();
  std::unique_ptr<GpuVeaContext> context =
      std::make_unique<GpuVeaContext>(ipc_task_runner_, std::move(remote_vea));
  GpuVeaContext* context_ptr = context.get();
  context_ptr->Initialize(
      config,
      base::BindOnce(
          &GpuVeaImpl::InitEncodeSessionAfterContextInitializedOnIpcThread,
          base::Unretained(this), init_complete_event, out_context,
          std::move(context)));
}

void GpuVeaImpl::InitEncodeSessionAfterContextInitializedOnIpcThread(
    base::WaitableEvent* init_complete_event,
    VeaContext** out_context,
    std::unique_ptr<VeaContext> context,
    bool success) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  output_formats_.clear();

  if (success) {
    *out_context = context.release();
  } else {
    DLOG(ERROR) << "Failed to initialize encode session.";
  }
  init_complete_event->Signal();
}

void GpuVeaImpl::CloseEncodeSession(VeaContext* context) {
  if (!connection_) {
    DLOG(FATAL) << "CloseEncodeSession called before successful Initialize().";
    return;
  }
  DLOG(INFO) << "Closing encode session";
  ipc_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&GpuVeaImpl::CloseEncodeSessionOnIpcThread,
                                base::Unretained(this), context));
}

void GpuVeaImpl::CloseEncodeSessionOnIpcThread(VeaContext* context) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  output_formats_.clear();
  delete context;
}

}  // namespace arc
