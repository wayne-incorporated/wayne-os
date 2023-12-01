// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/libvda/decode/gpu/gpu_vda_impl.h"

#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/memory/ref_counted.h>
#include <base/notreached.h>
#include <base/stl_util.h>
#include <base/synchronization/waitable_event.h>
#include <base/task/single_thread_task_runner.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/object_path.h>
#include <dbus/object_proxy.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <mojo/public/cpp/system/platform_handle.h>
#include <sys/eventfd.h>

#include "arc/vm/libvda/decode/gpu/decode_helpers.h"
#include "arc/vm/libvda/gbm_util.h"
#include "arc/vm/libvda/gpu/format_util.h"
#include "arc/vm/libvda/gpu/mojom/video_common.mojom.h"
#include "arc/vm/libvda/gpu/mojom/video_decode_accelerator.mojom.h"

namespace arc {
namespace {

// Convert the specified mojo |result| to a VDA result
inline vda_result_t ConvertResult(
    arc::mojom::VideoDecodeAccelerator::Result result) {
  switch (result) {
    case arc::mojom::VideoDecodeAccelerator::Result::SUCCESS:
      return SUCCESS;
    case arc::mojom::VideoDecodeAccelerator::Result::ILLEGAL_STATE:
      return ILLEGAL_STATE;
    case arc::mojom::VideoDecodeAccelerator::Result::INVALID_ARGUMENT:
      return INVALID_ARGUMENT;
    case arc::mojom::VideoDecodeAccelerator::Result::UNREADABLE_INPUT:
      return UNREADABLE_INPUT;
    case arc::mojom::VideoDecodeAccelerator::Result::PLATFORM_FAILURE:
      return PLATFORM_FAILURE;
    case arc::mojom::VideoDecodeAccelerator::Result::INSUFFICIENT_RESOURCES:
      return INSUFFICIENT_RESOURCES;
    case arc::mojom::VideoDecodeAccelerator::Result::CANCELLED:
      return CANCELLED;
    default:
      DLOG(ERROR) << "Unknown error code: " << result;
      return PLATFORM_FAILURE;
  }
}

// GpuVdaContext is the GPU decode session context created by GpuVdaImpl which
// handles all mojo VideoDecodeClient invocations and callbacks.
class GpuVdaContext : public VdaContext, arc::mojom::VideoDecodeClient {
 public:
  // Create a new GpuVdaContext. Must be called on |ipc_task_runner|.
  GpuVdaContext(
      const scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner,
      mojo::Remote<arc::mojom::VideoDecodeAccelerator> remote_vda);
  GpuVdaContext(const GpuVdaContext&) = delete;
  GpuVdaContext& operator=(const GpuVdaContext&) = delete;

  ~GpuVdaContext();

  using InitializeCallback = base::OnceCallback<void(vda_result_t)>;

  // Initializes the VDA context object. When complete, callback is called with
  // the result. Must be called on |ipc_task_runner_|.
  void Initialize(vda_profile_t profile, InitializeCallback callback);

  // VdaContext overrides.
  vda_result_t Decode(int32_t bitstream_id,
                      base::ScopedFD fd,
                      uint32_t offset,
                      uint32_t bytes_used) override;
  vda_result_t SetOutputBufferCount(size_t num_output_buffers) override;
  vda_result_t UseOutputBuffer(int32_t picture_buffer_id,
                               vda_pixel_format_t format,
                               base::ScopedFD fd,
                               size_t num_planes,
                               video_frame_plane_t* planes,
                               uint64_t modifier) override;
  vda_result_t ReuseOutputBuffer(int32_t picture_buffer_id) override;
  vda_result_t Reset() override;
  vda_result_t Flush() override;

  // arc::mojom::VideoDecodeClient overrides.
  void ProvidePictureBuffers(arc::mojom::PictureBufferFormatPtr format_ptr,
                             arc::mojom::RectPtr visible_rect_ptr) override;
  void PictureReady(arc::mojom::PicturePtr) override;
  void NotifyError(arc::mojom::VideoDecodeAccelerator::Result error) override;
  void NotifyEndOfBitstreamBuffer(int32_t bitstream_id) override;

 private:
  // Callback invoked when VideoDecodeAccelerator::Initialize completes.
  void OnInitialized(InitializeCallback callback,
                     arc::mojom::VideoDecodeAccelerator::Result result);

  // Callback for VideoDecodeAccelerator connection errors.
  void OnVdaError(uint32_t custom_reason, const std::string& description);

  // Callback for VideoDecodeClient connection errors.
  void OnVdaClientError(uint32_t custom_reason, const std::string& description);

  // Callback invoked when VideoDecodeAccelerator::Reset completes.
  void OnResetDone(arc::mojom::VideoDecodeAccelerator::Result result);

  // Callback invoked when VideoDecodeAccelerator::Flush completes.
  void OnFlushDone(arc::mojom::VideoDecodeAccelerator::Result result);

  // Executes a decode. Called on |ipc_task_runner_|.
  void DecodeOnIpcThread(int32_t bitstream_id,
                         base::ScopedFD fd,
                         uint32_t offset,
                         uint32_t bytes_used);

  // Handles a SetOutputBuffer request by invoking a VideoDecodeAccelerator mojo
  // function. Called on |ipc_task_runner_|.
  void SetOutputBufferCountOnIpcThread(size_t num_output_buffers);

  // Handles a UseOutputBuffer request by invoking a VideoDecodeAccelerator mojo
  // function. Called on |ipc_task_runner_|.
  void UseOutputBufferOnIpcThread(int32_t picture_buffer_id,
                                  vda_pixel_format_t format,
                                  base::ScopedFD fd,
                                  std::vector<video_frame_plane_t> planes,
                                  uint64_t modifier);

  // Handles a ReuseOutputBuffer request by invoking a VideoDecodeAccelerator
  // mojo function. Called on |ipc_task_runner_|.
  void ReuseOutputBufferOnIpcThread(int32_t picture_buffer_id);

  // Handles a Reset request by invoking a VideoDecodeAccelerator mojo function.
  // Called on |ipc_task_runner_|.
  void ResetOnIpcThread();

  // Handles a SetOutputBuffer request by invoking a VideoDecodeAccelerator mojo
  // function. Called on |ipc_task_runner_|.
  void FlushOnIpcThread();

  scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner_;
  THREAD_CHECKER(ipc_thread_checker_);
  mojo::Remote<arc::mojom::VideoDecodeAccelerator> remote_vda_;
  mojo::Receiver<arc::mojom::VideoDecodeClient> receiver_;

  std::set<int32_t> decoding_bitstream_ids_;
};

GpuVdaContext::GpuVdaContext(
    const scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner,
    mojo::Remote<arc::mojom::VideoDecodeAccelerator> remote_vda)
    : ipc_task_runner_(std::move(ipc_task_runner)),
      remote_vda_(std::move(remote_vda)),
      receiver_(this) {
  // Since ipc_thread_checker_ binds to whichever thread it's created on, check
  // that we're on the correct thread first using BelongsToCurrentThread.
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  remote_vda_.set_disconnect_with_reason_handler(
      base::BindRepeating(&GpuVdaContext::OnVdaError, base::Unretained(this)));

  DLOG(INFO) << "Created new GPU context";
}

void GpuVdaContext::Initialize(vda_profile_t profile,
                               InitializeCallback callback) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  mojo::PendingRemote<arc::mojom::VideoDecodeClient> remote_client =
      receiver_.BindNewPipeAndPassRemote();
  receiver_.set_disconnect_with_reason_handler(base::BindRepeating(
      &GpuVdaContext::OnVdaClientError, base::Unretained(this)));

  arc::mojom::VideoDecodeAcceleratorConfigPtr config =
      arc::mojom::VideoDecodeAcceleratorConfig::New();
  // TODO(alexlau): Think about how to specify secure mode dynamically.
  config->secure_mode = false;
  config->profile = ConvertCodecProfileToMojoProfile(profile);

  remote_vda_->Initialize(
      std::move(config), std::move(remote_client),
      base::BindRepeating(&GpuVdaContext::OnInitialized, base::Unretained(this),
                          base::Passed(std::move(callback))));
}

void GpuVdaContext::OnInitialized(
    InitializeCallback callback,
    arc::mojom::VideoDecodeAccelerator::Result result) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  std::move(callback).Run(ConvertResult(result));
}

GpuVdaContext::~GpuVdaContext() {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
}

void GpuVdaContext::OnVdaError(uint32_t custom_reason,
                               const std::string& description) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  DLOG(ERROR) << "VideoDecodeAccelerator mojo connection error. custom_reason="
              << custom_reason << " description=" << description;
}

void GpuVdaContext::OnVdaClientError(uint32_t custom_reason,
                                     const std::string& description) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  DLOG(ERROR) << "VideoDecodeClient mojo connection error. custom_reason="
              << custom_reason << " description=" << description;
}

vda_result_t GpuVdaContext::Decode(int32_t bitstream_id,
                                   base::ScopedFD fd,
                                   uint32_t offset,
                                   uint32_t bytes_used) {
  ipc_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&GpuVdaContext::DecodeOnIpcThread, base::Unretained(this),
                     bitstream_id, std::move(fd), offset, bytes_used));
  return SUCCESS;
}

vda_result_t GpuVdaContext::SetOutputBufferCount(size_t num_output_buffers) {
  ipc_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&GpuVdaContext::SetOutputBufferCountOnIpcThread,
                                base::Unretained(this), num_output_buffers));
  return SUCCESS;
}

void GpuVdaContext::SetOutputBufferCountOnIpcThread(size_t num_output_buffers) {
  remote_vda_->AssignPictureBuffers(num_output_buffers);
}

void GpuVdaContext::DecodeOnIpcThread(int32_t bitstream_id,
                                      base::ScopedFD fd,
                                      uint32_t offset,
                                      uint32_t bytes_used) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);

  mojo::ScopedHandle handle_fd = mojo::WrapPlatformFile(std::move(fd));
  if (!handle_fd.is_valid()) {
    LOG(ERROR) << "Invalid bitstream handle.";
    return;
  }

  decoding_bitstream_ids_.insert(bitstream_id);

  arc::mojom::BitstreamBufferPtr buf = arc::mojom::BitstreamBuffer::New();
  buf->bitstream_id = bitstream_id;
  buf->handle_fd = std::move(handle_fd);
  buf->offset = offset;
  buf->bytes_used = bytes_used;

  remote_vda_->Decode(std::move(buf));
}

vda_result_t GpuVdaContext::UseOutputBuffer(int32_t picture_buffer_id,
                                            vda_pixel_format_t format,
                                            base::ScopedFD fd,
                                            size_t num_planes,
                                            video_frame_plane_t* planes,
                                            uint64_t modifier) {
  if (!CheckValidOutputFormat(format, num_planes))
    return INVALID_ARGUMENT;

  // Move semantics don't seem to work with mojo pointers so copy the
  // video_frame_plane_t objects and handle in the ipc thread. This allows
  // |planes| ownership to be retained by the user.
  std::vector<video_frame_plane_t> planes_vector(planes, planes + num_planes);
  ipc_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&GpuVdaContext::UseOutputBufferOnIpcThread,
                     base::Unretained(this), picture_buffer_id, format,
                     std::move(fd), std::move(planes_vector), modifier));
  return SUCCESS;
}

void GpuVdaContext::UseOutputBufferOnIpcThread(
    int32_t picture_buffer_id,
    vda_pixel_format_t format,
    base::ScopedFD fd,
    std::vector<video_frame_plane_t> planes,
    uint64_t modifier) {
  mojo::ScopedHandle handle_fd = mojo::WrapPlatformFile(std::move(fd));
  if (!handle_fd.is_valid()) {
    LOG(ERROR) << "Invalid output buffer handle.";
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

  auto modifier_ptr = arc::mojom::BufferModifier::New();
  modifier_ptr->val = modifier;

  remote_vda_->ImportBufferForPicture(
      picture_buffer_id, ConvertPixelFormatToHalPixelFormat(format),
      std::move(handle_fd), std::move(mojo_planes), std::move(modifier_ptr));
}

vda_result_t GpuVdaContext::ReuseOutputBuffer(int32_t picture_buffer_id) {
  ipc_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&GpuVdaContext::ReuseOutputBufferOnIpcThread,
                                base::Unretained(this), picture_buffer_id));
  return SUCCESS;
}

void GpuVdaContext::ReuseOutputBufferOnIpcThread(int32_t picture_buffer_id) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  remote_vda_->ReusePictureBuffer(picture_buffer_id);
}

vda_result GpuVdaContext::Reset() {
  ipc_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&GpuVdaContext::ResetOnIpcThread, base::Unretained(this)));
  return SUCCESS;
}

void GpuVdaContext::ResetOnIpcThread() {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  remote_vda_->Reset(
      base::BindRepeating(&GpuVdaContext::OnResetDone, base::Unretained(this)));
}

void GpuVdaContext::OnResetDone(
    arc::mojom::VideoDecodeAccelerator::Result result) {
  DispatchResetResponse(ConvertResult(result));
}

vda_result GpuVdaContext::Flush() {
  ipc_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&GpuVdaContext::FlushOnIpcThread, base::Unretained(this)));
  return SUCCESS;
}

void GpuVdaContext::FlushOnIpcThread() {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  remote_vda_->Flush(
      base::BindRepeating(&GpuVdaContext::OnFlushDone, base::Unretained(this)));
}

void GpuVdaContext::OnFlushDone(
    arc::mojom::VideoDecodeAccelerator::Result result) {
  DispatchFlushResponse(ConvertResult(result));
}

// VideoDecodeClient implementation function.
void GpuVdaContext::ProvidePictureBuffers(
    arc::mojom::PictureBufferFormatPtr format_ptr,
    arc::mojom::RectPtr visible_rect_ptr) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  DispatchProvidePictureBuffers(
      format_ptr->min_num_buffers, format_ptr->coded_size->width,
      format_ptr->coded_size->height, visible_rect_ptr->left,
      visible_rect_ptr->top, visible_rect_ptr->right, visible_rect_ptr->bottom);
}

// VideoDecodeClient implementation function.
void GpuVdaContext::PictureReady(arc::mojom::PicturePtr picture_ptr) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  DispatchPictureReady(
      picture_ptr->picture_buffer_id, picture_ptr->bitstream_id,
      picture_ptr->crop_rect->left, picture_ptr->crop_rect->top,
      picture_ptr->crop_rect->right, picture_ptr->crop_rect->bottom);
}

// VideoDecodeClient implementation function.
void GpuVdaContext::NotifyError(
    arc::mojom::VideoDecodeAccelerator::Result error) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  DispatchNotifyError(ConvertResult(error));
}

// VideoDecodeClient implementation function.
void GpuVdaContext::NotifyEndOfBitstreamBuffer(int32_t bitstream_id) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);

  DispatchNotifyEndOfBitstreamBuffer(bitstream_id);

  if (decoding_bitstream_ids_.erase(bitstream_id) == 0) {
    LOG(ERROR) << "Could not find bitstream id: " << bitstream_id;
    return;
  }
}

}  // namespace

// static
GpuVdaImpl* GpuVdaImpl::Create(VafConnection* conn) {
  auto impl = std::make_unique<GpuVdaImpl>(conn);
  if (!impl->Initialize()) {
    LOG(ERROR) << "Could not initialize GpuVdaImpl.";
    return nullptr;
  }

  return impl.release();
}

GpuVdaImpl::GpuVdaImpl(VafConnection* conn) : connection_(conn) {}

GpuVdaImpl::~GpuVdaImpl() = default;

std::vector<vda_input_format_t> GpuVdaImpl::GetSupportedInputFormats() {
  std::vector<vda_input_format_t> supported_input_formats;

  for (int i = 0; i < std::size(kInputFormats); i++) {
    auto* context = InitDecodeSession(kInputFormats[i].profile);
    if (context) {
      supported_input_formats.emplace_back(kInputFormats[i]);
      CloseDecodeSession(context);
    }
  }

  return supported_input_formats;
}

bool GpuVdaImpl::PopulateCapabilities() {
  input_formats_ = GetSupportedInputFormats();
  if (input_formats_.empty())
    return false;

  capabilities_.num_input_formats = input_formats_.size();
  capabilities_.input_formats = input_formats_.data();

  output_formats_ = GetSupportedRawFormats(GbmUsageType::DECODE);
  if (output_formats_.empty())
    return false;

  capabilities_.num_output_formats = output_formats_.size();
  capabilities_.output_formats = output_formats_.data();
  return true;
}

bool GpuVdaImpl::Initialize() {
  ipc_task_runner_ = connection_->GetIpcTaskRunner();

  if (!PopulateCapabilities()) {
    ipc_task_runner_.reset();
    return false;
  }

  return true;
}

VdaContext* GpuVdaImpl::InitDecodeSession(vda_profile_t profile) {
  if (!ipc_task_runner_) {
    DLOG(FATAL) << "InitDecodeSession called before successful Initialize().";
    return nullptr;
  }

  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  DLOG(INFO) << "Initializing decode session with profile " << profile;

  base::WaitableEvent init_complete_event(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);

  VdaContext* context = nullptr;
  ipc_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&GpuVdaImpl::InitDecodeSessionOnIpcThread,
                                base::Unretained(this), profile,
                                &init_complete_event, &context));
  init_complete_event.Wait();
  return context;
}

void GpuVdaImpl::InitDecodeSessionOnIpcThread(
    vda_profile_t profile,
    base::WaitableEvent* init_complete_event,
    VdaContext** out_context) {
  DETACH_FROM_THREAD(ipc_thread_checker_);
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);

  mojo::Remote<arc::mojom::VideoDecodeAccelerator> remote_vda =
      connection_->CreateDecodeAccelerator();

  std::unique_ptr<GpuVdaContext> context =
      std::make_unique<GpuVdaContext>(ipc_task_runner_, std::move(remote_vda));
  GpuVdaContext* context_ptr = context.get();
  context_ptr->Initialize(
      profile,
      base::BindRepeating(
          &GpuVdaImpl::InitDecodeSessionAfterContextInitializedOnIpcThread,
          base::Unretained(this), init_complete_event, out_context,
          base::Passed(std::move(context))));
}

void GpuVdaImpl::InitDecodeSessionAfterContextInitializedOnIpcThread(
    base::WaitableEvent* init_complete_event,
    VdaContext** out_context,
    std::unique_ptr<VdaContext> context,
    vda_result_t result) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);

  if (result == SUCCESS) {
    *out_context = context.release();
  } else {
    DLOG(ERROR) << "Failed to initialize decode session.";
  }
  init_complete_event->Signal();
}

void GpuVdaImpl::CloseDecodeSession(VdaContext* context) {
  if (!ipc_task_runner_) {
    DLOG(FATAL) << "CloseDecodeSession called before successful Initialize().";
    return;
  }
  DLOG(INFO) << "Closing decode session";
  RunTaskOnThread(ipc_task_runner_,
                  base::BindOnce(&GpuVdaImpl::CloseDecodeSessionOnIpcThread,
                                 base::Unretained(this), context));
}

void GpuVdaImpl::CloseDecodeSessionOnIpcThread(VdaContext* context) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  delete context;
}

}  // namespace arc
