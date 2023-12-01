// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/libvda/decode/gpu/gpu_vd_impl.h"

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
#include <mojo/public/cpp/bindings/associated_receiver.h>
#include <mojo/public/cpp/bindings/associated_remote.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <mojo/public/cpp/system/platform_handle.h>
#include <sys/eventfd.h>

#include "arc/vm/libvda/decode/gpu/decode_helpers.h"
#include "arc/vm/libvda/gbm_util.h"
#include "arc/vm/libvda/gpu/format_util.h"
#include "arc/vm/libvda/gpu/mojom/video_common.mojom.h"
#include "arc/vm/libvda/gpu/mojom/video_decoder.mojom.h"
#include "arc/vm/libvda/gpu/mojom/video_frame_pool.mojom.h"

namespace arc {
namespace {

// Small helper struct based on Chrome ui::gfx::Size to hold a video frame Size.
struct Size {
  int width = 0;
  int height = 0;
};

// GpuVdContext is the GPU decode session context created by GpuVdImpl which
// handles all mojo VideoDecodeClient invocations and callbacks.
class GpuVdContext : public VdaContext,
                     arc::mojom::VideoDecoderClient,
                     arc::mojom::VideoFramePoolClient {
 public:
  // Create a new GpuVdContext. Must be called on |ipc_task_runner|.
  GpuVdContext(
      const scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner,
      mojo::Remote<arc::mojom::VideoDecoder> remote_vd);
  GpuVdContext(const GpuVdContext&) = delete;
  GpuVdContext& operator=(const GpuVdContext&) = delete;

  ~GpuVdContext();

  using InitializeCallback = base::OnceCallback<void(vd_decoder_status_t)>;

  // Initializes the VD context object. When complete, callback is called with
  // the result. Must be called on |ipc_task_runner_|.
  void Initialize(vda_profile_t profile,
                  const Size& coded_size,
                  InitializeCallback callback);

  // VdaContext overrides.
  vda_result_t Decode(int32_t buffer_id,
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

  // arc::mojom::VideoDecoderClient implementation.
  void OnVideoFrameDecoded(int32_t video_frame_id,
                           arc::mojom::RectPtr visible_rect,
                           int64_t timestamp) override;
  void OnError(arc::mojom::DecoderStatus status) override;

  // arc::mojom::VideoFramePoolClient implementation.
  void RequestVideoFrames(mojom::VideoPixelFormat format,
                          arc::mojom::SizePtr coded_size,
                          arc::mojom::RectPtr visible_rect_ptr,
                          uint32_t num_frames) override;

 private:
  // Callback invoked when VideoDecoder::Initialize completes.
  void OnInitialized(InitializeCallback callback,
                     arc::mojom::DecoderStatus status);

  // Callback invoked whenever a decode operation completes.
  void OnDecodeDone(int32_t buffer_id, arc::mojom::DecoderStatus status);

  // Callback for connection errors.
  void OnConnectionError(uint32_t custom_reason,
                         const std::string& description);

  // Callback invoked when VideoDecoder::Reset completes.
  void OnResetDone();

  // Callback invoked whenever a VideoDecoder flush completes.
  void OnFlushDone(arc::mojom::DecoderStatus status);

  // Callback invoked when a VideoFramePool::AddVideoFrame request completes.
  void OnAddVideoFrameDone(int32_t video_frame_id, bool result);

  // Executes a decode. Called on |ipc_task_runner_|.
  void DecodeOnIpcThread(int32_t buffer_id,
                         base::ScopedFD fd,
                         uint32_t offset,
                         uint32_t bytes_used);

  // Handles a SetOutputBuffer request by invoking a VideoDecoder mojo function.
  // Called on |ipc_task_runner_|.
  void SetOutputBufferCountOnIpcThread(size_t num_output_buffers);

  // Handles a UseOutputBuffer request by invoking a VideoDecoder mojo function.
  // Called on |ipc_task_runner_|.
  void UseOutputBufferOnIpcThread(int32_t picture_buffer_id,
                                  vda_pixel_format_t format,
                                  base::ScopedFD fd,
                                  std::vector<video_frame_plane_t> planes,
                                  uint64_t modifier);

  // Handles a ReuseOutputBuffer request by invoking a VideoDecoder mojo
  // function. Called on |ipc_task_runner_|.
  void ReuseOutputBufferOnIpcThread(int32_t picture_buffer_id);

  // Handles a Reset request by invoking a VideoDecoder mojo function. Called on
  // |ipc_task_runner_|.
  void ResetOnIpcThread();

  // Handles a SetOutputBuffer request by invoking a VideoDecoder mojo function.
  // Called on |ipc_task_runner_|.
  void FlushOnIpcThread();

  // The remote video decoder mojo service and its local receiver.
  mojo::Remote<arc::mojom::VideoDecoder> remote_vd_;
  mojo::Receiver<arc::mojom::VideoDecoderClient> receiver_;

  // The remote video frame pool mojo service and its local receiver.
  mojo::AssociatedRemote<arc::mojom::VideoFramePool> remote_pool_;
  mojo::AssociatedReceiver<arc::mojom::VideoFramePoolClient> receiver_pool_;

  // Ids of buffers currently being decoded.
  std::set<int32_t> decoding_buffer_ids_;

  // The coded size currently used for video frames.
  Size coded_size_;
  // The coded size requested by the decoder, will be applied once the client
  // calls SetOutputBufferCount().
  Size requested_coded_size_;
  // The number of output buffers requested by the decoder, will be applied once
  // the client calls SetOutputBufferCount().
  uint32_t requested_num_buffers_ = 0;
  // The number of output buffers.
  uint32_t output_buffer_count_ = 0;

  scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner_;
  THREAD_CHECKER(ipc_thread_checker_);

  base::WeakPtr<GpuVdContext> weak_this_;
  base::WeakPtrFactory<GpuVdContext> weak_this_factory_{this};
};

GpuVdContext::GpuVdContext(
    const scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner,
    mojo::Remote<arc::mojom::VideoDecoder> remote_vd)
    : remote_vd_(std::move(remote_vd)),
      receiver_(this),
      receiver_pool_(this),
      ipc_task_runner_(std::move(ipc_task_runner)) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);

  weak_this_ = weak_this_factory_.GetWeakPtr();
  remote_vd_.set_disconnect_with_reason_handler(
      base::BindRepeating(&GpuVdContext::OnConnectionError, weak_this_));

  DLOG(INFO) << "Created new GPU context";
}

void GpuVdContext::Initialize(vda_profile_t profile,
                              const Size& coded_size,
                              InitializeCallback callback) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  mojo::PendingRemote<arc::mojom::VideoDecoderClient> remote_client =
      receiver_.BindNewPipeAndPassRemote();
  receiver_.set_disconnect_with_reason_handler(
      base::BindRepeating(&GpuVdContext::OnConnectionError, weak_this_));

  arc::mojom::VideoDecoderConfigPtr config =
      arc::mojom::VideoDecoderConfig::New();
  config->profile = ConvertCodecProfileToMojoProfile(profile);

  arc::mojom::SizePtr mojo_coded_size = arc::mojom::Size::New();
  mojo_coded_size->width = coded_size.width;
  mojo_coded_size->height = coded_size.height;
  config->coded_size = std::move(mojo_coded_size);

  remote_vd_->Initialize(
      std::move(config), std::move(remote_client),
      remote_pool_.BindNewEndpointAndPassReceiver(),
      base::BindRepeating(&GpuVdContext::OnInitialized, weak_this_,
                          base::Passed(std::move(callback))));
}

void GpuVdContext::OnInitialized(InitializeCallback callback,
                                 arc::mojom::DecoderStatus status) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  mojo::PendingAssociatedRemote<arc::mojom::VideoFramePoolClient>
      remote_pool_client = receiver_pool_.BindNewEndpointAndPassRemote();
  receiver_pool_.set_disconnect_with_reason_handler(
      base::BindRepeating(&GpuVdContext::OnConnectionError, weak_this_));

  remote_pool_->Initialize(std::move(remote_pool_client));

  std::move(callback).Run(ConvertDecoderStatus(status));
}

GpuVdContext::~GpuVdContext() {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);

  // Invalidate all weak pointers to stop incoming callbacks.
  weak_this_factory_.InvalidateWeakPtrs();
}

void GpuVdContext::OnConnectionError(uint32_t custom_reason,
                                     const std::string& description) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  DLOG(ERROR) << "Mojo connection error. custom_reason=" << custom_reason
              << " description=" << description;
}

vda_result_t GpuVdContext::SetOutputBufferCount(size_t num_output_buffers) {
  ipc_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&GpuVdContext::SetOutputBufferCountOnIpcThread,
                                weak_this_, num_output_buffers));
  return SUCCESS;
}

void GpuVdContext::SetOutputBufferCountOnIpcThread(size_t num_output_buffers) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);

  if (num_output_buffers < requested_num_buffers_) {
    LOG(WARNING) << "Received less buffers (" << num_output_buffers
                 << ") than requested (" << requested_num_buffers_ << ")";
  }

  coded_size_ = requested_coded_size_;
  output_buffer_count_ = num_output_buffers;
  requested_coded_size_ = Size();
  requested_num_buffers_ = 0;
}

vda_result_t GpuVdContext::Decode(int32_t buffer_id,
                                  base::ScopedFD fd,
                                  uint32_t offset,
                                  uint32_t bytes_used) {
  ipc_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&GpuVdContext::DecodeOnIpcThread, weak_this_,
                                buffer_id, std::move(fd), offset, bytes_used));
  return SUCCESS;
}

void GpuVdContext::DecodeOnIpcThread(int32_t buffer_id,
                                     base::ScopedFD fd,
                                     uint32_t offset,
                                     uint32_t bytes_used) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);

  mojo::PlatformHandle handle_fd(std::move(fd));
  if (!handle_fd.is_valid()) {
    LOG(ERROR) << "Invalid buffer handle.";
    return;
  }

  decoding_buffer_ids_.insert(buffer_id);

  arc::mojom::BufferPtr buffer = arc::mojom::Buffer::New();
  buffer->timestamp = buffer_id;
  buffer->handle_fd = std::move(handle_fd);
  buffer->offset = offset;
  buffer->size = bytes_used;
  arc::mojom::DecoderBufferPtr decoder_buffer =
      arc::mojom::DecoderBuffer::NewBuffer(std::move(buffer));

  remote_vd_->Decode(
      std::move(decoder_buffer),
      base::BindOnce(&GpuVdContext::OnDecodeDone, weak_this_, buffer_id));
}

void GpuVdContext::OnDecodeDone(int32_t buffer_id,
                                arc::mojom::DecoderStatus status) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);

  if (status != arc::mojom::DecoderStatus::OK) {
    LOG(ERROR) << "Failed to decode buffer with id: " << buffer_id;
    DispatchNotifyError(ToVDAResult(ConvertDecoderStatus(status)));
    return;
  }

  if (decoding_buffer_ids_.erase(buffer_id) == 0) {
    LOG(ERROR) << "Could not find buffer id: " << buffer_id;
    return;
  }

  DispatchNotifyEndOfBitstreamBuffer(buffer_id);
}

vda_result_t GpuVdContext::UseOutputBuffer(int32_t picture_buffer_id,
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
      base::BindOnce(&GpuVdContext::UseOutputBufferOnIpcThread, weak_this_,
                     picture_buffer_id, format, std::move(fd),
                     std::move(planes_vector), modifier));
  return SUCCESS;
}

void GpuVdContext::UseOutputBufferOnIpcThread(
    int32_t picture_buffer_id,
    vda_pixel_format_t format,
    base::ScopedFD fd,
    std::vector<video_frame_plane_t> planes,
    uint64_t modifier) {
  mojo::PlatformHandle handle_fd(std::move(fd));
  if (!handle_fd.is_valid()) {
    LOG(ERROR) << "Invalid output buffer handle.";
    return;
  }

  if ((picture_buffer_id < 0) ||
      (static_cast<size_t>(picture_buffer_id) >= output_buffer_count_)) {
    LOG(ERROR) << "Invalid picture buffer id: " << picture_buffer_id;
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

  arc::mojom::SizePtr mojo_coded_size = arc::mojom::Size::New();
  mojo_coded_size->width = coded_size_.width;
  mojo_coded_size->height = coded_size_.height;

  auto video_frame = arc::mojom::VideoFrame::New();
  video_frame->id = picture_buffer_id;
  video_frame->coded_size = std::move(mojo_coded_size);
  video_frame->handle_fd = std::move(handle_fd);
  video_frame->format = ConvertPixelFormatToHalPixelFormat(format);
  video_frame->planes = std::move(mojo_planes);
  video_frame->modifier = modifier;

  remote_pool_->AddVideoFrame(std::move(video_frame),
                              base::BindOnce(&GpuVdContext::OnAddVideoFrameDone,
                                             weak_this_, picture_buffer_id));
}

vda_result_t GpuVdContext::ReuseOutputBuffer(int32_t picture_buffer_id) {
  ipc_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&GpuVdContext::ReuseOutputBufferOnIpcThread,
                                weak_this_, picture_buffer_id));
  return SUCCESS;
}

void GpuVdContext::ReuseOutputBufferOnIpcThread(int32_t picture_buffer_id) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  remote_vd_->ReleaseVideoFrame(picture_buffer_id);
}

vda_result GpuVdContext::Reset() {
  ipc_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&GpuVdContext::ResetOnIpcThread, weak_this_));
  return SUCCESS;
}

void GpuVdContext::ResetOnIpcThread() {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  remote_vd_->Reset(
      base::BindRepeating(&GpuVdContext::OnResetDone, weak_this_));
}

void GpuVdContext::OnResetDone() {
  DispatchResetResponse(SUCCESS);
}

vda_result GpuVdContext::Flush() {
  ipc_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&GpuVdContext::FlushOnIpcThread, weak_this_));
  return SUCCESS;
}

void GpuVdContext::FlushOnIpcThread() {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);

  arc::mojom::DecoderBufferPtr decoder_buffer =
      arc::mojom::DecoderBuffer::NewEndOfStream(0);

  remote_vd_->Decode(std::move(decoder_buffer),
                     base::BindOnce(&GpuVdContext::OnFlushDone, weak_this_));
}

void GpuVdContext::OnFlushDone(arc::mojom::DecoderStatus status) {
  DispatchFlushResponse(ToVDAResult(ConvertDecoderStatus(status)));
}

// VideoDecoderClient implementation function.
void GpuVdContext::OnError(arc::mojom::DecoderStatus status) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  DispatchNotifyError(ToVDAResult(ConvertDecoderStatus(status)));
}

// VideoDecoderClient implementation function.
void GpuVdContext::OnVideoFrameDecoded(int32_t video_frame_id,
                                       arc::mojom::RectPtr visible_rect,
                                       int64_t timestamp) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);

  int32_t buffer_id = static_cast<int32_t>(timestamp);
  DispatchPictureReady(video_frame_id, buffer_id, visible_rect->left,
                       visible_rect->top, visible_rect->right,
                       visible_rect->bottom);
}

// VideoFramePoolClient implementation function.
void GpuVdContext::RequestVideoFrames(mojom::VideoPixelFormat format,
                                      arc::mojom::SizePtr coded_size,
                                      arc::mojom::RectPtr visible_rect,
                                      uint32_t num_frames) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);

  // The requested coded size will only be applied after SetOutputBufferCount is
  // called, as the client might still add frames with the old coded size.
  requested_coded_size_ = {coded_size->width, coded_size->height};
  requested_num_buffers_ = num_frames;

  DispatchProvidePictureBuffers(
      num_frames, coded_size->width, coded_size->height, visible_rect->left,
      visible_rect->top, visible_rect->right, visible_rect->bottom);
}

void GpuVdContext::OnAddVideoFrameDone(int32_t video_frame_id, bool result) {
  if (!result) {
    LOG(ERROR) << "Failed to import video frame (id: %i)" << video_frame_id;
    DispatchNotifyError(INVALID_ARGUMENT);
  }
}

}  // namespace

// static
GpuVdImpl* GpuVdImpl::Create(VafConnection* conn) {
  if (!conn || !conn->GetIpcTaskRunner()) {
    LOG(ERROR) << "Could not create GpuVdImpl: Invalid connection";
    return nullptr;
  }

  std::unique_ptr<GpuVdImpl> impl(new GpuVdImpl(conn));
  if (!impl->PopulateCapabilities()) {
    LOG(ERROR) << "Could not create GpuVdImpl: Failed to populate capabilities";
    return nullptr;
  }

  return impl.release();
}

GpuVdImpl::GpuVdImpl(VafConnection* conn)
    : connection_(conn), ipc_task_runner_(conn->GetIpcTaskRunner()) {
  weak_this_ = weak_this_factory_.GetWeakPtr();
}

GpuVdImpl::~GpuVdImpl() {
  // Invalidate all weak pointers on the IPC thread to stop incoming callbacks.
  RunTaskOnThread(ipc_task_runner_,
                  base::BindOnce(
                      [](base::WeakPtrFactory<GpuVdImpl>* weak_this_factory) {
                        weak_this_factory->InvalidateWeakPtrs();
                      },
                      &weak_this_factory_));
}

std::vector<vda_input_format_t> GpuVdImpl::GetSupportedInputFormats() {
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

bool GpuVdImpl::PopulateCapabilities() {
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

VdaContext* GpuVdImpl::InitDecodeSession(vda_profile_t profile) {
  DCHECK(!ipc_task_runner_->BelongsToCurrentThread());
  DLOG(INFO) << "Initializing decode session with profile " << profile;

  base::WaitableEvent init_complete_event;

  VdaContext* context = nullptr;
  ipc_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&GpuVdImpl::InitDecodeSessionOnIpcThread, weak_this_,
                     profile, &init_complete_event, &context));
  init_complete_event.Wait();
  return context;
}

void GpuVdImpl::InitDecodeSessionOnIpcThread(
    vda_profile_t profile,
    base::WaitableEvent* init_complete_event,
    VdaContext** out_context) {
  DETACH_FROM_THREAD(ipc_thread_checker_);
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);

  mojo::Remote<arc::mojom::VideoDecoder> remote_vd =
      connection_->CreateVideoDecoder();

  std::unique_ptr<GpuVdContext> context =
      std::make_unique<GpuVdContext>(ipc_task_runner_, std::move(remote_vd));
  GpuVdContext* context_ptr = context.get();

  // We only know the size after the first decoder buffer has been queued and
  // the decoder calls RequestFrames(), so we use an arbitrary size as default.
  constexpr Size kInitialCodedSize{320, 240};
  context_ptr->Initialize(
      profile, kInitialCodedSize,
      base::BindOnce(
          &GpuVdImpl::InitDecodeSessionAfterContextInitializedOnIpcThread,
          weak_this_, init_complete_event, out_context, std::move(context)));
}

void GpuVdImpl::InitDecodeSessionAfterContextInitializedOnIpcThread(
    base::WaitableEvent* init_complete_event,
    VdaContext** out_context,
    std::unique_ptr<VdaContext> context,
    vd_decoder_status_t status) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());

  if (status == OK) {
    *out_context = context.release();
  } else {
    DLOG(ERROR) << "Failed to initialize decode session.";
  }
  init_complete_event->Signal();
}

void GpuVdImpl::CloseDecodeSession(VdaContext* context) {
  DLOG(INFO) << "Closing decode session";
  RunTaskOnThread(ipc_task_runner_,
                  base::BindOnce(&GpuVdImpl::CloseDecodeSessionOnIpcThread,
                                 weak_this_, context));
}

void GpuVdImpl::CloseDecodeSessionOnIpcThread(VdaContext* context) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  delete context;
}

}  // namespace arc
