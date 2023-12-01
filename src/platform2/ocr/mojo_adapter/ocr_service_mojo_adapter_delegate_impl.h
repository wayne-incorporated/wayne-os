// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OCR_MOJO_ADAPTER_OCR_SERVICE_MOJO_ADAPTER_DELEGATE_IMPL_H_
#define OCR_MOJO_ADAPTER_OCR_SERVICE_MOJO_ADAPTER_DELEGATE_IMPL_H_

#include <memory>

#include <base/threading/thread.h>
#include <mojo/core/embedder/scoped_ipc_support.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "ocr/mojo_adapter/ocr_service_mojo_adapter.h"
#include "ocr/mojo_adapter/ocr_service_mojo_adapter_delegate.h"

namespace ocr {

// Implementation of the OcrServiceMojoAdapterDelegate interface.
class OcrServiceMojoAdapterDelegateImpl final
    : public OcrServiceMojoAdapterDelegate {
 public:
  OcrServiceMojoAdapterDelegateImpl();
  ~OcrServiceMojoAdapterDelegateImpl() override;
  OcrServiceMojoAdapterDelegateImpl(const OcrServiceMojoAdapterDelegateImpl&) =
      delete;
  OcrServiceMojoAdapterDelegateImpl& operator=(
      const OcrServiceMojoAdapterDelegateImpl&) = delete;

  // OcrServiceMojoAdapterDelegate:
  mojo::Remote<chromeos::ocr::mojom::OpticalCharacterRecognitionService>
  GetOcrService() override;

 private:
  // IPC threads.
  base::Thread mojo_thread_{"Mojo Thread"};
  base::Thread dbus_thread_{"D-Bus Thread"};

  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;
};

}  // namespace ocr

#endif  // OCR_MOJO_ADAPTER_OCR_SERVICE_MOJO_ADAPTER_DELEGATE_IMPL_H_
