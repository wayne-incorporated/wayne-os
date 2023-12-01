// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OCR_OCR_SERVICE_IMPL_H_
#define OCR_OCR_SERVICE_IMPL_H_

#include <base/functional/callback.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver_set.h>
#include <mojo/public/cpp/system/handle.h>

#include "ocr/mojo/ocr_service.mojom.h"

namespace ocr {

using OcrServiceReceiverSet =
    mojo::ReceiverSet<chromeos::ocr::mojom::OpticalCharacterRecognitionService,
                      bool>;

// Implements the "OpticalCharacterRecognitionService" Mojo interface
// exposed by the OCR Daemon (see the API definition at mojo/ocr_service.mojom).
class OcrServiceImpl final
    : public chromeos::ocr::mojom::OpticalCharacterRecognitionService {
 public:
  OcrServiceImpl();
  ~OcrServiceImpl() override;
  OcrServiceImpl(const OcrServiceImpl&) = delete;
  OcrServiceImpl& operator=(const OcrServiceImpl&) = delete;

  // chromeos::ocr::mojom::OpticalCharacterRecognitionService:
  void GenerateSearchablePdfFromImage(
      mojo::ScopedHandle input_fd_handle,
      mojo::ScopedHandle output_fd_handle,
      chromeos::ocr::mojom::OcrConfigPtr ocr_config,
      chromeos::ocr::mojom::PdfRendererConfigPtr pdf_renderer_config,
      GenerateSearchablePdfFromImageCallback callback) override;

  // Adds a new pending receiver (client) to the internal ReceiverSet.
  void AddReceiver(mojo::PendingReceiver<
                       chromeos::ocr::mojom::OpticalCharacterRecognitionService>
                       pending_receiver,
                   bool should_quit);

  // Sets the callback that will be called when a connection error is
  // encountered on any receiver endpoint.
  void SetOnDisconnectCallback(
      base::RepeatingCallback<void(bool)> on_disconnect_callback);

 private:
  // Disconnect handler for |receivers_|.
  // Runs |on_disconnect_callback_| and passes to it the
  // context_value (should_quit) of the receiver.
  void OnDisconnect();

  // Receiver set that connects this instance (which is an implementation of
  // chromeos::ocr::mojom::OpticalCharacterRecognitionService) with any message
  // pipes set up on top of received file descriptors.
  // A new receiver is added whenever the BootstrapMojoConnection D-Bus method
  // is called.
  OcrServiceReceiverSet receivers_;

  // Callback used to notify OcrDaemon of receiver disconnects.
  base::RepeatingCallback<void(bool)> on_disconnect_callback_;
};

}  // namespace ocr

#endif  // OCR_OCR_SERVICE_IMPL_H_
