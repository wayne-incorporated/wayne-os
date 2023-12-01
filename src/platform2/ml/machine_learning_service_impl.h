// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_MACHINE_LEARNING_SERVICE_IMPL_H_
#define ML_MACHINE_LEARNING_SERVICE_IMPL_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/functional/callback_forward.h>
#include <dbus/bus.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/receiver_set.h>
#include <mojo/public/cpp/platform/platform_channel.h>

#include "ml/dlcservice_client.h"
#include "ml/model_metadata.h"
#include "ml/mojom/machine_learning_service.mojom.h"
#include "ml_core/dlc/dlc_client.h"

namespace ml {

class MachineLearningServiceImpl
    : public chromeos::machine_learning::mojom::MachineLearningService {
 public:
  // Creates an instance bound to `pipe`. The specified `disconnect_handler`
  // will be invoked if the binding encounters a connection error or is closed.
  // The `bus` is used to construct `dlcservice_client_` if it is not nullptr.
  MachineLearningServiceImpl(
      mojo::PendingReceiver<
          chromeos::machine_learning::mojom::MachineLearningService> receiver,
      base::OnceClosure disconnect_handler,
      dbus::Bus* bus = nullptr);

 protected:
  // Testing constructor that allows overriding of the model dir. Should not be
  // used outside of tests.
  MachineLearningServiceImpl(
      mojo::PendingReceiver<
          chromeos::machine_learning::mojom::MachineLearningService> receiver,
      base::OnceClosure disconnect_handler,
      const std::string& model_dir);
  MachineLearningServiceImpl(const MachineLearningServiceImpl&) = delete;
  MachineLearningServiceImpl& operator=(const MachineLearningServiceImpl&) =
      delete;

 private:
  // chromeos::machine_learning::mojom::MachineLearningService:
  void Clone(mojo::PendingReceiver<
             chromeos::machine_learning::mojom::MachineLearningService>
                 receiver) override;
  void LoadBuiltinModel(
      chromeos::machine_learning::mojom::BuiltinModelSpecPtr spec,
      mojo::PendingReceiver<chromeos::machine_learning::mojom::Model> receiver,
      LoadBuiltinModelCallback callback) override;
  void LoadFlatBufferModel(
      chromeos::machine_learning::mojom::FlatBufferModelSpecPtr spec,
      mojo::PendingReceiver<chromeos::machine_learning::mojom::Model> receiver,
      LoadFlatBufferModelCallback callback) override;
  void LoadTextClassifier(
      mojo::PendingReceiver<chromeos::machine_learning::mojom::TextClassifier>
          receiver,
      LoadTextClassifierCallback callback) override;
  void LoadHandwritingModel(
      chromeos::machine_learning::mojom::HandwritingRecognizerSpecPtr spec,
      mojo::PendingReceiver<
          chromeos::machine_learning::mojom::HandwritingRecognizer> receiver,
      LoadHandwritingModelCallback callback) override;
  void REMOVED_4(
      chromeos::machine_learning::mojom::HandwritingRecognizerSpecPtr spec,
      mojo::PendingReceiver<
          chromeos::machine_learning::mojom::HandwritingRecognizer> receiver,
      REMOVED_4Callback callback) override;
  void LoadSpeechRecognizer(
      chromeos::machine_learning::mojom::SodaConfigPtr spec,
      mojo::PendingRemote<chromeos::machine_learning::mojom::SodaClient>
          soda_client,
      mojo::PendingReceiver<chromeos::machine_learning::mojom::SodaRecognizer>
          soda_recognizer,
      LoadSpeechRecognizerCallback callback) override;
  void LoadGrammarChecker(
      mojo::PendingReceiver<chromeos::machine_learning::mojom::GrammarChecker>
          receiver,
      LoadGrammarCheckerCallback callback) override;
  void LoadTextSuggester(
      mojo::PendingReceiver<chromeos::machine_learning::mojom::TextSuggester>
          receiver,
      chromeos::machine_learning::mojom::TextSuggesterSpecPtr spec,
      LoadTextSuggesterCallback callback) override;
  void LoadWebPlatformHandwritingModel(
      chromeos::machine_learning::web_platform::mojom::
          HandwritingModelConstraintPtr constraint,
      mojo::PendingReceiver<chromeos::machine_learning::web_platform::mojom::
                                HandwritingRecognizer> receiver,
      LoadWebPlatformHandwritingModelCallback callback) override;
  void LoadDocumentScanner(
      mojo::PendingReceiver<chromeos::machine_learning::mojom::DocumentScanner>
          receiver,
      chromeos::machine_learning::mojom::DocumentScannerConfigPtr config,
      LoadDocumentScannerCallback callback) override;
  void CreateWebPlatformModelLoader(
      mojo::PendingReceiver<model_loader::mojom::ModelLoader> receiver,
      model_loader::mojom::CreateModelLoaderOptionsPtr options,
      CreateWebPlatformModelLoaderCallback callback) override;
  void LoadImageAnnotator(
      chromeos::machine_learning::mojom::ImageAnnotatorConfigPtr config,
      mojo::PendingReceiver<
          ::chromeos::machine_learning::mojom::ImageContentAnnotator> receiver,
      LoadImageAnnotatorCallback callback) override;

  void InternalLoadImageAnnotator(
      chromeos::machine_learning::mojom::ImageAnnotatorConfigPtr config,
      mojo::PendingReceiver<
          ::chromeos::machine_learning::mojom::ImageContentAnnotator> receiver,
      LoadImageAnnotatorCallback callback,
      const base::FilePath& dlc_root);

  // Metadata required to load builtin models. Initialized at construction.
  const std::map<chromeos::machine_learning::mojom::BuiltinModelId,
                 BuiltinModelMetadata>
      builtin_model_metadata_;

  const std::string model_dir_;

  // DlcserviceClient used to communicate with DlcService.
  std::unique_ptr<DlcserviceClient> dlcservice_client_;

  // ml_core's DlcClient.
  std::unique_ptr<cros::DlcClient> ml_core_dlc_client_;

  // Primordial receiver bootstrapped over D-Bus. Once opened, is never closed.
  mojo::Receiver<chromeos::machine_learning::mojom::MachineLearningService>
      receiver_;

  // Additional receivers bound via `Clone`.
  mojo::ReceiverSet<chromeos::machine_learning::mojom::MachineLearningService>
      clone_receivers_;

  // Primordial remotes to the worker process.
  // Can not use `mojo::RemoteSet` in Chrome OS for the moment.
  std::vector<
      mojo::Remote<chromeos::machine_learning::mojom::MachineLearningService>>
      worker_remotes_;

  // Holds the platform channels used in bootstrapping mojo connection
  // between the manager and worker processes.
  std::vector<mojo::PlatformChannel> internal_channels;
};

}  // namespace ml

#endif  // ML_MACHINE_LEARNING_SERVICE_IMPL_H_
