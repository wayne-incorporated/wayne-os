// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/machine_learning_service_impl.h"

#include <memory>
#include <utility>

#include <unistd.h>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/file.h>
#include <base/files/memory_mapped_file.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <brillo/message_loops/message_loop.h>
#include <mojo/public/cpp/bindings/self_owned_receiver.h>
#include <tensorflow/lite/model.h>
#include <unicode/putil.h>
#include <unicode/udata.h>
#include <utils/memory/mmap.h>

#include "ml/document_scanner_impl.h"
#include "ml/document_scanner_library.h"
#include "ml/grammar_checker_impl.h"
#include "ml/grammar_library.h"
#include "ml/handwriting.h"
#include "ml/handwriting_recognizer_impl.h"
#include "ml_core/dlc/dlc_client.h"
#if USE_ONDEVICE_IMAGE_CONTENT_ANNOTATION
#include "ml/image_content_annotation.h"
#endif
#include "ml/image_content_annotation_impl.h"
#include "ml/model_impl.h"
#include "ml/mojom/handwriting_recognizer.mojom.h"
#include "ml/mojom/image_content_annotation.mojom.h"
#include "ml/mojom/model.mojom.h"
#include "ml/mojom/soda.mojom.h"
#include "ml/mojom/web_platform_handwriting.mojom.h"
#include "ml/mojom/web_platform_model.mojom.h"
#include "ml/process.h"
#include "ml/request_metrics.h"
#include "ml/soda_recognizer_impl.h"
#include "ml/text_classifier_impl.h"
#include "ml/text_suggester_impl.h"
#include "ml/text_suggestions.h"
#include "ml/web_platform_handwriting_recognizer_impl.h"
#include "ml/web_platform_model_loader_impl.h"

namespace ml {

namespace {

using ::chromeos::machine_learning::mojom::BuiltinModelId;
using ::chromeos::machine_learning::mojom::BuiltinModelSpecPtr;
using ::chromeos::machine_learning::mojom::FlatBufferModelSpecPtr;
using ::chromeos::machine_learning::mojom::HandwritingRecognizer;
using ::chromeos::machine_learning::mojom::HandwritingRecognizerSpec;
using ::chromeos::machine_learning::mojom::HandwritingRecognizerSpecPtr;
using ::chromeos::machine_learning::mojom::LoadHandwritingModelResult;
using ::chromeos::machine_learning::mojom::LoadModelResult;
using ::chromeos::machine_learning::mojom::MachineLearningService;
using ::chromeos::machine_learning::mojom::Model;
using ::chromeos::machine_learning::mojom::SodaClient;
using ::chromeos::machine_learning::mojom::SodaConfigPtr;
using ::chromeos::machine_learning::mojom::SodaRecognizer;
using ::chromeos::machine_learning::mojom::TextClassifier;

constexpr char kSystemModelDir[] = "/opt/google/chrome/ml_models/";
// Base name for UMA metrics related to model loading (`LoadBuiltinModel`,
// `LoadFlatBufferModel`, `LoadTextClassifier` or LoadHandwritingModel).
constexpr char kMetricsRequestName[] = "LoadModelResult";

constexpr int kMlServiceDBusUid = 20177;

constexpr char kIcuDataFilePath[] = "/opt/google/chrome/icudtl.dat";

// Used to hold the mmap object of the icu data file. Each process should only
// have one instance of it. Intentionally never close it.
// We can not make it as a member of `MachineLearningServiceImpl` because it
// will crash the unit test (because in that case, when the
// `MachineLearningServiceImpl` object is destructed, the file will be
// unmapped but the icu data can not be reset in the testing process).
base::MemoryMappedFile* g_icu_data_mmap_file = nullptr;

void InitIcuIfNeeded() {
  if (!g_icu_data_mmap_file) {
    g_icu_data_mmap_file = new base::MemoryMappedFile();
    CHECK(g_icu_data_mmap_file->Initialize(
        base::FilePath(kIcuDataFilePath),
        base::MemoryMappedFile::Access::READ_ONLY));
    // Init the Icu library.
    UErrorCode err = U_ZERO_ERROR;
    udata_setCommonData(const_cast<uint8_t*>(g_icu_data_mmap_file->data()),
                        &err);
    DCHECK(err == U_ZERO_ERROR);
    // Never try to load Icu data from files.
    udata_setFileAccess(UDATA_ONLY_PACKAGES, &err);
    DCHECK(err == U_ZERO_ERROR);
  }
}

// Used to avoid duplicating code between two types of recognizers.
// Currently used in function `LoadHandwritingLibAndRecognizer`.
template <class Recognizer>
struct RecognizerTraits;

template <>
struct RecognizerTraits<HandwritingRecognizer> {
  using SpecPtr = HandwritingRecognizerSpecPtr;
  using Callback = MachineLearningServiceImpl::LoadHandwritingModelCallback;
  using Impl = HandwritingRecognizerImpl;
  static constexpr char kModelName[] = "HandwritingModel";
};

template <>
struct RecognizerTraits<
    chromeos::machine_learning::web_platform::mojom::HandwritingRecognizer> {
  using SpecPtr = chromeos::machine_learning::web_platform::mojom::
      HandwritingModelConstraintPtr;
  using Callback =
      MachineLearningServiceImpl::LoadWebPlatformHandwritingModelCallback;
  using Impl = WebPlatformHandwritingRecognizerImpl;
  static constexpr char kModelName[] = "WebPlatformHandwritingModel";
};

void LoadDocumentScannerFromPath(
    mojo::PendingReceiver<chromeos::machine_learning::mojom::DocumentScanner>
        receiver,
    MachineLearningServiceImpl::LoadDocumentScannerCallback callback,
    const std::string& root_path) {
  RequestMetrics request_metrics("DocumentScanner", kMetricsRequestName);
  request_metrics.StartRecordingPerformanceMetrics();

  // Load DocumentScannerLibrary.
  auto* const document_scanner_library =
      ml::DocumentScannerLibrary::GetInstance();
  if (!document_scanner_library->IsInitialized()) {
    auto result = document_scanner_library->Initialize(
        {.root_dir = base::FilePath(root_path)});

    if (result != ml::DocumentScannerLibrary::InitializeResult::kOk) {
      LOG(ERROR) << "Initialize ml::DocumentScannerLibrary with error "
                 << static_cast<int>(result);
      std::move(callback).Run(LoadModelResult::LOAD_MODEL_ERROR);
      request_metrics.RecordRequestEvent(LoadModelResult::LOAD_MODEL_ERROR);
      brillo::MessageLoop::current()->BreakLoop();
      return;
    }
  }

  // Create DocumentScanner.
  mojo::MakeSelfOwnedReceiver(
      std::make_unique<DocumentScannerImpl>(
          document_scanner_library->CreateDocumentScanner()),
      std::move(receiver));
  std::move(callback).Run(LoadModelResult::OK);

  request_metrics.FinishRecordingPerformanceMetrics();
  request_metrics.RecordRequestEvent(LoadModelResult::OK);
}

}  // namespace

MachineLearningServiceImpl::MachineLearningServiceImpl(
    mojo::PendingReceiver<
        chromeos::machine_learning::mojom::MachineLearningService> receiver,
    base::OnceClosure disconnect_handler,
    const std::string& model_dir)
    : builtin_model_metadata_(GetBuiltinModelMetadata()),
      model_dir_(model_dir),
      receiver_(this, std::move(receiver)) {
  receiver_.set_disconnect_handler(std::move(disconnect_handler));
}

MachineLearningServiceImpl::MachineLearningServiceImpl(
    mojo::PendingReceiver<
        chromeos::machine_learning::mojom::MachineLearningService> receiver,
    base::OnceClosure disconnect_handler,
    dbus::Bus* bus)
    : MachineLearningServiceImpl(
          std::move(receiver), std::move(disconnect_handler), kSystemModelDir) {
  if (bus) {
    dlcservice_client_ = std::make_unique<DlcserviceClient>(bus);
  }
}

void MachineLearningServiceImpl::Clone(
    mojo::PendingReceiver<MachineLearningService> receiver) {
  clone_receivers_.Add(this, std::move(receiver));
}

void MachineLearningServiceImpl::LoadBuiltinModel(
    BuiltinModelSpecPtr spec,
    mojo::PendingReceiver<Model> receiver,
    LoadBuiltinModelCallback callback) {
  // Unsupported models do not have metadata entries.
  const auto metadata_lookup = builtin_model_metadata_.find(spec->id);
  if (metadata_lookup == builtin_model_metadata_.end()) {
    LOG(WARNING) << "LoadBuiltinModel requested for unsupported model ID "
                 << spec->id << ".";
    std::move(callback).Run(LoadModelResult::MODEL_SPEC_ERROR);
    RecordModelSpecificationErrorEvent();
    return;
  }

  // If it is run in the control process, spawn a worker process and forward the
  // request to it.
  if (Process::GetInstance()->IsControlProcess()) {
    pid_t worker_pid;
    mojo::PlatformChannel channel;
    constexpr char kModelName[] = "BuiltinModel";
    if (!Process::GetInstance()->SpawnWorkerProcessAndGetPid(
            channel, kModelName, &worker_pid)) {
      // UMA metrics have already been reported in
      // `SpawnWorkerProcessAndGetPid`.
      std::move(callback).Run(LoadModelResult::LOAD_MODEL_ERROR);
      return;
    }
    Process::GetInstance()
        ->SendMojoInvitationAndGetRemote(worker_pid, std::move(channel),
                                         kModelName)
        ->LoadBuiltinModel(std::move(spec), std::move(receiver),
                           std::move(callback));
    return;
  }

  // From here below is the worker process.

  const BuiltinModelMetadata& metadata = metadata_lookup->second;

  DCHECK(!metadata.metrics_model_name.empty());

  RequestMetrics request_metrics(metadata.metrics_model_name,
                                 kMetricsRequestName);
  request_metrics.StartRecordingPerformanceMetrics();

  // Attempt to load model.
  const std::string model_path = model_dir_ + metadata.model_file;
  std::unique_ptr<tflite::FlatBufferModel> model =
      tflite::FlatBufferModel::BuildFromFile(model_path.c_str());
  if (model == nullptr) {
    LOG(ERROR) << "Failed to load model file '" << model_path << "'.";
    std::move(callback).Run(LoadModelResult::LOAD_MODEL_ERROR);
    request_metrics.RecordRequestEvent(LoadModelResult::LOAD_MODEL_ERROR);
    brillo::MessageLoop::current()->BreakLoop();
    return;
  }

  ModelImpl::Create(std::make_unique<ModelDelegate>(
                        metadata.required_inputs, metadata.required_outputs,
                        std::move(model), metadata.metrics_model_name),
                    std::move(receiver));

  std::move(callback).Run(LoadModelResult::OK);

  request_metrics.FinishRecordingPerformanceMetrics();
  request_metrics.RecordRequestEvent(LoadModelResult::OK);
}

void MachineLearningServiceImpl::LoadFlatBufferModel(
    FlatBufferModelSpecPtr spec,
    mojo::PendingReceiver<Model> receiver,
    LoadFlatBufferModelCallback callback) {
  DCHECK(!spec->metrics_model_name.empty());

  RequestMetrics request_metrics(spec->metrics_model_name, kMetricsRequestName);
  request_metrics.StartRecordingPerformanceMetrics();

  // If it is run in the control process, spawn a worker process and forward the
  // request to it.
  if (Process::GetInstance()->IsControlProcess()) {
    pid_t worker_pid;
    mojo::PlatformChannel channel;
    constexpr char kModelName[] = "FlatBufferModel";
    if (!Process::GetInstance()->SpawnWorkerProcessAndGetPid(
            channel, kModelName, &worker_pid)) {
      // UMA metrics have already been reported in
      // `SpawnWorkerProcessAndGetPid`.
      std::move(callback).Run(LoadModelResult::LOAD_MODEL_ERROR);
      return;
    }
    Process::GetInstance()
        ->SendMojoInvitationAndGetRemote(worker_pid, std::move(channel),
                                         kModelName)
        ->LoadFlatBufferModel(std::move(spec), std::move(receiver),
                              std::move(callback));
    return;
  }

  // From here below is the worker process.

  // Take the ownership of the content of `model_string` because `ModelDelegate`
  // has to hold the memory.
  auto model_data =
      std::make_unique<AlignedModelData>(std::move(spec->model_string));

  std::unique_ptr<tflite::FlatBufferModel> model =
      tflite::FlatBufferModel::VerifyAndBuildFromBuffer(model_data->data(),
                                                        model_data->size());
  if (model == nullptr) {
    LOG(ERROR) << "Failed to load model string of metric name: "
               << spec->metrics_model_name << "'.";
    std::move(callback).Run(LoadModelResult::LOAD_MODEL_ERROR);
    request_metrics.RecordRequestEvent(LoadModelResult::LOAD_MODEL_ERROR);
    brillo::MessageLoop::current()->BreakLoop();
    return;
  }

  ModelImpl::Create(
      std::make_unique<ModelDelegate>(
          std::map<std::string, int>(spec->inputs.begin(), spec->inputs.end()),
          std::map<std::string, int>(spec->outputs.begin(),
                                     spec->outputs.end()),
          std::move(model), std::move(model_data), spec->metrics_model_name),
      std::move(receiver));

  std::move(callback).Run(LoadModelResult::OK);

  request_metrics.FinishRecordingPerformanceMetrics();
  request_metrics.RecordRequestEvent(LoadModelResult::OK);
}

void MachineLearningServiceImpl::LoadTextClassifier(
    mojo::PendingReceiver<TextClassifier> receiver,
    LoadTextClassifierCallback callback) {
  // If it is run in the control process, spawn a worker process and forward the
  // request to it.
  if (Process::GetInstance()->IsControlProcess()) {
    pid_t worker_pid;
    mojo::PlatformChannel channel;
    constexpr char kModelName[] = "TextClassifierModel";
    if (!Process::GetInstance()->SpawnWorkerProcessAndGetPid(
            channel, kModelName, &worker_pid)) {
      // UMA metrics have already been reported in
      // `SpawnWorkerProcessAndGetPid`.
      std::move(callback).Run(LoadModelResult::LOAD_MODEL_ERROR);
      return;
    }
    Process::GetInstance()
        ->SendMojoInvitationAndGetRemote(worker_pid, std::move(channel),
                                         kModelName)
        ->LoadTextClassifier(std::move(receiver), std::move(callback));
    return;
  }

  // From here below is the worker process.

  RequestMetrics request_metrics("TextClassifier", kMetricsRequestName);
  request_metrics.StartRecordingPerformanceMetrics();

  // Create the TextClassifier.
  if (!TextClassifierImpl::Create(std::move(receiver))) {
    LOG(ERROR) << "Failed to create TextClassifierImpl object.";
    std::move(callback).Run(LoadModelResult::LOAD_MODEL_ERROR);
    request_metrics.RecordRequestEvent(LoadModelResult::LOAD_MODEL_ERROR);
    brillo::MessageLoop::current()->BreakLoop();
    return;
  }

  // initialize the icu library.
  InitIcuIfNeeded();

  std::move(callback).Run(LoadModelResult::OK);

  request_metrics.FinishRecordingPerformanceMetrics();
  request_metrics.RecordRequestEvent(LoadModelResult::OK);
}

template <class Recognizer>
void LoadHandwritingLibAndRecognizer(
    typename RecognizerTraits<Recognizer>::SpecPtr spec,
    mojo::PendingReceiver<Recognizer> receiver,
    typename RecognizerTraits<Recognizer>::Callback callback,
    const std::string& root_path) {
  RequestMetrics request_metrics(RecognizerTraits<Recognizer>::kModelName,
                                 kMetricsRequestName);
  request_metrics.StartRecordingPerformanceMetrics();

  // Returns error if root_path is empty.
  if (root_path.empty()) {
    std::move(callback).Run(LoadHandwritingModelResult::DLC_GET_PATH_ERROR);
    request_metrics.RecordRequestEvent(
        LoadHandwritingModelResult::DLC_GET_PATH_ERROR);
    return;
  }

  // Load HandwritingLibrary.
  auto* const hwr_library = ml::HandwritingLibrary::GetInstance(root_path);

  if (hwr_library->GetStatus() != ml::HandwritingLibrary::Status::kOk) {
    LOG(ERROR) << "Initialize ml::HandwritingLibrary with error "
               << static_cast<int>(hwr_library->GetStatus());

    switch (hwr_library->GetStatus()) {
      case ml::HandwritingLibrary::Status::kLoadLibraryFailed: {
        std::move(callback).Run(
            LoadHandwritingModelResult::LOAD_NATIVE_LIB_ERROR);
        request_metrics.RecordRequestEvent(
            LoadHandwritingModelResult::LOAD_NATIVE_LIB_ERROR);
        return;
      }
      case ml::HandwritingLibrary::Status::kFunctionLookupFailed: {
        std::move(callback).Run(
            LoadHandwritingModelResult::LOAD_FUNC_PTR_ERROR);
        request_metrics.RecordRequestEvent(
            LoadHandwritingModelResult::LOAD_FUNC_PTR_ERROR);
        return;
      }
      default: {
        std::move(callback).Run(LoadHandwritingModelResult::LOAD_MODEL_ERROR);
        request_metrics.RecordRequestEvent(
            LoadHandwritingModelResult::LOAD_MODEL_ERROR);
        return;
      }
    }
  }

  // Create HandwritingRecognizer.
  if (!RecognizerTraits<Recognizer>::Impl::Create(std::move(spec),
                                                  std::move(receiver))) {
    LOG(ERROR) << "LoadHandwritingRecognizer returned false.";
    std::move(callback).Run(LoadHandwritingModelResult::LOAD_MODEL_FILES_ERROR);
    request_metrics.RecordRequestEvent(
        LoadHandwritingModelResult::LOAD_MODEL_FILES_ERROR);
    return;
  }

  std::move(callback).Run(LoadHandwritingModelResult::OK);
  request_metrics.FinishRecordingPerformanceMetrics();
  request_metrics.RecordRequestEvent(LoadHandwritingModelResult::OK);
}

void MachineLearningServiceImpl::LoadHandwritingModel(
    chromeos::machine_learning::mojom::HandwritingRecognizerSpecPtr spec,
    mojo::PendingReceiver<
        chromeos::machine_learning::mojom::HandwritingRecognizer> receiver,
    LoadHandwritingModelCallback callback) {
  constexpr bool is_handwriting_enabled =
      ml::HandwritingLibrary::IsUseLibHandwritingEnabled();
  constexpr bool is_language_packs_enabled =
      ml::HandwritingLibrary::IsUseLanguagePacksEnabled();
  constexpr bool is_handwriting_dlc_enabled =
      ml::HandwritingLibrary::IsUseLibHandwritingDlcEnabled();

  if (!is_handwriting_enabled && !is_language_packs_enabled &&
      !is_handwriting_dlc_enabled) {
    // If:
    //  1) handwriting is not on rootfs and
    //  2) handwriting is not in DLC and
    //  3) language packs is not enabled
    // then this function should not be called because the client side should
    // also be guarded by the same flags.
    LOG(ERROR) << "Clients should not call LoadHandwritingModel without "
                  "Handwriting enabled.";
    std::move(callback).Run(LoadHandwritingModelResult::LOAD_MODEL_ERROR);
    return;
  }

  // If it is run in the control process, spawn a worker process and forward the
  // request to it.
  if (Process::GetInstance()->IsControlProcess()) {
    pid_t worker_pid;
    mojo::PlatformChannel channel;
    constexpr char kModelName[] = "HandwritingModel";
    if (!Process::GetInstance()->SpawnWorkerProcessAndGetPid(
            channel, kModelName, &worker_pid)) {
      // UMA metrics has already been reported in `SpawnWorkerProcessAndGetPid`.
      std::move(callback).Run(LoadHandwritingModelResult::LOAD_MODEL_ERROR);
      return;
    }
    Process::GetInstance()
        ->SendMojoInvitationAndGetRemote(worker_pid, std::move(channel),
                                         kModelName)
        ->LoadHandwritingModel(std::move(spec), std::move(receiver),
                               std::move(callback));
    return;
  }

  // From here below is the worker process.

  // TODO(claudiomagni): When Language Packs is complete, deprecate the first
  // case and only use Language Packs.
  if (is_handwriting_enabled || is_language_packs_enabled) {
    // TODO(honglinyu): when Web Platform HWR's `HandwritingModelConstraint`
    // also contains the `library_dlc_path` field, we will not need to pass in
    // the `lib_path` separately because it is already in `spec`. Now this
    // needed to share the template function `LoadHandwritingLibAndRecognizer`.
    const std::string lib_path = spec->library_dlc_path.value_or(
        ml::HandwritingLibrary::kHandwritingDefaultInstallDir);
    LoadHandwritingLibAndRecognizer<HandwritingRecognizer>(
        std::move(spec), std::move(receiver), std::move(callback), lib_path);
    return;
  }

  // If handwriting is installed as DLC, get the dir and subsequently load it
  // from there.
  if (is_handwriting_dlc_enabled) {
    dlcservice_client_->GetDlcRootPath(
        "libhandwriting",
        base::BindOnce(&LoadHandwritingLibAndRecognizer<HandwritingRecognizer>,
                       std::move(spec), std::move(receiver),
                       std::move(callback)));
    return;
  }

  NOTREACHED();
}

void MachineLearningServiceImpl::REMOVED_4(
    HandwritingRecognizerSpecPtr spec,
    mojo::PendingReceiver<HandwritingRecognizer> receiver,
    REMOVED_4Callback callback) {
  NOTIMPLEMENTED();
}

void MachineLearningServiceImpl::LoadSpeechRecognizer(
    SodaConfigPtr config,
    mojo::PendingRemote<SodaClient> soda_client,
    mojo::PendingReceiver<SodaRecognizer> soda_recognizer,
    LoadSpeechRecognizerCallback callback) {
  // TODO(crbug.com/1222888): Perform validation prior to spawning worker
  // process.

  // If it is run in the control process, spawn a worker process and forward the
  // request to it.
  if (Process::GetInstance()->IsControlProcess()) {
    pid_t worker_pid;
    mojo::PlatformChannel channel;
    constexpr char kModelName[] = "SodaModel";
    if (!Process::GetInstance()->SpawnWorkerProcessAndGetPid(
            channel, kModelName, &worker_pid)) {
      // UMA metrics has already been reported in `SpawnWorkerProcessAndGetPid`.
      std::move(callback).Run(LoadModelResult::LOAD_MODEL_ERROR);
      return;
    }
    Process::GetInstance()
        ->SendMojoInvitationAndGetRemote(worker_pid, std::move(channel),
                                         kModelName)
        ->LoadSpeechRecognizer(std::move(config), std::move(soda_client),
                               std::move(soda_recognizer), std::move(callback));
    return;
  }

  // From here below is the worker process.

  RequestMetrics request_metrics("Soda", kMetricsRequestName);
  request_metrics.StartRecordingPerformanceMetrics();

  // Create the SodaRecognizer.
  if (!SodaRecognizerImpl::Create(std::move(config), std::move(soda_client),
                                  std::move(soda_recognizer))) {
    LOG(ERROR) << "Failed to create SodaRecognizerImpl object.";
    // TODO(robsc): it may be better that SODA has its specific enum values to
    // return, similar to handwriting. So before we finalize the impl of SODA
    // Mojo API, we may revisit this return value.
    std::move(callback).Run(LoadModelResult::LOAD_MODEL_ERROR);
    request_metrics.RecordRequestEvent(LoadModelResult::LOAD_MODEL_ERROR);
    brillo::MessageLoop::current()->BreakLoop();
    return;
  }

  std::move(callback).Run(LoadModelResult::OK);

  request_metrics.FinishRecordingPerformanceMetrics();
  request_metrics.RecordRequestEvent(LoadModelResult::OK);
}

void MachineLearningServiceImpl::LoadGrammarChecker(
    mojo::PendingReceiver<chromeos::machine_learning::mojom::GrammarChecker>
        receiver,
    LoadGrammarCheckerCallback callback) {
  // If it is run in the control process, spawn a worker process and forward the
  // request to it.
  if (Process::GetInstance()->IsControlProcess()) {
    pid_t worker_pid;
    mojo::PlatformChannel channel;
    constexpr char kModelName[] = "GrammarCheckerModel";
    if (!Process::GetInstance()->SpawnWorkerProcessAndGetPid(
            channel, kModelName, &worker_pid)) {
      // UMA metrics have already been reported in
      // `SpawnWorkerProcessAndGetPid`.
      std::move(callback).Run(LoadModelResult::LOAD_MODEL_ERROR);
      return;
    }
    Process::GetInstance()
        ->SendMojoInvitationAndGetRemote(worker_pid, std::move(channel),
                                         kModelName)
        ->LoadGrammarChecker(std::move(receiver), std::move(callback));
    return;
  }

  // From here below is the worker process.

  RequestMetrics request_metrics("GrammarChecker", kMetricsRequestName);
  request_metrics.StartRecordingPerformanceMetrics();

  // Load GrammarLibrary.
  auto* const grammar_library = ml::GrammarLibrary::GetInstance();

  if (grammar_library->GetStatus() ==
      ml::GrammarLibrary::Status::kNotSupported) {
    LOG(ERROR) << "Initialize ml::GrammarLibrary with error "
               << static_cast<int>(grammar_library->GetStatus());

    std::move(callback).Run(LoadModelResult::FEATURE_NOT_SUPPORTED_ERROR);
    request_metrics.RecordRequestEvent(
        LoadModelResult::FEATURE_NOT_SUPPORTED_ERROR);
    brillo::MessageLoop::current()->BreakLoop();
    return;
  }

  if (grammar_library->GetStatus() != ml::GrammarLibrary::Status::kOk) {
    LOG(ERROR) << "Initialize ml::GrammarLibrary with error "
               << static_cast<int>(grammar_library->GetStatus());

    std::move(callback).Run(LoadModelResult::LOAD_MODEL_ERROR);
    request_metrics.RecordRequestEvent(LoadModelResult::LOAD_MODEL_ERROR);
    brillo::MessageLoop::current()->BreakLoop();
    return;
  }

  // Create GrammarChecker.
  if (!GrammarCheckerImpl::Create(std::move(receiver))) {
    std::move(callback).Run(LoadModelResult::LOAD_MODEL_ERROR);
    request_metrics.RecordRequestEvent(LoadModelResult::LOAD_MODEL_ERROR);
    brillo::MessageLoop::current()->BreakLoop();
    return;
  }

  std::move(callback).Run(LoadModelResult::OK);

  request_metrics.FinishRecordingPerformanceMetrics();
  request_metrics.RecordRequestEvent(LoadModelResult::OK);
}

void MachineLearningServiceImpl::LoadTextSuggester(
    mojo::PendingReceiver<chromeos::machine_learning::mojom::TextSuggester>
        receiver,
    chromeos::machine_learning::mojom::TextSuggesterSpecPtr spec,
    LoadTextSuggesterCallback callback) {
  RequestMetrics request_metrics("TextSuggester", kMetricsRequestName);
  request_metrics.StartRecordingPerformanceMetrics();

  // Load TextSuggestions library.
  auto* const text_suggestions = ml::TextSuggestions::GetInstance();

  if (text_suggestions->GetStatus() ==
      ml::TextSuggestions::Status::kNotSupported) {
    LOG(ERROR) << "Initialize ml::TextSuggestions with error "
               << static_cast<int>(text_suggestions->GetStatus());

    std::move(callback).Run(LoadModelResult::FEATURE_NOT_SUPPORTED_ERROR);
    request_metrics.RecordRequestEvent(
        LoadModelResult::FEATURE_NOT_SUPPORTED_ERROR);
    return;
  }

  if (text_suggestions->GetStatus() != ml::TextSuggestions::Status::kOk) {
    LOG(ERROR) << "Initialize ml::TextSuggestions with error "
               << static_cast<int>(text_suggestions->GetStatus());

    std::move(callback).Run(LoadModelResult::LOAD_MODEL_ERROR);
    request_metrics.RecordRequestEvent(LoadModelResult::LOAD_MODEL_ERROR);
    return;
  }

  // Create TextSuggester.
  if (!TextSuggesterImpl::Create(std::move(receiver), std::move(spec))) {
    std::move(callback).Run(LoadModelResult::LOAD_MODEL_ERROR);
    request_metrics.RecordRequestEvent(LoadModelResult::LOAD_MODEL_ERROR);
    return;
  }

  std::move(callback).Run(LoadModelResult::OK);

  request_metrics.FinishRecordingPerformanceMetrics();
  request_metrics.RecordRequestEvent(LoadModelResult::OK);
}

void MachineLearningServiceImpl::LoadWebPlatformHandwritingModel(
    chromeos::machine_learning::web_platform::mojom::
        HandwritingModelConstraintPtr constraint,
    mojo::PendingReceiver<
        chromeos::machine_learning::web_platform::mojom::HandwritingRecognizer>
        receiver,
    LoadWebPlatformHandwritingModelCallback callback) {
  constexpr bool is_handwriting_enabled =
      ml::HandwritingLibrary::IsUseLibHandwritingEnabled();
  constexpr bool is_handwriting_dlc_enabled =
      ml::HandwritingLibrary::IsUseLibHandwritingDlcEnabled();

  if (!is_handwriting_enabled && !is_handwriting_dlc_enabled) {
    // If handwriting is not on rootfs and not in DLC, this function should not
    // be called because the client side should also be guarded by the same
    // flags.
    LOG(ERROR) << "Clients should not call LoadHandwritingModel without "
                  "Handwriting enabled.";
    std::move(callback).Run(LoadHandwritingModelResult::LOAD_MODEL_ERROR);
    return;
  }

  // If it is run in the control process, spawn a worker process and forward the
  // request to it.
  if (Process::GetInstance()->IsControlProcess()) {
    pid_t worker_pid;
    mojo::PlatformChannel channel;
    constexpr char kModelName[] = "WebPlatformHandwritingModel";
    if (!Process::GetInstance()->SpawnWorkerProcessAndGetPid(
            channel, kModelName, &worker_pid)) {
      // UMA metrics has already been reported in `SpawnWorkerProcessAndGetPid`.
      std::move(callback).Run(LoadHandwritingModelResult::LOAD_MODEL_ERROR);
      return;
    }
    Process::GetInstance()
        ->SendMojoInvitationAndGetRemote(worker_pid, std::move(channel),
                                         kModelName)
        ->LoadWebPlatformHandwritingModel(
            std::move(constraint), std::move(receiver), std::move(callback));
    return;
  }

  // From here below is in the worker process.
  DCHECK(Process::GetInstance()->IsWorkerProcess());

  // If handwriting is installed on rootfs, load it from there.
  if (is_handwriting_enabled) {
    LoadHandwritingLibAndRecognizer<
        chromeos::machine_learning::web_platform::mojom::HandwritingRecognizer>(
        std::move(constraint), std::move(receiver), std::move(callback),
        ml::HandwritingLibrary::kHandwritingDefaultInstallDir);
    return;
  }

  // If handwriting is installed as DLC, get the dir and subsequently load it
  // from there.
  if (is_handwriting_dlc_enabled) {
    dlcservice_client_->GetDlcRootPath(
        "libhandwriting",
        base::BindOnce(&LoadHandwritingLibAndRecognizer<
                           chromeos::machine_learning::web_platform::mojom::
                               HandwritingRecognizer>,
                       std::move(constraint), std::move(receiver),
                       std::move(callback)));
    return;
  }

  NOTREACHED();
}

void MachineLearningServiceImpl::LoadDocumentScanner(
    mojo::PendingReceiver<chromeos::machine_learning::mojom::DocumentScanner>
        receiver,
    chromeos::machine_learning::mojom::DocumentScannerConfigPtr config,
    LoadDocumentScannerCallback callback) {
  if (!ml::DocumentScannerLibrary::IsSupported()) {
    LOG(ERROR) << "Document scanner library is not supported";
    std::move(callback).Run(LoadModelResult::FEATURE_NOT_SUPPORTED_ERROR);
    return;
  }

  // If it is run in the control process, spawn a worker process and forward the
  // request to it.
  if (Process::GetInstance()->IsControlProcess()) {
    pid_t worker_pid;
    mojo::PlatformChannel channel;
    constexpr char kModelName[] = "DocumentScanner";
    if (!Process::GetInstance()->SpawnWorkerProcessAndGetPid(
            channel, kModelName, &worker_pid)) {
      // UMA metrics have already been reported in
      // `SpawnWorkerProcessAndGetPid`.
      std::move(callback).Run(LoadModelResult::LOAD_MODEL_ERROR);
      return;
    }
    Process::GetInstance()
        ->SendMojoInvitationAndGetRemote(worker_pid, std::move(channel),
                                         kModelName)
        ->LoadDocumentScanner(std::move(receiver), std::move(config),
                              std::move(callback));
    return;
  }

  // From here below is the worker process.
  std::string path = ml::kLibDocumentScannerDefaultDir;
  if (!config.is_null()) {
    path = config->library_dlc_path->path;
  }
  LoadDocumentScannerFromPath(std::move(receiver), std::move(callback),
                              std::move(path));
}

void MachineLearningServiceImpl::CreateWebPlatformModelLoader(
    mojo::PendingReceiver<model_loader::mojom::ModelLoader> receiver,
    model_loader::mojom::CreateModelLoaderOptionsPtr options,
    CreateWebPlatformModelLoaderCallback callback) {
  // If it is run in the control process, spawn a worker process and forward the
  // request to it.
  if (Process::GetInstance()->IsControlProcess()) {
    // Currently, we only support "TfLite".
    //   - If the input type is `kAuto`, we will try to load it as "TfLite".
    //   - If the device preference is `kGpu`, it will fallback to CPU.
    if (options->model_format != model_loader::mojom::ModelFormat::kTfLite &&
        options->model_format != model_loader::mojom::ModelFormat::kAuto) {
      std::move(callback).Run(
          model_loader::mojom::CreateModelLoaderResult::kNotSupported);
      return;
    }

    pid_t worker_pid;
    mojo::PlatformChannel channel;
    constexpr char kModelName[] = "WebPlatformFlatBufferModel";
    if (!Process::GetInstance()->SpawnWorkerProcessAndGetPid(
            channel, kModelName, &worker_pid)) {
      // UMA metrics have already been reported in
      // `SpawnWorkerProcessAndGetPid`.
      std::move(callback).Run(
          model_loader::mojom::CreateModelLoaderResult::kUnknownError);
      return;
    }
    Process::GetInstance()
        ->SendMojoInvitationAndGetRemote(worker_pid, std::move(channel),
                                         kModelName)
        ->CreateWebPlatformModelLoader(std::move(receiver), std::move(options),
                                       std::move(callback));
    return;
  }

  // From here below is the worker process.
  RequestMetrics request_metrics("WebPlatformTfLiteFlatBufferModel",
                                 "CreateModelLoaderResult");
  request_metrics.StartRecordingPerformanceMetrics();

  WebPlatformModelLoaderImpl::Create(std::move(receiver), std::move(options));

  std::move(callback).Run(model_loader::mojom::CreateModelLoaderResult::kOk);

  request_metrics.FinishRecordingPerformanceMetrics();
  request_metrics.RecordRequestEvent(
      model_loader::mojom::CreateModelLoaderResult::kOk);
}

void MachineLearningServiceImpl::LoadImageAnnotator(
    chromeos::machine_learning::mojom::ImageAnnotatorConfigPtr config,
    mojo::PendingReceiver<
        ::chromeos::machine_learning::mojom::ImageContentAnnotator> receiver,
    LoadImageAnnotatorCallback callback) {
  if (!USE_ONDEVICE_IMAGE_CONTENT_ANNOTATION) {
    LOG(ERROR) << "Image content annotator library is not supported";
    std::move(callback).Run(LoadModelResult::FEATURE_NOT_SUPPORTED_ERROR);
    return;
  }

  // If it is run in the control process, spawn a worker process and forward the
  // request to it.
  if (Process::GetInstance()->IsControlProcess()) {
    pid_t worker_pid;
    mojo::PlatformChannel channel;
    constexpr char kModelName[] = "ImageAnnotator";
    if (!Process::GetInstance()->SpawnWorkerProcessAndGetPid(
            channel, kModelName, &worker_pid)) {
      // UMA metrics have already been reported in
      // `SpawnWorkerProcessAndGetPid`.
      std::move(callback).Run(LoadModelResult::LOAD_MODEL_ERROR);
      return;
    }
    Process::GetInstance()
        ->SendMojoInvitationAndGetRemote(worker_pid, std::move(channel),
                                         kModelName)
        ->LoadImageAnnotator(std::move(config), std::move(receiver),
                             std::move(callback));
    return;
  }
  // From here below is the worker process.

  // Change euid so we can connect to dbus to install DLC.
  if (seteuid(kMlServiceDBusUid) != 0) {
    LOG(ERROR) << "Failed to seteuid for dbus";
    std::move(callback).Run(LoadModelResult::LOAD_MODEL_ERROR);
    return;
  }
  // Create ml core dlc client for this worker process.
  auto split = base::SplitOnceCallback(std::move(callback));
  ml_core_dlc_client_ = cros::DlcClient::Create(
      base::BindOnce(&MachineLearningServiceImpl::InternalLoadImageAnnotator,
                     base::Unretained(this), std::move(config),
                     std::move(receiver), std::move(split.first)),
      base::BindOnce(
          [](LoadImageAnnotatorCallback callback,
             const std::string& error_msg) {
            LOG(ERROR) << "Couldn't install DLC: " << error_msg;
            std::move(callback).Run(LoadModelResult::LOAD_MODEL_ERROR);
          },
          std::move(split.second)));
  if (seteuid(0) != 0) {
    LOG(ERROR) << "Failed to seteuid";
    std::move(callback).Run(LoadModelResult::LOAD_MODEL_ERROR);
    return;
  }
  ml_core_dlc_client_->InstallDlc();
}

void MachineLearningServiceImpl::InternalLoadImageAnnotator(
    chromeos::machine_learning::mojom::ImageAnnotatorConfigPtr config,
    mojo::PendingReceiver<
        ::chromeos::machine_learning::mojom::ImageContentAnnotator> receiver,
    LoadImageAnnotatorCallback callback,
    const base::FilePath& dlc_root) {
  RequestMetrics request_metrics("ImageAnnotator", kMetricsRequestName);
  request_metrics.StartRecordingPerformanceMetrics();

#if USE_ONDEVICE_IMAGE_CONTENT_ANNOTATION
  auto* const ica_library = ImageContentAnnotationLibrary::GetInstance(
      dlc_root.Append("libcros_ml_core_internal.so"));
  if (ica_library->GetStatus() != ImageContentAnnotationLibrary::Status::kOk) {
    LOG(ERROR) << "Failed to initialize ImageContentAnnotationLibrary, error "
               << static_cast<int>(ica_library->GetStatus());
    std::move(callback).Run(LoadModelResult::LOAD_MODEL_ERROR);
    return;
  }
#else
  ImageContentAnnotationLibrary* const ica_library = nullptr;
#endif
  if (!ImageContentAnnotatorImpl::Create(std::move(config), std::move(receiver),
                                         ica_library)) {
    LOG(ERROR) << "Image content annotator creation failed.";
    std::move(callback).Run(LoadModelResult::LOAD_MODEL_ERROR);
    request_metrics.RecordRequestEvent(LoadModelResult::LOAD_MODEL_ERROR);
    brillo::MessageLoop::current()->BreakLoop();
    return;
  }

  request_metrics.FinishRecordingPerformanceMetrics();
  std::move(callback).Run(LoadModelResult::OK);
  request_metrics.RecordRequestEvent(LoadModelResult::OK);
}

}  // namespace ml
