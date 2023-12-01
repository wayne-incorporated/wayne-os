// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/handwriting.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/memory/free_deleter.h>
#include <base/native_library.h>
#include <base/strings/string_util.h>

#include "ml/util.h"

namespace ml {
namespace {

using chrome_knowledge::HandwritingRecognizerModelPaths;
using chrome_knowledge::HandwritingRecognizerOptions;
using chromeos::machine_learning::mojom::HandwritingRecognizerSpecPtr;

constexpr char kHandwritingLibraryRelativePath[] = "libhandwriting.so";

// Language codes supported by Longform.
constexpr char kLanguageCodeEn[] = "en";
constexpr char kLanguageCodeGesture[] = "gesture_in_context";

// Returns HandwritingRecognizerModelPaths based on the given `model_path`.
// Language is required to handle exceptions, like "en" (no DLC) and "gesture".
HandwritingRecognizerModelPaths GetModelPaths(
    const std::string& language, const base::FilePath& model_path) {
  HandwritingRecognizerModelPaths paths;
  // English and Gesture are not served by Language Packs; they are installed
  // in rootfs.
  if (language == kLanguageCodeEn) {
    paths.set_reco_model_path(model_path.Append("latin_indy.tflite").value());
    paths.set_seg_model_path(
        model_path.Append("latin_indy_seg.tflite").value());
    paths.set_conf_model_path(
        model_path.Append("latin_indy_conf.tflite").value());
    paths.set_fst_lm_path(model_path.Append("latin_indy.compact.fst").value());
    paths.set_recospec_path(model_path.Append("latin_indy.pb").value());
    return paths;
  } else if (language == kLanguageCodeGesture) {
    paths.set_reco_model_path(
        model_path.Append("gic.reco_model.tflite").value());
    paths.set_recospec_path(model_path.Append("gic.recospec.pb").value());
    return paths;
  }

  // If we get here, it means that Language Packs are enabled.
  // First load the language model and FST.
  paths.set_fst_lm_path(model_path.Append("compact.fst.local").value());
  paths.set_recospec_path(model_path.Append("qrnn.recospec.local").value());
  // Load the model for the script (latin, cyrillic, etc).
  paths.set_reco_model_path(model_path.Append("latin_indy.tflite").value());
  // The following are optionals: segmentation and confidence models.
  const auto seg_file_path = model_path.Append("latin_indy_seg.tflite");
  if (base::PathExists(seg_file_path))
    paths.set_seg_model_path(seg_file_path.value());
  const auto conf_file_path = model_path.Append("latin_indy_conf.tflite");
  if (base::PathExists(conf_file_path))
    paths.set_conf_model_path(conf_file_path.value());

  return paths;
}

class HandwritingLibraryImpl : public HandwritingLibrary {
 public:
  HandwritingLibraryImpl();
  ~HandwritingLibraryImpl() override = default;

  Status GetStatus() const override;
  HandwritingRecognizer CreateHandwritingRecognizer() const override;
  bool LoadHandwritingRecognizer(
      HandwritingRecognizer recognizer,
      HandwritingRecognizerSpecPtr spec) const override;
  bool LoadHandwritingRecognizerFromRootFs(
      HandwritingRecognizer recognizer,
      const std::string& language) const override;
  bool RecognizeHandwriting(
      HandwritingRecognizer recognizer,
      const chrome_knowledge::HandwritingRecognizerRequest& request,
      chrome_knowledge::HandwritingRecognizerResult* result) const override;

  void DestroyHandwritingRecognizer(
      HandwritingRecognizer recognizer) const override;

 private:
  friend class base::NoDestructor<HandwritingLibraryImpl>;
  FRIEND_TEST(HandwritingLibraryTest, CanLoadLibrary);

  // Initialize the handwriting library.
  explicit HandwritingLibraryImpl(const std::string& lib_path);
  HandwritingLibraryImpl(const HandwritingLibraryImpl&) = delete;
  HandwritingLibraryImpl& operator=(const HandwritingLibraryImpl&) = delete;

  std::optional<base::ScopedNativeLibrary> library_;
  Status status_;
  // Path that contains the library and the model files.
  const base::FilePath lib_path_;

  // Store the interface function pointers.
  // TODO(honglinyu) as pointed out by cjmcdonald@, we should group the pointers
  // into a single `HandwritingInterface` struct and make it optional, i.e.,
  // declaring something like |std::optional<HandwritingInterface> interface_|.
  CreateHandwritingRecognizerFn create_handwriting_recognizer_;
  LoadHandwritingRecognizerFn load_handwriting_recognizer_;
  RecognizeHandwritingFn recognize_handwriting_;
  DeleteHandwritingResultDataFn delete_handwriting_result_data_;
  DestroyHandwritingRecognizerFn destroy_handwriting_recognizer_;
};

HandwritingLibraryImpl::HandwritingLibraryImpl(const std::string& lib_path)
    : status_(Status::kUninitialized),
      lib_path_(lib_path),
      create_handwriting_recognizer_(nullptr),
      load_handwriting_recognizer_(nullptr),
      recognize_handwriting_(nullptr),
      delete_handwriting_result_data_(nullptr),
      destroy_handwriting_recognizer_(nullptr) {
  if (!IsHandwritingLibrarySupported()) {
    status_ = Status::kNotSupported;
    return;
  }
  // Load the library with an option preferring own symbols. Otherwise the
  // library will try to call, e.g., external tflite, which leads to crash.
  base::NativeLibraryOptions native_library_options;
  native_library_options.prefer_own_symbols = true;
  library_.emplace(base::LoadNativeLibraryWithOptions(
      lib_path_.Append(kHandwritingLibraryRelativePath), native_library_options,
      nullptr));
  if (!library_->is_valid()) {
    status_ = Status::kLoadLibraryFailed;
    return;
  }

// Helper macro to look up functions from the library, assuming the function
// pointer type is named as (name+"Fn"), which is the case in
// "libhandwriting/handwriting_interface.h".
#define ML_HANDWRITING_LOOKUP_FUNCTION(function_ptr, name)             \
  function_ptr =                                                       \
      reinterpret_cast<name##Fn>(library_->GetFunctionPointer(#name)); \
  if (function_ptr == NULL) {                                          \
    status_ = Status::kFunctionLookupFailed;                           \
    return;                                                            \
  }
  // Look up the function pointers.
  ML_HANDWRITING_LOOKUP_FUNCTION(create_handwriting_recognizer_,
                                 CreateHandwritingRecognizer);
  ML_HANDWRITING_LOOKUP_FUNCTION(load_handwriting_recognizer_,
                                 LoadHandwritingRecognizer);
  ML_HANDWRITING_LOOKUP_FUNCTION(recognize_handwriting_, RecognizeHandwriting);
  ML_HANDWRITING_LOOKUP_FUNCTION(delete_handwriting_result_data_,
                                 DeleteHandwritingResultData);
  ML_HANDWRITING_LOOKUP_FUNCTION(destroy_handwriting_recognizer_,
                                 DestroyHandwritingRecognizer);
#undef ML_HANDWRITING_LOOKUP_FUNCTION

  status_ = Status::kOk;
}

HandwritingLibrary::Status HandwritingLibraryImpl::GetStatus() const {
  return status_;
}

// Proxy functions to the library function pointers.
HandwritingRecognizer HandwritingLibraryImpl::CreateHandwritingRecognizer()
    const {
  DCHECK(status_ == Status::kOk);
  return (*create_handwriting_recognizer_)();
}

bool HandwritingLibraryImpl::LoadHandwritingRecognizerFromRootFs(
    HandwritingRecognizer const recognizer, const std::string& language) const {
  DCHECK(status_ == Status::kOk);

  // options is not used for now.
  const std::string options_pb =
      HandwritingRecognizerOptions().SerializeAsString();

  const std::string paths_pb =
      GetModelPaths(language, lib_path_).SerializeAsString();
  return (*load_handwriting_recognizer_)(recognizer, options_pb.data(),
                                         options_pb.size(), paths_pb.data(),
                                         paths_pb.size());
}

bool HandwritingLibraryImpl::LoadHandwritingRecognizer(
    HandwritingRecognizer const recognizer,
    const HandwritingRecognizerSpecPtr spec) const {
  DCHECK(status_ == Status::kOk);

  // options is not used for now.
  const std::string options_pb =
      HandwritingRecognizerOptions().SerializeAsString();

  base::FilePath model_path;

  // If enabled, get model data from Language Packs instead of the path on
  // rootfs.
  // The only way to know if the client wants to use Language Packs is to check
  // that |language_pack_path| has been set.
  // TODO(claudiomagni): Work out the proper way to indicate that we are using
  //                     Language Packs. Also add tests for this code path.
  if (ml::HandwritingLibrary::IsUseLanguagePacksEnabled() &&
      spec->language_pack_path) {
    const std::string target_path = spec->language_pack_path.value();
    const std::optional<base::FilePath> real_language_pack_path =
        GetRealPath(base::FilePath(target_path));
    if (!real_language_pack_path) {
      LOG(ERROR) << "Bad Language Pack path" << target_path;
      return false;
    }
    model_path = base::FilePath(real_language_pack_path.value());

    // For security, we check that the path is pointing to a safe location on
    // disk.
    if (!IsDlcPathValid(model_path)) {
      LOG(ERROR) << "Not a valid Language Pack path " << target_path;
      return false;
    }
  } else {
    model_path = lib_path_;
  }

  const std::string paths_pb =
      GetModelPaths(spec->language, model_path).SerializeAsString();
  return (*load_handwriting_recognizer_)(recognizer, options_pb.data(),
                                         options_pb.size(), paths_pb.data(),
                                         paths_pb.size());
}

bool HandwritingLibraryImpl::RecognizeHandwriting(
    HandwritingRecognizer const recognizer,
    const chrome_knowledge::HandwritingRecognizerRequest& request,
    chrome_knowledge::HandwritingRecognizerResult* const result) const {
  DCHECK(status_ == Status::kOk);
  const std::string request_pb = request.SerializeAsString();
  char* result_data = nullptr;
  int result_size = 0;
  const bool recognize_result =
      (*recognize_handwriting_)(recognizer, request_pb.data(),
                                request_pb.size(), &result_data, &result_size);
  if (recognize_result) {
    const bool parse_result_status =
        result->ParseFromArray(result_data, result_size);
    DCHECK(parse_result_status);
    // only need to delete result_data if succeeds.
    (*delete_handwriting_result_data_)(result_data);
  }

  return recognize_result;
}

void HandwritingLibraryImpl::DestroyHandwritingRecognizer(
    HandwritingRecognizer const recognizer) const {
  DCHECK(status_ == Status::kOk);
  (*destroy_handwriting_recognizer_)(recognizer);
}

static HandwritingLibrary* g_fake_handwriting_library = nullptr;

}  // namespace

constexpr char HandwritingLibrary::kHandwritingDefaultInstallDir[];

HandwritingLibrary* HandwritingLibrary::GetInstance(
    const std::string& lib_path) {
  if (g_fake_handwriting_library) {
    return g_fake_handwriting_library;
  }
  static base::NoDestructor<HandwritingLibraryImpl> instance(lib_path);
  return instance.get();
}

void HandwritingLibrary::UseFakeHandwritingLibraryForTesting(
    HandwritingLibrary* const fake_handwriting_library) {
  g_fake_handwriting_library = fake_handwriting_library;
}

}  // namespace ml
