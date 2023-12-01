// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/grammar_library.h"

#include <string>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/native_library.h>

namespace ml {
namespace {

constexpr char kGrammarFilesPath[] = "/opt/google/chrome/ml_models/grammar/";
constexpr char kGrammarLibraryRelativePath[] = "libgrammar.so";
constexpr char kGrammarModelRelativePath[] = "translation_model.pb";

}  // namespace

GrammarLibrary::GrammarLibrary()
    : status_(Status::kUninitialized),
      create_grammar_checker_(nullptr),
      load_grammar_checker_(nullptr),
      check_grammar_(nullptr),
      delete_grammar_checker_result_data_(nullptr),
      destroy_grammar_checker_(nullptr) {
  if (!IsGrammarLibrarySupported()) {
    status_ = Status::kNotSupported;
    return;
  }

  base::NativeLibraryOptions native_library_options;
  native_library_options.prefer_own_symbols = true;
  base::NativeLibraryLoadError error;
  library_.emplace(base::LoadNativeLibraryWithOptions(
      base::FilePath(kGrammarFilesPath).Append(kGrammarLibraryRelativePath),
      native_library_options, &error));
  if (!library_->is_valid()) {
    status_ = Status::kLoadLibraryFailed;
    LOG(ERROR) << error.ToString();
    return;
  }

#define ML_GRAMMAR_LOOKUP_FUNCTION(function_ptr, name)                 \
  function_ptr =                                                       \
      reinterpret_cast<name##Fn>(library_->GetFunctionPointer(#name)); \
  if (function_ptr == NULL) {                                          \
    status_ = Status::kFunctionLookupFailed;                           \
    return;                                                            \
  }
  // Look up the function pointers.
  ML_GRAMMAR_LOOKUP_FUNCTION(create_grammar_checker_, CreateGrammarChecker);
  ML_GRAMMAR_LOOKUP_FUNCTION(load_grammar_checker_, LoadGrammarChecker);
  ML_GRAMMAR_LOOKUP_FUNCTION(check_grammar_, CheckGrammar);
  ML_GRAMMAR_LOOKUP_FUNCTION(delete_grammar_checker_result_data_,
                             DeleteGrammarCheckerResultData);
  ML_GRAMMAR_LOOKUP_FUNCTION(destroy_grammar_checker_, DestroyGrammarChecker);
#undef ML_GRAMMAR_LOOKUP_FUNCTION

  status_ = Status::kOk;
}

GrammarLibrary::Status GrammarLibrary::GetStatus() const {
  return status_;
}

GrammarLibrary* GrammarLibrary::GetInstance() {
  static base::NoDestructor<GrammarLibrary> instance;
  return instance.get();
}

GrammarChecker GrammarLibrary::CreateGrammarChecker() const {
  DCHECK(status_ == Status::kOk);
  return (*create_grammar_checker_)();
}

bool GrammarLibrary::LoadGrammarChecker(GrammarChecker const checker) const {
  DCHECK(status_ == Status::kOk);
  chrome_knowledge::GrammarCheckerModelPaths paths;
  paths.set_model_path(base::FilePath(kGrammarFilesPath)
                           .Append(kGrammarModelRelativePath)
                           .value());
  const std::string paths_pb = paths.SerializeAsString();
  return (*load_grammar_checker_)(checker, paths_pb.data(), paths_pb.size());
}

bool GrammarLibrary::CheckGrammar(
    GrammarChecker const checker,
    const chrome_knowledge::GrammarCheckerRequest& request,
    chrome_knowledge::GrammarCheckerResult* const result) const {
  DCHECK(status_ == Status::kOk);
  const std::string request_pb = request.SerializeAsString();
  char* result_data = nullptr;
  int result_size = 0;
  const bool check_result =
      (*check_grammar_)(checker, request_pb.data(), request_pb.size(),
                        &result_data, &result_size);
  if (check_result) {
    const bool parse_result_status =
        result->ParseFromArray(result_data, result_size);
    DCHECK(parse_result_status);
    // only need to delete result_data if succeeds.
    (*delete_grammar_checker_result_data_)(result_data);
  }

  return check_result;
}

void GrammarLibrary::DestroyGrammarChecker(GrammarChecker const checker) const {
  DCHECK(status_ == Status::kOk);
  (*destroy_grammar_checker_)(checker);
}

}  // namespace ml
