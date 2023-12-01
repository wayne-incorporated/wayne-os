// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/document_scanner_library.h"

#include <string>

#include <base/check.h>
#include <base/logging.h>
#include <base/native_library.h>

namespace ml {
namespace {

using chromeos_camera::document_scanning::CreateDocumentScannerFn;

constexpr char kDocumentScannerLibraryRelativePath[] = "libdocumentscanner.so";

}  // namespace

DocumentScannerLibrary::DocumentScannerLibrary() = default;

DocumentScannerLibrary::~DocumentScannerLibrary() = default;

DocumentScannerLibrary* DocumentScannerLibrary::GetInstance() {
  static base::NoDestructor<DocumentScannerLibrary> instance;
  return instance.get();
}

DocumentScannerLibrary::InitializeResult DocumentScannerLibrary::Initialize(
    const DocumentScannerLibraryParams& params) {
  DCHECK(IsSupported());
  if (initialized_) {
    return InitializeResult::kOk;
  }

  base::NativeLibraryOptions native_library_options = {
      .prefer_own_symbols = true,
  };

  base::NativeLibraryLoadError error;
  library_ = base::ScopedNativeLibrary(base::LoadNativeLibraryWithOptions(
      params.root_dir.Append(kDocumentScannerLibraryRelativePath),
      native_library_options, &error));
  if (!library_.is_valid()) {
    LOG(ERROR) << "Failed to load document scanner library: "
               << error.ToString();
    return InitializeResult::kLoadLibraryFailed;
  }

  create_document_scanner_ = reinterpret_cast<CreateDocumentScannerFn>(
      library_.GetFunctionPointer("CreateDocumentScanner"));
  if (create_document_scanner_ == nullptr) {
    return InitializeResult::kFunctionLookupFailed;
  }

  score_threshold_ = params.score_threshold;
  initialized_ = true;
  return InitializeResult::kOk;
}

std::unique_ptr<LibDocumentScanner>
DocumentScannerLibrary::CreateDocumentScanner() const {
  DCHECK(initialized_);
  return (*create_document_scanner_)(score_threshold_);
}

}  // namespace ml
