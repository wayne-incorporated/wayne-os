// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_DOCUMENT_SCANNER_LIBRARY_H_
#define ML_DOCUMENT_SCANNER_LIBRARY_H_

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/no_destructor.h>
#include <base/scoped_native_library.h>
#include <chromeos/libdocumentscanner/document_scanner.h>

#include "ml/util.h"

namespace ml {

using LibDocumentScanner = chromeos_camera::document_scanning::DocumentScanner;

// Default document scanning model directory.
constexpr char kLibDocumentScannerDefaultDir[] =
    "/usr/share/cros-camera/libfs/";

struct DocumentScannerLibraryParams {
  base::FilePath root_dir = base::FilePath(kLibDocumentScannerDefaultDir);
  // TODO(b/196931992): Update this value if there is any better value. And
  // consider set the value via Finch framework if we are not confident about
  // current value and need more experiments.
  float score_threshold = 2.0;
};

// A singleton proxy class for the document scanner DSO.
class DocumentScannerLibrary {
 public:
  enum class InitializeResult {
    kOk = 0,
    kUninitialized = 1,
    kLoadLibraryFailed = 2,
    kFunctionLookupFailed = 3,
  };

  DocumentScannerLibrary(const DocumentScannerLibrary&) = delete;
  DocumentScannerLibrary& operator=(const DocumentScannerLibrary&) = delete;
  ~DocumentScannerLibrary();

  static DocumentScannerLibrary* GetInstance();

  // Returns whether DocumentScannerLibrary is supported.
  static constexpr bool IsSupported() {
    return (IsEnabledOnRootfs() || IsEnabledOnDlc()) && !IsAsan();
  }

  // Returns bool of use.ondevice_document_scanning.
  static constexpr bool IsEnabledOnRootfs() {
    return USE_ONDEVICE_DOCUMENT_SCANNER;
  }

  // Returns bool of use.ondevice_document_scanning_dlc.
  static constexpr bool IsEnabledOnDlc() {
    return USE_ONDEVICE_DOCUMENT_SCANNER_DLC;
  }

  bool IsInitialized() { return initialized_; }

  InitializeResult Initialize(const DocumentScannerLibraryParams& params =
                                  DocumentScannerLibraryParams{});

  // Creates and returns a document scanner which is needed for using the other
  // interfaces.
  std::unique_ptr<LibDocumentScanner> CreateDocumentScanner() const;

 private:
  friend class base::NoDestructor<DocumentScannerLibrary>;

  DocumentScannerLibrary();

  base::ScopedNativeLibrary library_;
  float score_threshold_;

  // Store the interface function pointers.
  chromeos_camera::document_scanning::CreateDocumentScannerFn
      create_document_scanner_ = nullptr;

  bool initialized_ = false;
};

}  // namespace ml

#endif  // ML_DOCUMENT_SCANNER_LIBRARY_H_
