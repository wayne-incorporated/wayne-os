// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PWGTOCANONIJ_CANON_FILTER_H_
#define PWGTOCANONIJ_CANON_FILTER_H_

#include <optional>
#include <string>
#include <string_view>

#include <base/files/scoped_temp_dir.h>
#include <brillo/files/safe_fd.h>
#include <cups/ppd.h>
#include <cups/raster.h>

namespace canonij {

class CanonFilter {
 public:
  explicit CanonFilter(const char* jobId,
                       brillo::SafeFD inputFd,
                       base::ScopedTempDir tmpDir);
  virtual ~CanonFilter();

  // Run our filter.  This will process the input file specified in the
  // constructor and write PDL output to stdout.  Return true on success, false
  // on error.
  bool Run(const char* options);

  // Specify an output file descriptor to write to instead of using stdout.  The
  // caller is responsible for opening/closing the file represented by fd.
  void SetOutputForTesting(int fd);
  // If this is set, the ShouldCancel method will not check for any signals, but
  // rather will return true after it has been called 'count' times.
  void SetCancelCountdownForTesting(int count);

 private:
  bool Setup(const char* cmdLineOptions);
  bool SendStartJob();
  bool SendConfiguration();
  bool ProcessInput();
  bool SendPageHeader(unsigned byteCount);
  bool SendEndJob();
  bool WriteString(std::string_view str);

  std::optional<std::string> PageSizeValue() const;
  std::optional<std::string> MediaTypeValue() const;
  std::optional<std::string> BorderlessValue() const;
  std::optional<std::string> ColorModelValue() const;
  std::optional<std::string> DuplexValue() const;

  bool ShouldCancel();

  void CloseRasterFiles();

 private:
  brillo::SafeFD inputFd_;
  int outputFd_ = STDOUT_FILENO;
  base::ScopedTempDir tmpDir_;
  std::string jobId_ = "";
  std::optional<std::string> paperSize_;
  std::optional<std::string> paperType_;
  std::optional<std::string> borderless_;
  std::optional<std::string> colorMode_;
  std::optional<std::string> duplex_;
  std::optional<int> testCancelCountdown_;
  ppd_file_t* ppd_ = nullptr;
  cups_raster_t* rasterIn_ = nullptr;
  cups_raster_t* rasterOut_ = nullptr;
};

}  // namespace canonij

#endif  // PWGTOCANONIJ_CANON_FILTER_H_
