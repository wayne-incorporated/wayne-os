// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "pwgtocanonij/canon_filter.h"

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <iostream>
#include <memory>
#include <unordered_map>
#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/stringprintf.h>
#include <cups/cups.h>
#include <cups/ppd.h>

namespace canonij {

CanonFilter::CanonFilter(const char* jobId,
                         brillo::SafeFD inputFd,
                         base::ScopedTempDir tmpDir)
    : inputFd_(std::move(inputFd)), tmpDir_(std::move(tmpDir)) {
  // Job ID needs to be 8 characters long, per the ICD.  Prepend with 0's.
  for (int padding = 8 - strlen(jobId); padding > 0; --padding) {
    jobId_ += "0";
  }
  jobId_ += jobId;

  // In order to cancel a job, we block this signal and then check for pending
  // signals later on.
  sigset_t sigset;
  sigemptyset(&sigset);
  sigaddset(&sigset, SIGTERM);
  sigprocmask(SIG_BLOCK, &sigset, nullptr);
}

CanonFilter::~CanonFilter() {
  if (ppd_ != nullptr) {
    ppdClose(ppd_);
  }
  CloseRasterFiles();
}

void CanonFilter::CloseRasterFiles() {
  if (rasterIn_ != nullptr) {
    cupsRasterClose(rasterIn_);
    rasterIn_ = nullptr;
  }
  if (rasterOut_ != nullptr) {
    cupsRasterClose(rasterOut_);
    rasterOut_ = nullptr;
  }
}

bool CanonFilter::Run(const char* options) {
  // If this fails, we can just exit since it doesn't send any data to the
  // printer.
  if (!Setup(options)) {
    std::cerr << "ERROR: Unable to initialize filter." << std::endl;
    return false;
  }

  // If any of these fail, we don't continue with the next step, but we always
  // send the EndJob so we can leave the printer in a good state.
  bool retval = true;
  if (!ShouldCancel() && !SendStartJob()) {
    std::cerr << "ERROR: Unable to send StartJob data." << std::endl;
    retval = false;
  }

  if (!ShouldCancel() && retval && !SendConfiguration()) {
    std::cerr << "ERROR: Unable to send Configuration data." << std::endl;
    retval = false;
  }

  if (!ShouldCancel() && retval && !ProcessInput()) {
    std::cerr << "ERROR: Unable to process input file." << std::endl;
    retval = false;
  }

  if (!SendEndJob()) {
    std::cerr << "ERROR: Unable to send EndJob data." << std::endl;
    retval = false;
  }

  return retval;
}

void CanonFilter::SetOutputForTesting(int fd) {
  outputFd_ = fd;
}

void CanonFilter::SetCancelCountdownForTesting(int count) {
  testCancelCountdown_ = count;
}

bool CanonFilter::Setup(const char* cmdLineOptions) {
  char* ppdFilename = getenv("PPD");
  if (ppdFilename == nullptr) {
    std::cerr << "ERROR: PPD env var not specified." << std::endl;
    return false;
  }
  ppd_ = ppdOpenFile(ppdFilename);
  if (!ppd_) {
    std::cerr << "ERROR: Unable to open ppd file: " << ppdFilename << std::endl;
    return false;
  }

  cups_option_t* options;
  const int num_options = cupsParseOptions(cmdLineOptions, 0, &options);

  ppdMarkDefaults(ppd_);
  cupsMarkOptions(ppd_, num_options, options);

  cupsFreeOptions(num_options, options);

  // Get all of the necessary values from the PPD.
  paperSize_ = PageSizeValue();
  paperType_ = MediaTypeValue();
  borderless_ = BorderlessValue();
  colorMode_ = ColorModelValue();
  duplex_ = DuplexValue();

  if (!paperSize_ || !paperType_ || !borderless_ || !colorMode_ || !duplex_) {
    std::cerr << "ERROR: Unable to get PPD values during Setup." << std::endl;
    return false;
  }

  return true;
}

bool CanonFilter::SendStartJob() {
  const std::string startJobText = base::StringPrintf(
      R"(<?xml version="1.0" encoding="utf-8" ?>
<cmd xmlns:ivec="http://www.canon.com/ns/cmd/2008/07/common/">
    <ivec:contents>
        <ivec:operation>StartJob</ivec:operation>
        <ivec:param_set servicetype="print">
            <ivec:jobID>%s</ivec:jobID>
            <ivec:bidi>0</ivec:bidi>
        </ivec:param_set>
    </ivec:contents>
</cmd>)",
      jobId_.c_str());

  return WriteString(startJobText);
}

bool CanonFilter::SendConfiguration() {
  const std::string configText = base::StringPrintf(
      R"(<?xml version="1.0" encoding="utf-8" ?>
<cmd xmlns:ivec="http://www.canon.com/ns/cmd/2008/07/common/">
    <ivec:contents>
        <ivec:operation>SetConfiguration</ivec:operation>
        <ivec:param_set servicetype="print">
            <ivec:jobID>%s</ivec:jobID>
            <ivec:papersize>%s</ivec:papersize>
            <ivec:papertype>%s</ivec:papertype>
            <ivec:borderlessprint>%s</ivec:borderlessprint>
            <ivec:printcolormode>%s</ivec:printcolormode>
            <ivec:duplexprint>%s</ivec:duplexprint>
        </ivec:param_set>
    </ivec:contents>
</cmd>)",
      jobId_.c_str(), paperSize_.value().c_str(), paperType_.value().c_str(),
      borderless_.value().c_str(), colorMode_.value().c_str(),
      duplex_.value().c_str());

  return WriteString(configText);
}

bool CanonFilter::ProcessInput() {
  // This filter is expecting input in PWG raster format and it outputs PWG
  // raster with an XML header specifying the number of PWG raster bytes.  Since
  // the CUPS raster functions don't return the number of PWG raster bytes
  // read/written, there's no way to get the number of PWG raster bytes.
  // Instead, we create a temporary PWG raster file to write to (the CUPS
  // raster functions work fine for this), and we then get the size of that
  // temporary file to create our XML header.  We then read the temporary PWG
  // raster file and write to our output.
  CloseRasterFiles();
  rasterIn_ = cupsRasterOpen(inputFd_.get(), CUPS_RASTER_READ);

  unsigned pageCount = 0;
  cups_page_header2_t header;
  while (cupsRasterReadHeader2(rasterIn_, &header) && !ShouldCancel()) {
    ++pageCount;
    std::cerr << "PAGE: " << pageCount << " " << header.NumCopies << std::endl;

    // For each page we read from the input, we will create a temporary output
    // raster file.
    const base::FilePath filePath =
        tmpDir_.GetPath().Append(base::StringPrintf("Page_%d", pageCount));
    const char* rasterOutPath = filePath.value().c_str();
    base::ScopedFD tmpFile(
        open(rasterOutPath, O_RDWR | O_TRUNC | O_CREAT, S_IWUSR | S_IRUSR));
    if (tmpFile.get() < 0) {
      std::cerr << "ERROR: Unable to open tmp file " << rasterOutPath << ": "
                << strerror(errno) << "." << std::endl;
      return false;
    }
    rasterOut_ = cupsRasterOpen(tmpFile.get(), CUPS_RASTER_WRITE_PWG);

    // Write the header to our output raster file, followed by the raster data.
    if (!cupsRasterWriteHeader2(rasterOut_, &header)) {
      std::cerr << "ERROR: Unable to write raster header for page " << pageCount
                << "." << std::endl;
      return false;
    }
    const unsigned nbytes = header.cupsBytesPerLine;
    const unsigned nlines = header.cupsHeight;
    std::vector<uint8_t> line(nbytes, 0);
    for (int y = nlines; y > 0 && !ShouldCancel(); --y) {
      if (cupsRasterReadPixels(rasterIn_, line.data(), nbytes) != nbytes) {
        std::cerr << "ERROR: Unable to read raster data for page " << pageCount
                  << "." << std::endl;
        return false;
      }

      if (cupsRasterWritePixels(rasterOut_, line.data(), nbytes) != nbytes) {
        std::cerr << "ERROR: Unable to write raster data for page " << pageCount
                  << "." << std::endl;
        return false;
      }
    }

    // This will cleanup the raster object but doesn't do anything with the
    // underlying file descriptor.
    cupsRasterClose(rasterOut_);
    rasterOut_ = nullptr;

    // Figure out the size of our temp file, then read the contents and write to
    // our output.
    const off_t rasterSize = lseek(tmpFile.get(), 0, SEEK_END);
    if (rasterSize < 0) {
      std::cerr << "ERROR: Unable to find size of raster file for page "
                << pageCount << ": " << strerror(errno) << "." << std::endl;
      return false;
    }
    SendPageHeader(rasterSize);

    if (lseek(tmpFile.get(), 0, SEEK_SET) < 0) {
      std::cerr << "ERROR: Unable to read temp raster file for page "
                << pageCount << ": " << strerror(errno) << "." << std::endl;
      return false;
    }
    // Read 1MB chunks.
    std::vector<char> buffer(1048576, 0);
    ssize_t bytesRead = 0;
    ssize_t bytesWritten = 0;
    while ((bytesRead = read(tmpFile.get(), buffer.data(), buffer.size())) >
           0) {
      if (!WriteString(std::string_view(buffer.data(), bytesRead))) {
        std::cerr << "ERROR: Unable to write output for page " << pageCount
                  << ": " << strerror(errno) << "." << std::endl;
        return false;
      }
      bytesWritten += bytesRead;
    }

    // Sanity check to make sure the value we put in the XML matches the number
    // of bytes we actually wrote.
    if (rasterSize != bytesWritten) {
      std::cerr << "ERROR: expected to write " << rasterSize
                << " bytes of raster data, but wrote " << bytesWritten << "."
                << std::endl;
      return false;
    }
  }

  cupsRasterClose(rasterIn_);
  rasterIn_ = nullptr;

  return true;
}

bool CanonFilter::SendPageHeader(unsigned byteCount) {
  const std::string pageText = base::StringPrintf(
      R"(<?xml version="1.0" encoding="utf-8" ?>
<cmd xmlns:ivec="http://www.canon.com/ns/cmd/2008/07/common/">
    <ivec:contents>
        <ivec:operation>SendData</ivec:operation>
        <ivec:param_set servicetype="print">
            <ivec:jobID>%s</ivec:jobID>
            <ivec:format>PWGRaster</ivec:format>
            <ivec:datasize>%u</ivec:datasize>
        </ivec:param_set>
    </ivec:contents>
</cmd>)",
      jobId_.c_str(), byteCount);

  return WriteString(pageText);
}

bool CanonFilter::SendEndJob() {
  const std::string endJobText = base::StringPrintf(
      R"(<?xml version="1.0" encoding="utf-8" ?>
<cmd xmlns:ivec="http://www.canon.com/ns/cmd/2008/07/common/">
    <ivec:contents>
        <ivec:operation>EndJob</ivec:operation>
        <ivec:param_set servicetype="print">
            <ivec:jobID>%s</ivec:jobID>
        </ivec:param_set>
    </ivec:contents>
</cmd>)",
      jobId_.c_str());

  return WriteString(endJobText);
}

bool CanonFilter::WriteString(std::string_view str) {
  size_t bytesToWrite = str.length();
  size_t offset = 0;
  while (bytesToWrite > 0) {
    ssize_t bytesWritten = write(outputFd_, str.data() + offset, bytesToWrite);
    if (bytesWritten < 0) {
      // For the EAGAIN case, we just try again.  For any other error we return
      // an error code.
      if (errno != EAGAIN) {
        std::cerr << "ERROR: Unable to write data: " << strerror(errno) << "."
                  << std::endl;
        return false;
      }
    } else {
      bytesToWrite -= bytesWritten;
      offset += bytesWritten;
    }
  }

  return true;
}

std::optional<std::string> CanonFilter::PageSizeValue() const {
  static const std::unordered_map<std::string, std::string> values{
      {"Letter", "na_letter_8.5x11in"},
      {"Letter.bl", "na_letter_8.5x11in"},
      {"legal", "na_legal_8.5x14in"},
      {"A5", "iso_a5_148x210mm"},
      {"A4", "iso_a4_210x297mm"},
      {"A4.bl", "iso_a4_210x297mm"},
      {"B5", "jis_b5_182x257mm"},
      {"4x6", "na_index-4x6_4x6in"},
      {"4x6.bl", "na_index-4x6_4x6in"},
      {"5x7", "na_5x7_5x7in"},
      {"5x7.bl", "na_5x7_5x7in"},
      {"8x10", "custom_canon_203x254mm"},
      {"8x10.bl", "custom_canon_203x254mm"},
      {"envelop10p", "na_number-10_4.125x9.5in"},
      {"envelopdlp", "iso_dl_110x220mm"},
      {"l", "custom_canon_89x127mm"},
      {"l.bl", "custom_canon_89x127mm"},
      {"Postcard", "jpn_hagaki_100x148mm"},
      {"Postcard.bl", "jpn_hagaki_100x148mm"},
      {"square127", "custom_canon_127x127mm"},
  };

  const ppd_choice_t* ppdValue = ppdFindMarkedChoice(ppd_, "PageSize");
  if (ppdValue) {
    auto it = values.find(ppdValue->choice);
    if (it != values.end()) {
      return it->second;
    }
  }

  std::cerr << "ERROR: Unable to retrieve PageSize from PPD." << std::endl;
  return std::nullopt;
}

std::optional<std::string> CanonFilter::MediaTypeValue() const {
  static const std::unordered_map<std::string, std::string> values{
      {"plain", "stationery"},
      {"glossygold", "custom-media-type-canon-3"},
      {"proplatinum", "custom-media-type-canon-16"},
      {"luster", "custom-media-type-canon-17"},
      {"semigloss", "custom-media-type-canon-6"},
      {"glossypaper", "custom-media-type-canon-14"},
      {"matte", "custom-media-type-canon-15"},
      {"photopaper", "photographic"},
      {"envelope", "custom-media-type-canon-18"},
      {"highres", "custom-media-type-canon-9"},
      {"photo", "custom-media-type-canon-19"},
      {"ijpostcard", "custom-media-type-canon-11"},
      {"postcard", "custom-media-type-canon-12"}};

  const ppd_choice_t* ppdValue = ppdFindMarkedChoice(ppd_, "MediaType");
  if (ppdValue) {
    auto it = values.find(ppdValue->choice);
    if (it != values.end()) {
      return it->second;
    }
  }

  std::cerr << "ERROR: Unable to retrieve MediaType from PPD." << std::endl;
  return std::nullopt;
}

std::optional<std::string> CanonFilter::BorderlessValue() const {
  const ppd_choice_t* ppdValue = ppdFindMarkedChoice(ppd_, "PageSize");
  if (ppdValue) {
    const ppd_size_t* pageSize = ppdPageSize(ppd_, ppdValue->choice);
    if (pageSize) {
      // Check to see if we have 0 margins.  For these Canon PPDs, the width is
      // one less than the right-left margins.  Similarly for the length.
      if (pageSize->left == 0.0 && pageSize->bottom == 0.0 &&
          ((pageSize->width - pageSize->right) <= 1.0) &&
          ((pageSize->length - pageSize->top) <= 1.0)) {
        return "ON";
      } else {
        return "OFF";
      }
    }
  }

  std::cerr << "ERROR: Unable to retrieve Borderless value from PPD."
            << std::endl;
  return std::nullopt;
}

std::optional<std::string> CanonFilter::ColorModelValue() const {
  const ppd_choice_t* ppdValue = ppdFindMarkedChoice(ppd_, "ColorModel");
  if (ppdValue) {
    // If this is "rgb", return Color.  For all other values return monochrome.
    if (!strcmp(ppdValue->choice, "rgb")) {
      return "color";
    }
    return "monochrome";
  }

  std::cerr << "ERROR: Unable to retrieve ColorModel from PPD." << std::endl;
  return std::nullopt;
}

std::optional<std::string> CanonFilter::DuplexValue() const {
  const ppd_choice_t* ppdValue = ppdFindMarkedChoice(ppd_, "Duplex");
  if (ppdValue) {
    // If this is "None", return OFF.  For all other values return ON.
    if (!strcmp(ppdValue->choice, "None")) {
      return "OFF";
    }
    return "ON";
  }

  std::cerr << "ERROR: Unable to retrieve Duplex from PPD." << std::endl;
  return std::nullopt;
}

bool CanonFilter::ShouldCancel() {
  if (testCancelCountdown_.has_value()) {
    if (*testCancelCountdown_ <= 0) {
      return true;
    }
    --(*testCancelCountdown_);
    return false;
  }

  sigset_t sigset;
  sigemptyset(&sigset);
  return (sigpending(&sigset) == 0) && sigismember(&sigset, SIGTERM);
}

}  // namespace canonij
