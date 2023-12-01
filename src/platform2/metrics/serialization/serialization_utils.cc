// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics/serialization/serialization_utils.h"

#include <sys/file.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_file.h"
#include "base/logging.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "metrics/serialization/metric_sample.h"

#include <base/check.h>

#define READ_WRITE_ALL_FILE_FLAGS \
  (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)

namespace metrics {
namespace {

// Magic string that gets written at the beginning of the message file
// when the file has been partially uploaded.
constexpr char kMagicString[] = {'S', 'K', 'I', 'P'};

// Leaves a marker at the beginning of the metrics file, to indicate that the
// first part of the file has been processed.  The marker starts with a 4-byte
// magic number ("SKIP") followed by the offset to the remaining samples.
// Returns true on success, false on errors.
//
// Since the file could also start with a regular message, whose 4-byte header
// indicates its size, the magic number must be an invalid size i.e. greater
// than kMessageMaxLength when read as an uint32_t in any byte order.
bool RemovePreviousSamples(int fd) {
  off_t offset = lseek(fd, 0, SEEK_CUR);
  char marker[sizeof(kMagicString) + sizeof(off_t)];

  if (offset == static_cast<off_t>(-1)) {
    PLOG(ERROR) << "cannot find offset in metrics log";
    return false;
  } else if (offset < sizeof(marker)) {
    LOG(ERROR) << "metrics log offset is too small: " << offset;
    return false;
  }

  // Fill marker with magic string and offset, then store it.
  memcpy(marker, kMagicString, sizeof(kMagicString));
  memcpy(marker + sizeof(kMagicString), &offset, sizeof(off_t));
  if (pwrite(fd, marker, sizeof(marker), 0) != sizeof(marker)) {
    PLOG(ERROR) << "cannot write marker to metrics log";
    return false;
  }

  // Optimization: zero out file content between the marker and the first valid
  // sample.  NOTE: the fallocate() call writes zeros over the entire range
  // specified, and optimizes away zero-filled blocks.  We don't care if the
  // optimization fails.
  int punch_hole_mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
  if (fallocate(fd, punch_hole_mode, sizeof(marker), offset - sizeof(marker)))
    PLOG(WARNING) << "cannot punch hole in metrics log";

  return true;
}

// Seeks to the first valid sample in an incompletely-uploaded metrics log, as
// needed.
void SeekToSamples(int fd) {
  char marker[sizeof(kMagicString) + sizeof(off_t)];
  off_t offset;

  // Special case (and, we hope, also the most common): if the beginning of the
  // file does not contain a valid marker, nothing else needs to be done.
  // Also, we don't need to worry about errors, as we'll hit them again shortly.
  if (pread(fd, &marker, sizeof(marker), 0) != sizeof(marker) ||
      memcmp(marker, kMagicString, sizeof(kMagicString)) != 0)
    return;

  memcpy(&offset, marker + sizeof(kMagicString), sizeof(off_t));
  if (lseek(fd, offset, SEEK_SET) < 0) {
    // This isn't really recoverable, but the earlier pread() did not change
    // the offset, and an error will be generated when reading the first sample.
    PLOG(WARNING) << "could not seek to samples at offset " << offset;
  }
}

// Reads the next message from |file_descriptor| into |message|.
//
// |message| will be set to the empty string if no message could be read (EOF)
// or the message was badly constructed.
//
// Returns false if no message can be read from this file anymore (EOF or
// unrecoverable error).
bool ReadMessage(int fd, std::string* message_out, size_t* bytes_used_out) {
  CHECK(message_out);

  int result;
  uint32_t message_size;
  const size_t message_hdr_size = sizeof(message_size);
  // The file containing the metrics does not leave the device, so the writer
  // and the reader always have the same endianness.
  result = HANDLE_EINTR(read(fd, &message_size, sizeof(message_size)));
  if (result < 0) {
    PLOG(ERROR) << "failed to read message header";
    return false;
  }
  if (result == 0) {
    // This indicates a normal EOF.
    return false;
  }
  if (result < message_hdr_size) {
    LOG(ERROR) << "bad read size " << result << ", expecting "
               << sizeof(message_size);
    return false;
  }

  // kMessageMaxLength applies to the entire message: the 4-byte
  // length field and the content.
  if (message_size > SerializationUtils::kMessageMaxLength) {
    LOG(ERROR) << "message too long, length = " << message_size;
    if (HANDLE_EINTR(lseek(fd, message_size - message_hdr_size, SEEK_CUR)) ==
        -1) {
      PLOG(ERROR) << "error while skipping message. Aborting.";
      return false;
    }
    // Badly formatted message was skipped. Treat the badly formatted sample as
    // an empty sample.
    message_out->clear();
    return true;
  }

  if (message_size < message_hdr_size) {
    LOG(ERROR) << "message too short, length = " << message_size;
    return false;
  }

  message_size -= message_hdr_size;  // The message size includes itself.
  char buffer[SerializationUtils::kMessageMaxLength];
  if (!base::ReadFromFD(fd, buffer, message_size)) {
    LOG(ERROR) << "failed to read message body";
    return false;
  }
  *message_out = std::string(buffer, message_size);
  *bytes_used_out = message_size + message_hdr_size;
  return true;
}

}  // namespace

MetricSample SerializationUtils::ParseSample(const std::string& sample) {
  if (sample.empty())
    return MetricSample();

  // Can't split at \0 anymore, so replace null chars with \n.
  std::string sample_copy = sample;
  std::replace(sample_copy.begin(), sample_copy.end(), '\0', '\n');
  std::vector<std::string> parts = base::SplitString(
      sample_copy, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
  // We should have two null terminated strings so split should produce
  // three chunks.
  if (parts.size() != 3) {
    LOG(ERROR) << "splitting message on \\0 produced " << parts.size()
               << " parts (expected 3)";
    return MetricSample();
  }
  const std::string& name = parts[0];
  const std::string& value = parts[1];

  if (base::EqualsCaseInsensitiveASCII(name, "crash")) {
    return MetricSample::CrashSample(value);
  } else if (base::EqualsCaseInsensitiveASCII(name, "histogram")) {
    return MetricSample::ParseHistogram(value);
  } else if (base::EqualsCaseInsensitiveASCII(name, "linearhistogram")) {
    return MetricSample::ParseLinearHistogram(value);
  } else if (base::EqualsCaseInsensitiveASCII(name, "sparsehistogram")) {
    return MetricSample::ParseSparseHistogram(value);
  } else if (base::EqualsCaseInsensitiveASCII(name, "useraction")) {
    return MetricSample::UserActionSample(value);
  } else {
    LOG(ERROR) << "invalid event type: " << name << ", value: " << value;
  }
  return MetricSample();
}

bool SerializationUtils::ReadAndTruncateMetricsFromFile(
    const std::string& filename,
    std::vector<MetricSample>* metrics,
    size_t sample_batch_max_length) {
  struct stat stat_buf = {};
  int result;
  off_t total_length = 0;

  result = stat(filename.c_str(), &stat_buf);
  if (result < 0) {
    if (errno != ENOENT)
      PLOG(ERROR) << filename << ": bad metrics file stat";

    // Nothing to collect---try later.
    return true;
  }
  if (stat_buf.st_size == 0) {
    // Also nothing to collect.
    return true;
  }
  base::ScopedFD fd(open(filename.c_str(), O_RDWR | O_CLOEXEC));
  if (fd.get() < 0) {
    PLOG(ERROR) << filename << ": cannot open";
    return true;
  }
  result = flock(fd.get(), LOCK_EX);
  if (result < 0) {
    PLOG(ERROR) << filename << ": cannot lock";
    return true;
  }

  // Skip consecutive zeros at the beginning of the file, which may have been
  // left by an earlier partial read if the file was too large.  Normally there
  // are none, but following long stretches of time without connectivity, there
  // could be a large number.  (They are optimized away by fallocate().)
  SeekToSamples(fd.get());

  // Try to process all messages in the log, but stop when
  // kMaxMetricsBytesCount has been exceeded.  If all messages are read and
  // processed, or an error occurs, truncate the file to zero size.  If the max
  // byte count is exceeded, stop processing samples, but set up the file to
  // continue at the next call.  There are races on daemon crash or system
  // crash: resolve them by allowing the loss of samples.
  bool skip_truncation = false;
  while (true) {
    std::string message;
    size_t bytes_used = 0;

    if (!ReadMessage(fd.get(), &message, &bytes_used))
      break;

    MetricSample sample = ParseSample(message);
    if (sample.IsValid())
      metrics->push_back(std::move(sample));

    total_length += bytes_used;
    if (total_length > sample_batch_max_length) {
      // Set up the file to continue processing.  Avoid final truncation,
      // unless there were errors.
      skip_truncation = RemovePreviousSamples(fd.get());
      break;
    }
  }

  if (!skip_truncation) {
    result = ftruncate(fd.get(), 0);
    if (result < 0)
      PLOG(ERROR) << "truncate metrics log";
  }

  result = flock(fd.get(), LOCK_UN);
  if (result < 0)
    PLOG(ERROR) << "unlock metrics log";

  return total_length <= sample_batch_max_length;
}

bool SerializationUtils::WriteMetricsToFile(
    const std::vector<MetricSample>& samples, const std::string& filename) {
  std::string output;
  for (const auto& sample : samples) {
    if (!sample.IsValid()) {
      return false;
    }
    std::string msg = sample.ToString();
    int32_t size = msg.length() + sizeof(int32_t);
    if (size > kMessageMaxLength) {
      LOG(ERROR) << "cannot write message: too long, length = " << size;
      return false;
    }
    output.append(reinterpret_cast<char*>(&size), sizeof(size));
    output.append(msg);
  }

  base::ScopedFD file_descriptor(open(filename.c_str(),
                                      O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC,
                                      READ_WRITE_ALL_FILE_FLAGS));

  if (file_descriptor.get() < 0) {
    PLOG(ERROR) << filename << ": cannot open";
    return false;
  }

  // Grab a lock to avoid chrome truncating the file underneath us. Keep the
  // file locked as briefly as possible. Freeing file_descriptor will close the
  // file and remove the lock IFF the process was not forked in the meantime,
  // which will leave the flock hanging and deadlock the reporting until the
  // forked process is killed otherwise. Thus we have to explicitly unlock the
  // file below.
  if (HANDLE_EINTR(flock(file_descriptor.get(), LOCK_EX)) < 0) {
    PLOG(ERROR) << filename << ": cannot lock";
    return false;
  }

  if (!base::WriteFileDescriptor(file_descriptor.get(), output)) {
    PLOG(ERROR) << "error writing output";
    std::ignore = flock(file_descriptor.get(), LOCK_UN);
    return false;
  }

  std::ignore = flock(file_descriptor.get(), LOCK_UN);

  return true;
}

}  // namespace metrics
