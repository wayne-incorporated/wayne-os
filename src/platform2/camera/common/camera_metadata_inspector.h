/*
 * Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_CAMERA_METADATA_INSPECTOR_H_
#define CAMERA_COMMON_CAMERA_METADATA_INSPECTOR_H_

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <base/files/file.h>
#include <base/sequence_checker.h>
#include <base/threading/thread.h>
#include <base/time/time.h>
#include <camera/camera_metadata.h>
#include <cros-camera/export.h>
#include <hardware/camera3.h>
#include <re2/re2.h>

namespace cros {

struct DiffData {
  std::string key;
  std::string old_val;
  std::string new_val;

  std::string FormatKey(int width);
  std::string FormatValue(int width);
};

class CROS_CAMERA_EXPORT CameraMetadataInspector {
 public:
  // Holds the string representation of the entries of a metadata.
  using DataMap = std::map<std::string, std::string>;

  // The factory function that creates a CameraMetadataInspector from the
  // command line switches of the current process:
  // --metadata_inspector_output=<path/to/output/file>
  // --metadata_inspector_allowlist=<regex_filter> (optional)
  // --metadata_inspector_denylist=<regex_filter> (optional)
  // --metadata_inspector_position=<comma_separated_numbers> (optional)
  // See the comments of |output_file_|, |allowlist_|, |denylist_| and
  // |inspect_position_| below for more details.  Returns nullptr on error.
  static std::unique_ptr<CameraMetadataInspector> Create(
      int partial_result_count);

  // Disallow copy constructor and assign operator.
  CameraMetadataInspector(const CameraMetadataInspector&) = delete;
  CameraMetadataInspector& operator=(const CameraMetadataInspector&) = delete;

  // Inspect a capture request and dump the difference from the previous one
  // in |output_file_|.
  void InspectRequest(const camera3_capture_request_t* request,
                      size_t position);

  // Inspect a capture result and dump the difference from the previous one
  // in |output_file_|.  Partial results would be aggregated automatically, but
  // the caller needs to guarantee it's called on the same sequence.
  void InspectResult(const camera3_capture_result_t* result, size_t position);

  // Whether a position should be inspected (see |inspect_positions_| comments
  // for details).
  bool IsPositionInspected(size_t position) const;

 private:
  enum class Kind { kRequest, kResult, kNumberOfKinds };

  // The private constructor used in the factory function.
  CameraMetadataInspector(int partial_result_count,
                          base::File output_file,
                          std::unique_ptr<RE2> allowlist,
                          std::unique_ptr<RE2> denylist,
                          std::set<size_t> inspect_positions,
                          std::unique_ptr<base::Thread> thread);

  // Writes and flushes |msg| to |output_file_|.
  void Write(base::StringPiece msg);

  // Returns true if |key| should be ignored according to |allowlist_| and
  // |denylist_|.
  bool ShouldIgnoreKey(const std::string& key);

  // Converts a metadata into the stringified DataMap.
  DataMap MapFromMetadata(const camera_metadata_t* metadata);

  // Compares two maps and returns a list of differences.
  std::vector<DiffData> Compare(const DataMap& old_map, const DataMap& new_map);

  // Compares the metadata with the previous one, and writes the formatted
  // difference into |output_file_|.
  void InspectOnThread(size_t position,
                       Kind kind,
                       const std::string& kind_tag,
                       int color,
                       base::Time time,
                       int frame_number,
                       camera_metadata_t* metadata);

  // How many sub-components a result will be composed of at most.
  int partial_result_count_;

  // The output file for the inspector.  Could be a special file such as
  // /dev/stdout.
  base::File output_file_;

  // If specified, only metadata with keys matching the regular expression
  // filter would be logged.
  std::unique_ptr<RE2> allowlist_;

  // If specified, only metadata with keys not matching the regular expression
  // filter would be logged.  Denylist could be used with allowlist, and only
  // keys (in allowlist && not in the denylist) would be logged.
  std::unique_ptr<RE2> denylist_;

  // Specifies the positions to inspect metadata between the client, stream
  // manipulators (SM), and the HAL.  If there are N SMs, the values mean:
  //   0 - between the client and the 1st SM;
  //   i - between the i-th SM and the (i+1)-th SM (0 < i < N);
  //   N - between the last SM and the HAL.
  // If not specified, every position is inspected by default.
  std::set<size_t> inspect_positions_;

  // The latest DataMap for each kind of metadata for each position.
  std::map<size_t,
           std::array<DataMap, static_cast<size_t>(Kind::kNumberOfKinds)>>
      latest_map_;

  // The aggregated capture result for all current partial results.
  base::Lock pending_result_lock_;
  android::CameraMetadata pending_result_ GUARDED_BY(pending_result_lock_);

  // The real work such as InspectOnThread() is running on |thread_|, so the
  // capture flow won't be blocked by InspectRequest() and InspectResult().
  std::unique_ptr<base::Thread> thread_;
};

}  // namespace cros

#endif  // CAMERA_COMMON_CAMERA_METADATA_INSPECTOR_H_
