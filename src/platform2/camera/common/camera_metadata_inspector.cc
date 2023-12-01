/*
 * Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common/camera_metadata_inspector.h"

#include <algorithm>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/command_line.h>
#include <base/containers/contains.h>
#include <base/functional/bind.h>
#include <base/memory/ptr_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <system/camera_metadata.h>

#include "cros-camera/common.h"

namespace {

const char kSeparator[] = " | ";
const int kSeparatorWidth = 3;

const char kArrow[] = " => ";
const int kArrowWidth = 4;

const char kEllipsis[] = "...";
const int kEllipsisWidth = 3;

// The ASCII escape color code for request metadata. It's green.
const int kRequestColor = 32;

// The ASCII escape color code for result metadata. It's yellow.
const int kResultColor = 33;

// The max column width for an output line.
const int kMaxLineWidth = 100;

// The format is HH:MM:ss.SSS, such as 23:59:59.999.
const int kTimestampWidth = 12;

// The inspect position number, expected smaller than 10.
const int kPositionWidth = 1;

// The format is (Req|Res)(frame % 1000), such as Req087.
const int kIdentifierWidth = 6;

// The length of the longest request/result key name (lensShadingCorrectionMap).
const int kMaxKeyWidth = 24;

// The remaining line width is the space for value.
const int kMaxValueWidth =
    kMaxLineWidth -
    (kTimestampWidth + kSeparatorWidth + kPositionWidth + kSeparatorWidth +
     kIdentifierWidth + kSeparatorWidth + kMaxKeyWidth + kSeparatorWidth);

// Formats the key of |entry| as {tag_section}.{tag_name}.  Returns empty string
// on error.
std::string FormatEntryKey(const camera_metadata_ro_entry_t& entry) {
  const char* tag_section = get_camera_metadata_section_name(entry.tag);
  if (tag_section == nullptr) {
    LOGF(ERROR) << "Failed to get section name of " << entry.tag;
    return "";
  }

  const char* tag_name = get_camera_metadata_tag_name(entry.tag);
  if (tag_name == nullptr) {
    LOGF(ERROR) << "Failed to get tag name of " << entry.tag;
    return "";
  }

  return base::StringPrintf("%s.%s", tag_section, tag_name);
}

// Formats the value at index |idx| of |entry| according to its type.  Uses the
// name of enum if possible, and falls back to numeric value if not found.
// Returns empty string on error.
std::string FormatEntryValueAt(const camera_metadata_ro_entry_t& entry,
                               size_t idx) {
  switch (entry.type) {
    case TYPE_BYTE: {
      uint8_t val = entry.data.u8[idx];
      char buf[64];
      if (camera_metadata_enum_snprint(entry.tag, val, buf, sizeof(buf)) == 0) {
        return buf;
      }
      return std::to_string(val);
    }
    case TYPE_INT32: {
      int32_t val = entry.data.i32[idx];
      char buf[64];
      if (camera_metadata_enum_snprint(entry.tag, val, buf, sizeof(buf)) == 0) {
        return buf;
      }
      return std::to_string(val);
    }
    case TYPE_INT64:
      return std::to_string(entry.data.i64[idx]);
    case TYPE_FLOAT:
      return base::StringPrintf("%.2g", entry.data.f[idx]);
    case TYPE_DOUBLE:
      return base::StringPrintf("%.2g", entry.data.d[idx]);
    case TYPE_RATIONAL: {
      camera_metadata_rational_t val = entry.data.r[idx];
      return base::StringPrintf("%d/%d", val.numerator, val.denominator);
    }
    default:
      LOGF(ERROR) << "Unknown entry type " << entry.type;
      return "";
  }
}

}  // namespace

namespace cros {

std::string DiffData::FormatKey(int width) {
  DCHECK_GE(width, kEllipsisWidth);
  if (width >= key.size()) {
    return key;
  }
  auto dot_pos = key.find('.', key.size() - width - 1);
  if (dot_pos != std::string::npos) {
    return key.substr(dot_pos + 1);
  } else {
    return kEllipsis + key.substr(key.size() - (width - kEllipsisWidth));
  }
}

std::string DiffData::FormatValue(int width) {
  DCHECK_GE(width, kEllipsisWidth + kArrowWidth + kEllipsisWidth);

  int old_width = old_val.size();
  int new_width = new_val.size();
  int limit = width - kArrowWidth;

  if (old_width + new_width > limit) {
    if (std::min(old_width, new_width) * 2 <= limit) {
      // It can fit into |limit| by only trimming the longer one.
      if (old_width > new_width) {
        old_width = limit - new_width;
      } else {
        new_width = limit - old_width;
      }
    } else {
      // Distribute the width evenly if we need to trim both.
      old_width = limit / 2;
      new_width = limit - old_width;
    }
  }

  auto Format = [&](const std::string& s, int w) {
    if (s.size() <= w) {
      return s;
    }
    return s.substr(0, w - kEllipsisWidth) + kEllipsis;
  };

  return Format(old_val, old_width) + kArrow + Format(new_val, new_width);
}

// static
std::unique_ptr<CameraMetadataInspector> CameraMetadataInspector::Create(
    int partial_result_count) {
  auto cl = base::CommandLine::ForCurrentProcess();
  base::FilePath output_path =
      cl->GetSwitchValuePath("metadata_inspector_output");
  if (output_path.empty()) {
    return nullptr;
  }

  base::File output_file = {
      output_path, base::File::FLAG_OPEN_ALWAYS | base::File::FLAG_APPEND};
  if (!output_file.IsValid()) {
    LOGF(ERROR) << "Failed to open output file " << output_path.value();
    return nullptr;
  }

  auto GetRE2FromSwitch = [&](base::StringPiece name) -> std::unique_ptr<RE2> {
    std::string value = cl->GetSwitchValueASCII(name);
    if (value.empty()) {
      return nullptr;
    }
    RE2::Options option;
    option.set_case_sensitive(false);
    return std::make_unique<RE2>(value, option);
  };

  std::unique_ptr<RE2> allowlist =
      GetRE2FromSwitch("metadata_inspector_allowlist");
  if (allowlist && !allowlist->ok()) {
    LOGF(ERROR) << "Failed to build regex for allowlist: "
                << allowlist->error();
    return nullptr;
  }

  std::unique_ptr<RE2> denylist =
      GetRE2FromSwitch("metadata_inspector_denylist");
  if (denylist && !denylist->ok()) {
    LOGF(ERROR) << "Failed to build regex for denylist: " << denylist->error();
    return nullptr;
  }

  std::vector<std::string> position_strs =
      base::SplitString(cl->GetSwitchValueASCII("metadata_inspector_positions"),
                        ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  std::set<size_t> positions;
  for (std::string& s : position_strs) {
    size_t p;
    if (!base::StringToSizeT(s, &p)) {
      LOGF(ERROR) << "Failed to parse inspect positions";
      return nullptr;
    }
    positions.insert(p);
  }

  auto thread = std::make_unique<base::Thread>("CameraMetadataInspectorThread");
  if (!thread->Start()) {
    LOGF(ERROR) << "Failed to start thread";
    return nullptr;
  }

  return base::WrapUnique(new CameraMetadataInspector(
      partial_result_count, std::move(output_file), std::move(allowlist),
      std::move(denylist), std::move(positions), std::move(thread)));
}

CameraMetadataInspector::CameraMetadataInspector(
    int partial_result_count,
    base::File output_file,
    std::unique_ptr<RE2> allowlist,
    std::unique_ptr<RE2> denylist,
    std::set<size_t> inspect_positions,
    std::unique_ptr<base::Thread> thread)
    : partial_result_count_(partial_result_count),
      output_file_(std::move(output_file)),
      allowlist_(std::move(allowlist)),
      denylist_(std::move(denylist)),
      inspect_positions_(std::move(inspect_positions)),
      thread_(std::move(thread)) {}

void CameraMetadataInspector::Write(base::StringPiece msg) {
  output_file_.WriteAtCurrentPos(msg.data(), msg.size());
  output_file_.Flush();
}

bool CameraMetadataInspector::ShouldIgnoreKey(const std::string& key) {
  if (key.empty()) {
    return true;
  }
  if (allowlist_ && !RE2::PartialMatch(key, *allowlist_)) {
    return true;
  }
  if (denylist_ && RE2::PartialMatch(key, *denylist_)) {
    return true;
  }
  return false;
}

CameraMetadataInspector::DataMap CameraMetadataInspector::MapFromMetadata(
    const camera_metadata_t* metadata) {
  CameraMetadataInspector::DataMap map;
  size_t n = get_camera_metadata_entry_count(metadata);
  for (size_t i = 0; i < n; i++) {
    camera_metadata_ro_entry_t entry;
    int ret = get_camera_metadata_ro_entry(metadata, i, &entry);
    if (ret != 0) {
      LOGF(ERROR) << "Failed to get the metadata entry at " << i;
      continue;
    }
    std::string key = FormatEntryKey(entry);
    if (ShouldIgnoreKey(key)) {
      continue;
    }
    std::vector<std::string> values;
    values.reserve(entry.count);
    for (size_t j = 0; j < entry.count; j++) {
      values.push_back(FormatEntryValueAt(entry, j));
    }
    map[key] = base::JoinString(values, " ");
  }
  return map;
}

std::vector<DiffData> CameraMetadataInspector::Compare(const DataMap& old_map,
                                                       const DataMap& new_map) {
  std::vector<std::string> keys;
  for (auto& map : {old_map, new_map}) {
    for (auto& elem : map) {
      keys.push_back(elem.first);
    }
  }
  std::sort(keys.begin(), keys.end());
  keys.erase(std::unique(keys.begin(), keys.end()), keys.end());

  auto GetValue = [&](const DataMap& map, const std::string& key) {
    auto it = map.find(key);
    return it != map.end() ? it->second : "nil";
  };

  std::vector<DiffData> diffs;
  for (const auto& key : keys) {
    std::string old_val = GetValue(old_map, key);
    std::string new_val = GetValue(new_map, key);
    if (old_val != new_val) {
      DiffData diff = {key, old_val, new_val};
      diffs.push_back(diff);
    }
  }

  return diffs;
}

void CameraMetadataInspector::InspectOnThread(size_t position,
                                              Kind kind,
                                              const std::string& kind_name,
                                              int color,
                                              base::Time time,
                                              int frame_number,
                                              camera_metadata_t* metadata) {
  DCHECK(thread_->task_runner()->BelongsToCurrentThread());
  auto map = MapFromMetadata(metadata);
  base::Time::Exploded exploded;
  time.UTCExplode(&exploded);
  auto diffs = Compare(latest_map_[position][static_cast<size_t>(kind)], map);
  std::stringstream ss;
  for (auto diff : diffs) {
    ss << "\e[" << color << "m";
    ss << base::StringPrintf("%02d:%02d:%02d.%03d", exploded.hour,
                             exploded.minute, exploded.second,
                             exploded.millisecond);
    ss << kSeparator;
    ss << position;
    ss << kSeparator;
    ss << base::StringPrintf("%s%03d", kind_name.c_str(), frame_number % 1000);
    ss << kSeparator;
    ss << base::StringPrintf("%*s", kMaxKeyWidth,
                             diff.FormatKey(kMaxKeyWidth).c_str());
    ss << kSeparator;
    ss << diff.FormatValue(kMaxValueWidth);
    ss << "\e[0m\n";
  }
  Write(ss.str());
  latest_map_[position][static_cast<size_t>(kind)] = map;
  free_camera_metadata(metadata);
}

void CameraMetadataInspector::InspectRequest(
    const camera3_capture_request_t* request, size_t position) {
  if (request->settings == nullptr) {
    return;
  }
  thread_->task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&CameraMetadataInspector::InspectOnThread,
                     base::Unretained(this), position, Kind::kRequest, "Req",
                     kRequestColor, base::Time::Now(), request->frame_number,
                     clone_camera_metadata(request->settings)));
}

void CameraMetadataInspector::InspectResult(
    const camera3_capture_result_t* result, size_t position) {
  if (result->result == nullptr) {
    return;
  }
  {
    base::AutoLock l(pending_result_lock_);
    pending_result_.append(result->result);
  }
  if (result->partial_result != partial_result_count_) {
    return;
  }
  thread_->task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&CameraMetadataInspector::InspectOnThread,
                     base::Unretained(this), position, Kind::kResult, "Res",
                     kResultColor, base::Time::Now(), result->frame_number,
                     pending_result_.release()));
}

bool CameraMetadataInspector::IsPositionInspected(size_t position) const {
  return inspect_positions_.empty() ||
         base::Contains(inspect_positions_, position);
}

}  // namespace cros
