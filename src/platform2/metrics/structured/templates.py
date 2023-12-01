# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Templates for generating event classes for structured metrics."""


HEADER_FILE_TEMPLATE = """\
// Generated from gen_events.py. DO NOT EDIT!
// source: structured.xml

#ifndef {file.guard_path}
#define {file.guard_path}

#include <cstdint>
#include <string>

#include <brillo/brillo_export.h>

#include "metrics/structured/event_base.h"

namespace metrics {{
namespace structured {{
namespace events {{

constexpr uint64_t kProjectNameHashes[] = {project_hashes};

{project_code}

}}  // namespace events
}}  // namespace structured
}}  // namespace metrics

#endif  // {file.guard_path}\
"""


HEADER_PROJECT_TEMPLATE = """\
namespace {project.namespace} {{

{event_code}\
}}  // namespace {project.namespace}

"""


HEADER_EVENT_TEMPLATE = """\
class BRILLO_EXPORT {event.name} final : public ::metrics::structured::EventBase {{
 public:
  {event.name}();
  ~{event.name}() override;

  static constexpr uint64_t kEventNameHash = UINT64_C({event.name_hash});
  static constexpr uint64_t kProjectNameHash = UINT64_C({project.name_hash});
  static constexpr IdType kIdType = IdType::{project.id_type};
  static constexpr StructuredEventProto_EventType kEventType =
    StructuredEventProto_EventType_{project.event_type};

{metric_code}\
}};

"""


HEADER_METRIC_TEMPLATE = """\
  static constexpr uint64_t k{metric.name}NameHash = UINT64_C({metric.hash});
  {event.name}& Set{metric.name}(const {metric.setter_type} value);
  {metric.getter_type} Get{metric.name}ForTest() const;

"""

HEADER_ARRAY_LENGTH_TEMPLATE = """\
  static constexpr size_t Get{metric.name}MaxLength() {{ return {metric.max_size}; }}
"""


IMPL_FILE_TEMPLATE = """\
// Generated from gen_events.py. DO NOT EDIT!
// source: structured.xml

#include "structured_events.h"

namespace metrics {{
namespace structured {{
namespace events {{
{project_code}
}}  // namespace events
}}  // namespace structured
}}  // namespace metrics\
"""


IMPL_PROJECT_TEMPLATE = """\
namespace {project.namespace} {{

{event_code}\
}}  // namespace {project.namespace}

"""


IMPL_EVENT_TEMPLATE = """\
{event.name}::{event.name}() :
  ::metrics::structured::EventBase(kEventNameHash, kProjectNameHash, kIdType, kEventType) {{}}
{event.name}::~{event.name}() = default;
{metric_code}\
"""


IMPL_METRIC_TEMPLATE = """\
{event.name}& {event.name}::Set{metric.name}(const {metric.setter_type} value) {{
  {metric.setter}(k{metric.name}NameHash, value);
  return *this;
}}

{metric.getter_type} {event.name}::Get{metric.name}ForTest() const {{
  return {metric.getter}(k{metric.name}NameHash);
}}

"""

IMPL_ARRAY_METRIC_TEMPLATE = """\
{event.name}& {event.name}::Set{metric.name}(const {metric.setter_type} value) {{
  {metric.setter}(k{metric.name}NameHash, value, {event.name}::Get{metric.name}MaxLength());
  return *this;
}}

{metric.getter_type} {event.name}::Get{metric.name}ForTest() const {{
  return {metric.getter}(k{metric.name}NameHash);
}}

"""
