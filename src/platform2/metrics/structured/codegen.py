# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Objects for describing template code to be generated from structured.xml."""

import hashlib
import os
import re
import struct


class Util:
    """Helpers for generating C++."""

    @staticmethod
    def sanitize_name(name):
        return re.sub("[^0-9a-zA-Z_]", "_", name)

    @staticmethod
    def camel_to_snake(name):
        pat = "((?<=[a-z0-9])[A-Z]|(?!^)[A-Z](?=[a-z]))"
        return re.sub(pat, r"_\1", name).lower()

    @staticmethod
    def hash_name(name):
        # This must match the hash function in chromium's
        # //base/metrics/metric_hashes.cc. >Q means 8 bytes, big endian.
        name = name.encode("utf-8")
        md5 = hashlib.md5(name)
        return struct.unpack(">Q", md5.digest()[:8])[0]

    @staticmethod
    def event_name_hash(project_name, event_name):
        """Make the name hash for an event.

        This gets uploaded in the StructuredEventProto.event_name_hash field. It
        is the sole means of recording which event from structured.xml a
        StructuredEventProto instance represents.

        To avoid naming collisions, it must contain three pieces of information:
         - the name of the event itself
         - the name of the event's project, to avoid collisions with events of
           the same name in other projects
         - an identifier that this comes from chromeos, to avoid collisions with
           events and projects of the same name defined in chromium's
           structured.xml

        This must use sanitized names for the project and event.
        """
        event_name = Util.sanitize_name(event_name)
        project_name = Util.sanitize_name(project_name)
        return Util.hash_name(f"cros::{project_name}::{event_name}")


class FileInfo:
    """Codegen-related info about a file."""

    def __init__(self, dirname, basename):
        self.dirname = dirname
        self.basename = basename
        self.filepath = os.path.join(dirname, basename)

        # This takes the last three components of the filepath for use in the
        # header guard, ie. METRICS_STRUCTURED_STRUCTURED_EVENTS_H_
        relative_path = os.sep.join(self.filepath.split(os.sep)[-3:])
        self.guard_path = Util.sanitize_name(relative_path).upper()


class ProjectInfo:
    """Codegen-related info about a project."""

    def __init__(self, project):
        self.name = Util.sanitize_name(project.name)
        self.namespace = Util.camel_to_snake(self.name)
        self.name_hash = Util.hash_name(self.name)

        # Set ID Type.
        if project.id == "uma":
            self.id_type = "kUmaId"
        elif project.id == "per-project":
            self.id_type = "kProjectId"
        elif project.id == "none":
            self.id_type = "kUnidentified"

        # Set event type. This is inferred by checking all metrics within the
        # project. If any of a project's metrics is a raw string, then its
        # events are considered raw string events, even if they also contain
        # non-strings.
        self.event_type = "REGULAR"
        for event in project.events:
            for metric in event.metrics:
                if metric.type == "raw-string":
                    self.event_type = "RAW_STRING"
                    break


class EventInfo:
    """Codegen-related info about an event."""

    def __init__(self, event, project_info):
        self.name = Util.sanitize_name(event.name)
        self.name_hash = Util.event_name_hash(project_info.name, self.name)


class MetricInfo:
    """Codegen-related info about a metric."""

    def __init__(self, metric):
        self.name = Util.sanitize_name(metric.name)
        self.hash = Util.hash_name(metric.name)

        if metric.type == "hmac-string":
            self.setter_type = "std::string&"
            self.setter = "AddHmacMetric"
            self.getter_type = "std::string"
            self.getter = "GetHmacMetricForTest"
        elif metric.type == "int":
            self.setter_type = "int64_t"
            self.setter = "AddIntMetric"
            self.getter_type = "int64_t"
            self.getter = "GetIntMetricForTest"
        elif metric.type == "raw-string":
            self.setter_type = "std::string&"
            self.setter = "AddRawStringMetric"
            self.getter_type = "std::string"
            self.getter = "GetRawStringMetricForTest"
        elif metric.type == "double":
            self.setter_type = "double"
            self.setter = "AddDoubleMetric"
            self.getter_type = "double"
            self.getter = "GetDoubleMetricForTest"
        elif metric.type == "int-array":
            self.setter_type = "std::vector<int64_t>&"
            self.max_size = metric.max_size
            self.setter = "AddIntArrayMetric"
            self.getter_type = "std::vector<int64_t>"
            self.getter = "GetIntArrayMetricForTest"
        else:
            raise ValueError("Invalid metric type.")


class Template:
    """Template for producing code from structured.xml."""

    def __init__(
        self,
        model,
        dirname,
        basename,
        file_template,
        project_template,
        event_template,
        metric_template,
        array_template,
        is_header,
    ):
        self.model = model
        self.dirname = dirname
        self.basename = basename
        self.file_template = file_template
        self.project_template = project_template
        self.event_template = event_template
        self.metric_template = metric_template
        self.array_template = array_template
        self.is_header = is_header

    def write_file(self):
        file_info = FileInfo(self.dirname, self.basename)
        with open(file_info.filepath, "w", encoding="utf-8") as f:
            f.write(self._stamp_file(file_info))

    def _stamp_file(self, file_info):
        project_code = "".join(
            self._stamp_project(file_info, p) for p in self.model.projects
        )

        project_names = sorted([p.name for p in self.model.projects])
        project_hashes_list = [
            f"UINT64_C({Util.hash_name(n)})" for n in project_names
        ]
        project_hashes_literal = "{" + ", ".join(project_hashes_list) + "}"

        return self.file_template.format(
            file=file_info,
            project_code=project_code,
            project_hashes=project_hashes_literal,
        )

    def _stamp_project(self, file_info, project):
        project_info = ProjectInfo(project)
        event_code = "".join(
            self._stamp_event(file_info, project_info, event)
            for event in project.events
        )
        return self.project_template.format(
            file=file_info, project=project_info, event_code=event_code
        )

    def _stamp_event(self, file_info, project_info, event):
        event_info = EventInfo(event, project_info)
        if self.is_header:
            metric_code = "".join(
                self._stamp_metric(file_info, event_info, metric)
                for metric in event.metrics
            )
            metric_code += "".join(
                self._stamp_array_metric(file_info, event_info, metric)
                for metric in event.metrics
                if metric.is_array()
            )
        else:
            metric_code = "".join(
                self._stamp_metric(file_info, event_info, metric)
                for metric in event.metrics
                if not metric.is_array()
            )
            metric_code += "".join(
                self._stamp_array_metric(file_info, event_info, metric)
                for metric in event.metrics
                if metric.is_array()
            )

        return self.event_template.format(
            file=file_info,
            project=project_info,
            event=event_info,
            metric_code=metric_code,
        )

    def _stamp_metric(self, file_info, event_info, metric):
        return self.metric_template.format(
            file=file_info, event=event_info, metric=MetricInfo(metric)
        )

    def _stamp_array_metric(self, file_info, event_info, metric):
        return self.array_template.format(
            file=file_info, event=event_info, metric=MetricInfo(metric)
        )
