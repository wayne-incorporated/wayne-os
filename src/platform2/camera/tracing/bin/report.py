# -*- coding: utf-8 -*-

# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Implementation of the `report` subcommand."""

import logging
import os
import re
import subprocess
from typing import Optional

# pylint: disable=import-error
from cros_camera_tracing import utils


class TraceProcessorEnv:
    """Runtime environment for Perfetto trace processor."""

    # Local directory hosting the camera metrics definitions.
    METRICS_DIR = "metrics"

    # Path to the built-in trace processors.
    TRACE_PROCESSOR_IN_SDK = "/usr/bin/trace_processor_shell"
    TRACE_PROCESSOR_ON_DUT = "/usr/local/bin/trace_processor_shell"

    def __init__(self, trace_processor_path: Optional[str]):
        self.trace_processor_path = None
        if trace_processor_path:
            self.trace_processor_path = trace_processor_path
        elif utils.is_inside_chroot():
            self.trace_processor_path = TraceProcessorEnv.TRACE_PROCESSOR_IN_SDK
        elif utils.is_on_dut():
            self.trace_processor_path = TraceProcessorEnv.TRACE_PROCESSOR_ON_DUT
        if self.trace_processor_path is None or not os.path.exists(
            self.trace_processor_path
        ):
            raise RuntimeError("Unable to locate trace processor")

        self.metrics_dir = os.path.realpath(
            os.path.join(os.path.dirname(__file__), "..", self.METRICS_DIR)
        )

    def run(self, args):
        """Runs the trace processor."""

        cmd = [
            self.trace_processor_path,
            "--metric-extension",
            "%s@/" % self.metrics_dir,
            "--dev",
            "--run-metrics",
            args.metrics,
            args.input_file,
        ]
        if args.interactive:
            cmd += ["--interactive"]

        output = subprocess.run(
            cmd,
            check=True,
            encoding="utf-8",
            stderr=None if args.interactive else subprocess.DEVNULL,
            stdout=None if args.interactive else subprocess.PIPE,
        )
        if not args.interactive:
            logging.info("Computed metrics:\n\n%s", output.stdout)

    def list_metrics(self):
        """Lists the camera metrics defined in the camera metrics dir."""

        # Metric has proto definition like:
        #   extend TraceMetrics {
        #     optional <Type> <Name> = <Id>;
        #   }
        metric_def_re = re.compile(
            r"extend\s+TraceMetrics\s*{"
            r"\s*optional\s+(?P<type>\w+)\s+(?P<name>\w+)\s*=\s*(?P<id>\d+);"
            r"\s*}"
        )
        all_metrics = {}
        protos_dir = os.path.join(self.metrics_dir, "protos")
        for proto_file in os.listdir(protos_dir):
            with open(os.path.join(protos_dir, proto_file)) as f:
                m = metric_def_re.search(f.read())
                if m is None:
                    continue
                mid = int(m.group("id"))
                all_metrics[mid] = m.group("name")

        logging.info(
            "List of camera metrics:\n%s",
            "\n".join(
                [
                    "%5d: %s" % (k, all_metrics[k])
                    for k in sorted(all_metrics.keys())
                ]
            ),
        )


def set_up_subcommand_parser(subparsers):
    """Sets up subcommand parser for the `report` subcommand."""

    report_parser = subparsers.add_parser(
        "report",
        description=(
            "Report parsed info from a recorded trace, such as metrics. Works "
            "only inside the CrOS SDK chroot for the time being due to "
            "dependency on the Tast trace processor binary"
        ),
        help="Report parsed info from recorded trace",
    )
    report_parser.add_argument(
        "-i",
        "--input_file",
        type=str,
        default="/tmp/perfetto-trace",
        help="The input recorded trace file to parse (default=%(default)s)",
    )
    report_parser.add_argument(
        "--trace_processor_path",
        type=str,
        default=None,
        help=(
            "Path to the Perfetto trace_processor binary; if not specified, "
            "will use the built-in trace processor inside the SDK or on the "
            "DUT (default=%(default)s)"
        ),
    )
    report_parser.add_argument(
        "--metrics",
        type=str,
        default=None,
        help="The list of comma separated metrics to compute",
    )
    report_parser.add_argument(
        "--list_metrics",
        action="store_true",
        default=False,
        help="List the available metrics that can be computed",
    )
    report_parser.add_argument(
        "--interactive",
        action="store_true",
        default=False,
        help=(
            "Enters the interactive mode of the trace processor; used mainly "
            "for development and debugging metrics SQL definitions"
        ),
    )


def execute_subcommand(args):
    """Executes the `report` subcommand."""

    env = TraceProcessorEnv(args.trace_processor_path)

    if args.list_metrics:
        env.list_metrics()

    if args.metrics:
        logging.info("Using trace processor: %s", env.trace_processor_path)
        env.run(args)
