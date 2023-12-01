# -*- coding: utf-8 -*-

# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Implementation of the `record` subcommand."""

import logging
import signal
import subprocess
import tempfile
import time

# pylint: disable=import-error
from cros_camera_tracing import utils


def generate_trace_config(args) -> str:
    """Generates the trace config."""

    fill_policy = "RING_BUFFER"
    if args.duration_sec is not None:
        fill_policy = "DISCARD"

    # Prepare track_event config strings. The spaces are indents for pretty
    # output.
    INDENT = " " * 12
    enabled_categories = args.enabled_categories.split(",")
    if args.with_gpu:
        enabled_categories += ["mesa.*"]
    enabled_categories_str = "\n".join(
        INDENT + f'enabled_categories: "{c}"' for c in enabled_categories
    )

    disabled_categories_str = "\n".join(
        INDENT + f'disabled_categories: "{c}"'
        for c in args.disabled_categories.split(",")
    )

    enabled_tags_str = "\n".join(
        INDENT + f'enabled_tags: "{c}"' for c in args.enabled_tags.split(",")
    )

    trace_config = f"""
# Buffer 0
buffers: {{
    size_kb: {args.buffer_size_kb}
    fill_policy: {fill_policy}
}}

# Buffer 1
buffers: {{
    size_kb: 4096
    fill_policy: DISCARD
}}

data_sources: {{
    config {{
        name: "track_event"
        target_buffer: 0
        track_event_config {{
{enabled_categories_str}
{disabled_categories_str}
{enabled_tags_str}
        }}
    }}
}}

data_sources: {{
    config {{
        name: "org.chromium.trace_event"
        target_buffer: 0
        chrome_config {{
            trace_config: "{{\\"record_mode\\":\\"record-until-full\\",\\"included_categories\\":[\\"camera\\"],\\"memory_dump_config\\": {{}}}}"
        }}
    }}
}}

# Event-driven recording of frequency and idle state changes.

data_sources: {{
    config {{
        name: "linux.ftrace"
        target_buffer: 0
        ftrace_config {{
            buffer_size_kb: 16384
            drain_period_ms: 250
            ftrace_events: "ftrace/print"
            ftrace_events: "power/cpu_frequency"
            ftrace_events: "power/cpu_idle"
            ftrace_events: "power/suspend_resume"
            #ftrace_events: "sched/sched_switch"
            #ftrace_events: "sched/sched_process_exit"
            #ftrace_events: "sched/sched_process_free"
            #ftrace_events: "task/task_newtask"
            #ftrace_events: "task/task_rename"
        }}
    }}
}}

# Polling the current cpu frequency.

data_sources: {{
    config {{
        name: "linux.sys_stats"
        target_buffer: 0
        sys_stats_config {{
            cpufreq_period_ms: 500
            meminfo_period_ms: 1000
            meminfo_counters: MEMINFO_MEM_TOTAL
            meminfo_counters: MEMINFO_MEM_FREE
            meminfo_counters: MEMINFO_MEM_AVAILABLE
            vmstat_period_ms: 1000
            vmstat_counters: VMSTAT_NR_FREE_PAGES
            vmstat_counters: VMSTAT_NR_ALLOC_BATCH
            vmstat_counters: VMSTAT_NR_INACTIVE_ANON
            vmstat_counters: VMSTAT_NR_ACTIVE_ANON
            stat_period_ms: 2500
            stat_counters: STAT_CPU_TIMES
            stat_counters: STAT_FORK_COUNT
        }}
    }}
}}

# Reporting the list of available frequency for each CPU.

data_sources {{
    config {{
        name: "linux.system_info"
        target_buffer: 1
    }}
}}

# This is to get full process name and thread<>process relationships.

data_sources: {{
    config {{
        name: "linux.process_stats"
        target_buffer: 1
        process_stats_config {{
            scan_all_processes_on_start: true
            record_thread_names: true
        }}
    }}
}}
"""

    if args.with_gpu:
        # Reference: http://shortn/_qCI224ZcLZ
        trace_config += f"""
data_sources {{
    config {{
        name: "gpu.counters.i915"
        target_buffer: 0
        gpu_counter_config {{
            counter_period_ns: {args.gpu_counter_period_ns}
        }}
    }}
}}
data_sources {{
    config {{
        name: "gpu.renderstages.intel"
        target_buffer: 0
    }}
}}
data_sources {{
    config {{
        name: "gpu.counters.msm"
        target_buffer: 0
        gpu_counter_config {{
            counter_period_ns: {args.gpu_counter_period_ns}
        }}
    }}
}}
data_sources {{
    config {{
        name: "gpu.renderstages.msm"
        target_buffer: 0
    }}
}}
data_sources {{
    config {{
        name: "gpu.counters.panfrost"
        target_buffer: 0
        gpu_counter_config {{
            counter_period_ns: {args.gpu_counter_period_ns}
        }}
    }}
}}
"""
    return trace_config


class PerfettoSession:
    """PerfettoSession represents a tracing session."""

    def __init__(self, args):
        self.trace_config = generate_trace_config(args)
        self.output_file = args.output_file
        self.remote = args.remote or None
        self.duration_sec = args.duration_sec or None

        # Temp file for storing the generated trace config. When running on a
        # remote DUT, the same temp filename will be used to create a temp
        # config file on the remote DUT.
        # pylint: disable=R1732
        self.tmp_cfg_file = tempfile.NamedTemporaryFile(prefix="trace_config-")

        # Temp file for trace event output. When running on a remote DUT, the
        # same temp filename will be used to create a temp config file on the
        # remote DUT.
        # pylint: disable=R1732
        self.tmp_out_file = tempfile.NamedTemporaryFile(prefix="trace-")

        self.perfetto_proc = None
        self.perfetto_pid = None
        self.interrupted = False
        self.enable_gpu_events = args.with_gpu
        self.pps_producer_proc = None
        self.pps_producer_pid = None

    def poll_process_pid(self, pgrep_str: str):
        POLL_TIMEOUT_SECS = 5
        POLL_RETRY_INTERVAL_SECS = 0.5

        start = time.monotonic()
        while time.monotonic() - start < POLL_TIMEOUT_SECS:
            try:
                output = subprocess.run(
                    utils.wrap_cmd(
                        ["/usr/bin/pgrep", "-f", pgrep_str],
                        remote=self.remote,
                    ),
                    check=True,
                    encoding="utf-8",
                    stdout=subprocess.PIPE,
                )
                return output.stdout.strip()
            except subprocess.CalledProcessError:
                logging.debug("Process not started yet")
                time.sleep(POLL_RETRY_INTERVAL_SECS)

        return None

    def start(self):
        """Starts the Perfetto tracing session.

        Generates the trace configs and starts the Perfetto process (remotely).
        """

        # Create trace config file
        perfetto_cmd = [
            "/usr/bin/perfetto",
            "-c",
            self.tmp_cfg_file.name,
            "--txt",
            "-o",
            self.tmp_out_file.name,
        ]
        self.tmp_cfg_file.write(bytes(self.trace_config, "utf-8"))
        self.tmp_cfg_file.flush()
        if self.remote is not None:
            subprocess.run(
                ["scp", self.tmp_cfg_file.name, "%s:/tmp/" % self.remote],
                check=True,
            )
        logging.debug("Trace config file: %s", self.tmp_cfg_file.name)

        if self.enable_gpu_events:
            pps_producer_cmd = ["/usr/bin/pps-producer"]
            # pylint: disable=R1732
            self.pps_producer_proc = subprocess.Popen(
                utils.wrap_cmd(pps_producer_cmd, self.remote),
                start_new_session=True,
            )
            self.pps_producer_pid = self.poll_process_pid(
                " ".join(pps_producer_cmd)
            )
            if self.pps_producer_pid is None:
                raise TimeoutError("pps-producer process failed to start")
            logging.info(
                "Started pps-producer (REMOTE=%s, PID=%s)...",
                self.remote,
                self.pps_producer_pid,
            )

        # pylint: disable=R1732
        self.perfetto_proc = subprocess.Popen(
            utils.wrap_cmd(perfetto_cmd, self.remote), start_new_session=True
        )
        self.perfetto_pid = self.poll_process_pid(" ".join(perfetto_cmd))
        if self.perfetto_pid is None:
            raise TimeoutError("Perfetto process failed to start")

        logging.info(
            "Started recording new trace (REMOTE=%s, PID=%s)...",
            self.remote,
            self.perfetto_pid,
        )

    def wait(self):
        """Waits for the Perfetto process to end.

        The function waits until either SIGINT is received or after
        collecting trace for |self.duration_sec| seconds.
        """

        if self.perfetto_proc is None:
            raise RuntimeError("Perfetto process not started yet")
        try:
            if self.duration_sec is None:
                logging.info("Ctrl+C to stop tracing")
            else:
                logging.info("Will record for %f second(s)", self.duration_sec)
            self.perfetto_proc.wait(self.duration_sec)
        except subprocess.TimeoutExpired:
            self.terminate()

    def terminate(self):
        """Stops the Perfetto and pps-producer processes.

        Gracefully terminates the Perfetto and pps-producer processes through
        SIGINT.
        """

        if self.perfetto_pid is not None:
            subprocess.run(
                utils.wrap_cmd(
                    ["kill", "-SIGINT", self.perfetto_pid], self.remote
                ),
                check=True,
            )

        if self.pps_producer_pid is not None:
            subprocess.run(
                utils.wrap_cmd(
                    ["kill", "-SIGINT", self.pps_producer_pid], self.remote
                ),
                check=True,
            )

        logging.info("Stopped recording trace")

    def clean_up(self):
        """Cleans up temp files and syncs the trace output."""

        PROCESS_WAIT_TIMEOUT = 10

        if self.perfetto_proc is None:
            raise RuntimeError("Perfetto process not started yet")

        try:
            self.perfetto_proc.wait(PROCESS_WAIT_TIMEOUT)
            logging.debug(
                "Perfetto process terminated with code %d",
                self.perfetto_proc.returncode,
            )
        except subprocess.TimeoutExpired:
            # We still want to copy the trace output.
            logging.warning(
                "Perfetto process (PID=%d) did not terminate", self.perfetto_pid
            )

        if self.pps_producer_proc is not None:
            try:
                self.pps_producer_proc.wait(PROCESS_WAIT_TIMEOUT)
                logging.debug(
                    "pps-producer process terminated with code %d",
                    self.pps_producer_proc.returncode,
                )
            except subprocess.TimeoutExpired:
                # We still want to copy the trace output.
                logging.warning(
                    "pps-producer process (PID=%d) did not terminate",
                    self.pps_producer_pid,
                )

        logging.info("Syncing trace output file...")
        if self.remote:
            # Copy the output trace file back to host.
            subprocess.run(
                [
                    "scp",
                    "%s:%s" % (self.remote, self.tmp_out_file.name),
                    self.output_file,
                ],
                check=True,
            )
            # Clean up all the temp files on the DUT.
            subprocess.run(
                utils.wrap_cmd(
                    [
                        "rm",
                        "-f",
                        self.tmp_cfg_file.name,
                        self.tmp_out_file.name,
                    ],
                    remote=self.remote,
                ),
                check=True,
            )
        else:
            subprocess.run(
                ["cp", self.tmp_out_file.name, self.output_file], check=True
            )
        logging.info("Trace output written to: %s", self.output_file)

        self.tmp_cfg_file.close()
        self.tmp_out_file.close()

    def __enter__(self):
        try:
            self.start()
        except Exception:
            # Reap the started processes if anything goes wrong.
            self.terminate()
        return self

    def __exit__(self, *_):
        self.clean_up()


def set_up_subcommand_parser(subparsers):
    """Sets up subcommand parser for the `record` subcommand."""

    record_parser = subparsers.add_parser(
        "record",
        description=(
            "Record a new trace. For event categories and tags filtering, "
            "see http://shortn/_MdNGQVXkGY"
        ),
        help="Record a new trace",
    )
    record_parser.add_argument(
        "-r",
        "--remote",
        type=str,
        default=None,
        help="Remote SSH DUT to trace (default is to trace locally)",
    )
    record_parser.add_argument(
        "-o",
        "--output_file",
        type=str,
        default="/tmp/perfetto-trace",
        help="Output trace file path (default=%(default)s)",
    )
    record_parser.add_argument(
        "-t",
        "--duration_sec",
        type=float,
        default=None,
        help="Duration in seconds to trace (default is to trace until Ctrl+C)",
    )
    record_parser.add_argument(
        "-b",
        "--buffer_size_kb",
        type=int,
        default=100000,
        help="Size of trace buffer in KB (default=%(default)s)",
    )
    record_parser.add_argument(
        "--enabled_categories",
        type=str,
        default="camera.*",
        help=(
            "Comma-separated track event categories to enable "
            "(default='%(default)s')"
        ),
    )
    record_parser.add_argument(
        "--disabled_categories",
        type=str,
        default="*",
        help=(
            "Comma-separated track event categories to disable "
            "(default='%(default)s')"
        ),
    )
    record_parser.add_argument(
        "--enabled_tags",
        type=str,
        default="",
        help=(
            "Comma-separated track event tags to enable; events tagged as "
            "`debug` and `slow` are disabled by default (default='%(default)s')"
        ),
    )
    record_parser.add_argument(
        "--with_gpu",
        action="store_true",
        help=(
            "Record trace with GPU events enabled; a larger buffer size or "
            "reduced GPU counter sampling period may be needed to avoid event "
            "drops"
        ),
    )
    record_parser.add_argument(
        "--gpu_counter_period_ns",
        type=int,
        default=100000,
        help="GPU counter sampling period in ns (default=%(default)s)",
    )


def execute_subcommand(args):
    """Executes the `record` subcommand."""

    with PerfettoSession(args) as s:
        # Capture SIGINT (KeyboardInterrupt from Ctrl+C).
        signal.signal(signal.SIGINT, lambda _, __: s.terminate())
        s.wait()
