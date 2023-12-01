#!/usr/bin/env python3
#
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Interactive viewer for memd logs.  It displays the logged values and allows
# toggling individual graphs off and on.

"""Interactive visualizer of memd logs."""

import argparse
import glob
import math
import os
import sys
import warnings

import matplotlib.pyplot as plt  # pylint: disable=import-error


# Remove spurious warning from pyplot.
warnings.filterwarnings(
    "ignore",
    ".*Using default event loop until function "
    "specific to this GUI is implemented.*",
)


def die(message):
    """Prints message and exits with error status."""
    print("memd_plot.py: fatal error:", message)
    sys.exit(1)


def warn(message):
    """Prints warning."""
    print("memd_plot.py: warning:", message)
    print(message)


def usage():
    """Prints usage message and exits"""
    die("usage: memd-plot.py <memd-log-directory>")


def eng_notation(x):
    """Converts number to string in engineering notation.

    Returns a formatted string for numeric value |x| rounded to an int in
    quasi-engineering notation, i.e:
      - if |x| is less than 1,000,000 use the standard integer format;
      - else use the <a>E<b> form where x = a * 10^b and b is a multiple of 3.
    """
    exponent = len(str(int(x))) - 1
    # Numbers up to 6 digits are easy to parse visually.
    if exponent < 6:
        return "%.7g" % x
    # Round exponent down to a multiple of 3.
    exponent = exponent - (exponent % 3)
    mantissa = x / (10 ** exponent)
    return "%.4gE^%s" % (mantissa, exponent)


def derivative(v1, v0, t1, t0):
    """Computes the difference quotient.

    Returns an approximation of the derivative dv/dt with special handling
    of delta(t) = 0.
    """
    if t1 > t0:
        return (v1 - v0) / (t1 - t0)
    else:
        return 0


# Dictionary keys that control pyplot keyboard bindings.
pyplot_keymap_entries = {}


def disable_pyplot_keymap():
    """Disables predefined pyplot keyboard bindings."""
    for name in pyplot_keymap_entries:
        plt.rcParams[name] = ""


def enable_pyplot_keymap():
    """Re-enables predefined pyplot keyboard bindings."""
    for name in pyplot_keymap_entries:
        plt.rcParams[name] = pyplot_keymap_entries[name]


def initialize_pyplot_keymap():
    """Saves the dictionary keys that control pyplot keyboard bindings."""
    for name in plt.rcParams:
        if name.startswith("keymap."):
            pyplot_keymap_entries[name] = plt.rcParams[name]


color_table = [
    "black",
    "black",
    "black",
    "black",
    "black",
    "blue",
    "blue",
    "red",
    "red",
    "#ff0000",
    "#00ff00",
    "#0000ff",
    "#06cc16",
    "#c5960f",
    "#530072",
    "#b60ab4",
    "#0d757b",
    "#0ceb6c",
    "#4ba6ad",
    "#d00b03",
    "#e3240d",
    "#e60606",
    "#ffa19e",
    "olive",
    "orange",
    "salmon",
    "sienna",
    "tan",
    "plum",
    "maroon",
    "navy",
    "indigo",
    "darkgreen",
    "purple",
    "chocolate",
]


def color_for_name(name):
    """Computes a random but consistent RGB color for string |name|."""
    h = hash(name)
    # Generating good colors is difficult, so just use a table.
    return color_table[h % len(color_table)]


def linestyle_for_name(name):
    """Computes (and memorizes) a random line style for string |name|."""
    h = hash(name)
    styles = ["-", "-", "-", "--", "-.", ":"]
    return styles[h % len(styles)]


next_label_key = 0
label_keys = {}
key_labels = {}


def add_grid(fig, max_x):
    """Adds a grid to the plot."""
    ax = fig.add_subplot(1, 1, 1)

    if max_x > 100:
        # The grid is too fine for plotting.  Ideally this should depend on the
        # current window on the plots, not the absolute maximum.
        return

    major_xticks = list(range(0, max_x, 5))
    minor_xticks = list(range(0, max_x, 1))
    major_yticks = list(range(0, 101, 10))
    minor_yticks = list(range(0, 101, 5))

    ax.set_xticks(major_xticks)
    ax.set_xticks(minor_xticks, minor=True)
    ax.set_yticks(major_yticks)
    ax.set_yticks(minor_yticks, minor=True)

    ax.grid(which="minor", alpha=0.5)
    ax.grid(which="major", alpha=1)


def round_up(x, digits):
    """Rounds up the |digits| most significant digits.

    For instance: round_up(12345, 2) returns 13000.
    """
    r = 10 ** (len(str(int(x))) - digits)
    return math.ceil(x / r) * r


def smooth_out(array, window_size):
    """Smooths out an array of values by averaging over a window."""
    for i in range(len(array) - 1, window_size - 2, -1):
        if array[i] is None:
            continue
        sample_count = 1
        for j in range(window_size - 1):
            v = array[i - (j + 1)]
            if v is not None:
                array[i] += v
                sample_count += 1
        array[i] /= float(sample_count)


def set_attribute(label, attribute_name, attribute_value):
    """Sets graph attribute |attribute_name| of |label| to |attribute_value|."""
    graph_attributes[label].update({attribute_name: attribute_value})


def clear_attribute(label, attribute_name):
    """Removes graph attribute |attribute_name| of |label|."""
    del graph_attributes[label][attribute_name]


def toggle_attribute(label, attribute_name):
    """Clears |attribute_name| of |label| if it is set, else sets it to True."""
    if attribute_name in graph_attributes[label]:
        clear_attribute(label, attribute_name)
    else:
        set_attribute(label, attribute_name, True)


# Tables that describe how various values/events are plotted.

# Graph_attributes is for time-varying values.
# Each graph is identified by its name (for instance, 'freeram'),
# also called 'label'.
#
# Graphs with 'ignore' == True are not plotted.
# Graphs with the same 'group' attribute are plotted with the same scale.
# 'off' == True: hides the graph at startup.
# 'differentiate' == True: plots the derivatives between samples.
# 'optional' == True: label is optional in samples.
graph_attributes = {
    # 'uptime' is treated specially since it is never plotted
    "uptime": {"ignore": True},
    # 'type' is also special because it is a string
    "type": {"ignore": True},
    "load": {
        "off": True,
        # Load averages returned by sysinfo need scaling.
        "scale": 1.0 / 65536,
    },
    "freeram": {
        "group": "ram",
        "scale": 1e-3,
    },
    "freeswap": {
        "scale": 1e-3,
    },
    "procs": {
        "off": True,
    },
    "runnables": {"off": True, "smooth": 3},
    "available": {
        "group": "ram",
        "scale": 1000,
    },
    "pswpin": {
        "differentiate": True,
        "group": "pages",
        "off": True,
    },
    "pswpout": {
        "differentiate": True,
        "group": "pages",
        "off": True,
    },
    "nr_pages_scanned": {
        "optional": True,
        "group": "pages",
        "off": True,
    },
    "pgalloc": {
        "optional": True,
        "differentiate": True,
        "group": "pages",
        "smooth": 3,
        "off": True,
    },
    "pgalloc_dma": {
        "optional": True,
        "differentiate": True,
        "group": "pages",
        "smooth": 3,
        "off": True,
    },
    "pgalloc_dma32": {
        "optional": True,
        "differentiate": True,
        "group": "pages",
        "smooth": 3,
        "off": True,
    },
    "pgalloc_normal": {
        "optional": True,
        "differentiate": True,
        "group": "pages",
        "smooth": 3,
        "off": True,
    },
    "pgmajfault": {
        "differentiate": True,
        "group": "pages",
        "off": True,
    },
    "pgmajfault_f": {
        "optional": True,
        "differentiate": True,
        "group": "pages",
        "off": True,
    },
}


# Parameter_attributes describes fixed values, plotted as horizontal lines.
parameter_attributes = {
    "margin": {
        "group": "ram",
        "scale": 1000,
    },
    "high_water_mark_kbytes": {
        "group": "ram",
    },
    "min_water_mark_kbytes": {
        "group": "ram",
    },
    "low_water_mark_kbytes": {
        "group": "ram",
    },
}


# Event_attributes describes events, plotted as vertical lines.
event_attributes = {
    "lowmem": {
        "name": "Enter Low Mem",
    },
    "lealow": {
        "name": "Leave Low Mem",
    },
    "oomkll": {
        "name": "OOM (from Chrome)",
    },
    "keroom": {
        "name": "OOM (kernel time)",
    },
    "traoom": {
        "name": "OOM (trace delivery)",
    },
    "discrd": {
        "name": "Tab/App Discard",
    },
    "sleepr": {
        "name": "Sleeper",
    },
}


max_values = {}
max_values_by_group = {}


class Plotter(object):
    """Methods to input, process and display memd samples."""

    def __init__(self, args):
        self._args = args
        self._samples = {}
        self._memd_parameters = {}
        self._label_key_index = 0
        self._needs_redisplay = True
        # Interactive input state
        self._ii_state = "base"
        self._labels = {}
        self._plot_labels = {}

    def normalize_samples(self):
        """Normalizes the arrays of values in |samples|

        Values are modified according to the graph attributes.
        Additionally, expected and found label names are
        checked for consistency.
        """
        # Sanity check of sample labels against the name/labels in
        # graph_attributes.
        known_labels = set(graph_attributes.keys())
        required_labels = set(
            [
                key
                for key in graph_attributes.keys()
                if "optional" not in graph_attributes[key]
            ]
        )
        found_labels = set(self._samples.keys())

        if not required_labels.issubset(found_labels):
            die(
                "these required fields are missing:\n%s\n"
                % (sorted(required_labels.difference(found_labels)))
            )

        if not found_labels.issubset(known_labels):
            warn(
                "ignoring these unknown fields:\n%s\n"
                % (sorted(found_labels.difference(known_labels)))
            )

        self._labels = found_labels & known_labels

        # Scale values by given scale factor (if any).
        # Also filter values (average over window, and compute derivative).
        # A bit hacky since there may be reboots.
        uptimes = self._samples["uptime"]
        for label in self._labels:
            attr = graph_attributes[label]

            if "ignore" in attr:
                continue

            scale = attr["scale"] if "scale" in attr else 1
            self._samples[label] = [scale * x for x in self._samples[label]]

            if "differentiate" in attr:
                s = self._samples[label]
                s = [
                    derivative(s[i + 1], s[i], uptimes[i + 1], uptimes[i])
                    for i in range(len(s) - 1)
                ]
                s.append(0.0)
                self._samples[label] = s

            if "smooth" in attr:
                window_size = attr["smooth"]
                smooth_out(self._samples[label], window_size)

        # Shift uptimes to a zero base and adjust for gaps between
        # clips, including negative gaps due to reboots.
        offset = 0.0
        last_uptime = -1.0
        adjusted_uptimes = []
        for uptime in uptimes:
            # If the uptimes are not contiguous (i.e. at most about
            # 0.1 seconds apart, generously rounded up to 0.5) adjust
            # offset so as to leave a 1-second gap.
            if abs(uptime - last_uptime) > 0.5:
                offset += last_uptime - uptime + 1.0
            last_uptime = uptime
            adjusted_uptimes.append(uptime + offset)

        self._samples["uptime"] = adjusted_uptimes

        # Scale all values to between 0 and 100 so they can all be
        # displayed in the same graph.  This takes a few steps.

        # 1. Find groups of quantities that should be scaled equally.
        sample_groups = {}
        for label in self._labels:
            attr = graph_attributes[label]
            if "group" in attr:
                group_name = attr["group"]
                if group_name not in sample_groups:
                    sample_groups[group_name] = set()
                sample_groups[group_name].add(label)

        # 2. Find max value for each group.
        for group_name in sample_groups:
            max_value = 0.0
            for label in sample_groups[group_name]:
                max_value = max(max_value, max(self._samples[label]))
            for label in sample_groups[group_name]:
                max_values[label] = max_value
            max_values_by_group[group_name] = max_value

        # Find max value for values that don't belong to any group.
        for label in self._labels:
            if (
                label not in max_values
                and "ignore" not in graph_attributes[label]
            ):
                max_values[label] = max(self._samples[label])

        # Round up max values so that they aren't ugly.  This
        # increases them a max of 10%.
        for (label, value) in max_values.items():
            max_values[label] = round_up(value, 2)
        for (group_name, value) in max_values_by_group.items():
            max_values_by_group[group_name] = round_up(value, 2)

        # Scale so that max_value is mapped to 100.
        for label in max_values:
            m = max_values[label]
            self._samples[label] = [x / m * 100 for x in self._samples[label]]

    def add_gaps_to_samples(self):
        new_samples = {}
        for name in self._samples:
            new_samples[name] = []

        uptimes = self._samples["uptime"]
        previous_uptime = -1.0
        for i, uptime in enumerate(uptimes):
            # Check for gap, but skip first (artificial) gap.  At each gap,
            # insert a None value in all value arrays, except uptime and type.
            if i > 0 and uptime > previous_uptime + 0.3:
                for name in self._samples:
                    if name == "uptime":
                        new_samples[name].append(previous_uptime)
                    elif name == "type":
                        new_samples[name].append("timer")
                    else:
                        new_samples[name].append(None)
            previous_uptime = uptime

            # Copy over old values.
            for name in self._samples:
                new_samples[name].append(self._samples[name][i])

        self._samples = new_samples

    def plot_values(self, label):
        """Plots the sampled values for label as a function of time."""

        on = "off" not in graph_attributes[label]
        legend_entry = "%s) %s (100 = %s)" % (
            label_keys[label],
            label,
            eng_notation(max_values[label]),
        )

        for v in self._samples[label]:
            if v and v < 0:
                die("negative value for %s: %s" % (label, v))

        plt.plot(
            self._samples["uptime"],
            self._samples[label],
            color=(color_for_name(label) if on else (1.0, 1.0, 1.0, 0)),
            linestyle=linestyle_for_name(label),
            label=legend_entry,
        )

    def plot_redisplay(self, fig):
        """Redisplays the full graph."""

        plt.clf()
        add_grid(fig, int(self._samples["uptime"][-1]))

        # Graphs.
        for plot_label in sorted(self._plot_labels):
            self.plot_values(plot_label)

        # Events.
        uptimes = self._samples["uptime"]
        event_types = self._samples["type"]
        times = {name: [] for name in event_attributes}
        values = {name: [] for name in event_attributes}
        for i, uptime in enumerate(uptimes):
            event_type = event_types[i]
            if event_type == "timer":
                continue

            # Create an isolated vertical line.
            times[event_type].append(uptime)
            values[event_type].append(105)
            times[event_type].append(uptime)
            values[event_type].append(-5)
            times[event_type].append(uptime)
            values[event_type].append(None)

        for event_type in event_attributes:
            if times[event_type]:
                plt.plot(
                    times[event_type],
                    values[event_type],
                    color=color_for_name(event_type),
                    linestyle=linestyle_for_name(event_type),
                    label=("| " + event_attributes[event_type]["name"]),
                )

        times = self._samples["uptime"]
        min_time = times[0]
        max_time = times[-1]
        for name in parameter_attributes:
            attr = parameter_attributes[name]
            parameter_value = self._memd_parameters[name]
            if "scale" in attr:
                parameter_value *= attr["scale"]
            if "group" in attr:
                max_value = max_values_by_group[attr["group"]]
                parameter_value /= max_value
                parameter_value *= 100
            legend_entry = "* %s (100 = %s)" % (name, eng_notation(max_value))
            plt.plot(
                [min_time, max_time],
                [parameter_value, parameter_value],
                color=color_for_name(name),
                linestyle=linestyle_for_name(name),
                label=legend_entry,
            )

        plt.legend(fontsize=12)

    def merge_pgalloc(self):
        """Combines the 'pgalloc_*' quantities into a single 'pgalloc'.

        Adds up all kinds of page allocation into a single one, for legacy logs.
        New logs are produced with a single 'pgalloc' quantity, old logs break
        it down by zone.
        """

        if "pgalloc" in self._samples:
            return

        pgalloc_samples = None
        for (label, values) in self._samples.items():
            if label.startswith("pgalloc_"):
                if pgalloc_samples is None:
                    pgalloc_samples = values[:]
                else:
                    pgalloc_samples = [
                        x + y for x, y in zip(pgalloc_samples, values)
                    ]
        self._samples["pgalloc"] = pgalloc_samples

    def run(self):
        """Reads the samples and plots them interactively."""
        field_names = None
        field_names_set = None
        lines = []

        print("available commands (in addition to pyplot standard commands):")
        print("t<key> - toggle graph <key> (see legend)")
        print("q      - quit")
        os.chdir(self._args["memd-log-directory"])
        filenames = glob.glob("memd.clip*.log") or die(
            "there are no clip files"
        )
        self.read_parameters()

        # Sort files by their time stamp (first line of each file)
        filenames = [
            x[0]
            for x in sorted(
                [(name, next(open(name, encoding="utf-8")))
                 for name in filenames],
                key=lambda x: x[1],
            )
        ]

        # Read samples into |self._samples|.
        for filename in filenames:
            with open(filename, encoding="utf-8") as sample_file:
                # Skip first line (time stamp).
                _ = next(sample_file)

                # Second line: field names.
                line = next(sample_file)
                if field_names:
                    assert set(line.split()) == field_names_set
                else:
                    field_names = line.split()
                    field_names_set = set(field_names)
                    self._samples = {field_name: []
                                     for field_name in field_names}

                # Read the following lines, which contain samples.
                for line in sample_file:
                    lines.append(line.split())

        # Build an array of values for each field.
        for line in lines:
            for name, value in zip(field_names, line):
                if name != "type":
                    value = float(value)
                self._samples[name].append(value)

        self.merge_pgalloc()
        self.normalize_samples()
        self.plot_samples()

    def read_parameters(self):
        """Reads the memd parameters file."""
        parameters = []
        try:
            with open("memd.parameters", encoding="utf-8") as parameters_file:
                parameters = parameters_file.readlines()[1:]
        except Exception:
            die("cannot open memd.parameters")

        for line in parameters:
            name, value = line.split()
            self._memd_parameters[name] = int(value)

    def assign_keys_to_labels(self):
        self._plot_labels = [
            label
            for label in self._labels
            if "ignore" not in graph_attributes[label]
        ]
        label_index = 0
        for label in sorted(self._plot_labels):
            key = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[label_index]
            label_keys[label] = key
            key_labels[key] = label
            label_index += 1

    def plot_samples(self):
        """Does all the interactive plotting work."""
        # Add None values to create breaks in plotted lines.
        self.add_gaps_to_samples()
        self.assign_keys_to_labels()
        fig = plt.figure(figsize=(30, 10))
        fig.canvas.mpl_connect("key_press_event", self.keypress_callback)
        initialize_pyplot_keymap()
        self.plot_interactive(fig)

    def plot_interactive(self, fig):
        while self._ii_state != "quit":
            if self._needs_redisplay:
                self.plot_redisplay(fig)
                self._needs_redisplay = False
            plt.waitforbuttonpress(0)

    def keypress_callback(self, event):
        """Callback for key press events."""
        key = event.key
        if self._ii_state == "toggling":
            key = key.upper()
            if key in key_labels:
                label = key_labels[key.upper()]
                toggle_attribute(label, "off")
                self._needs_redisplay = True
                enable_pyplot_keymap()
            else:
                print('no graph is associated with key "%s"' % key)
            self._ii_state = "base"
        elif self._ii_state == "base":
            if key == "q":
                self._ii_state = "quit"
            elif key == "t":
                self._ii_state = "toggling"
                disable_pyplot_keymap()


def main():
    """Reads memd logs and interactively displays their content."""
    parser = argparse.ArgumentParser(
        description="Display memd logs interactively."
    )
    parser.add_argument("memd-log-directory")
    plotter = Plotter(vars(parser.parse_args()))
    plotter.run()


main()
