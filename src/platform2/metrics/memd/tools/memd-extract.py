#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Extracts memd logs from feedback report logs, and reproduces the original
# /var/log/memd directory, containing the file memd.parameters and one or more
# memd.clip{000,001,...}.log (the "clip" files) with the sampled data.  This is
# the format expected by memd-plot.py.

"""Extracts memd logs from feedback report logs."""

from __future__ import print_function

import argparse
import glob
import os
import re
import subprocess
import sys


def die(message):
    """Prints message and exits with failure status."""
    print("memd-extract.py:", message)
    sys.exit(1)


class Extractor(object):
    """Methods to reconstruct memd logs from a feedback report."""

    def __init__(self, args):
        """Constructor."""
        self._args = args
        self._timestamp_re = re.compile(
            r"\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\..*"
        )

    def setup_outdir(self, outdir):
        """Sets up the output directory by creating or cleaning it as needed."""
        if not os.path.exists(outdir):
            os.mkdir(outdir)
            return

        if not os.path.isdir(outdir):
            die(
                "output directory path %s exists but is not a directory"
                % outdir
            )

        files = glob.glob("%s/*" % outdir)
        clip_re = re.compile(r"^%s/*memd.clip\d\d\d\.log$" % outdir)
        for filename in files:
            if filename == "memd.parameters" or clip_re.match(filename):
                os.remove(filename)

    def unzip_and_open(self, filename):
        """Unzips |filename| and opens system_logs.txt.

        Ensures that |filename| is a ZIP archive containing system_logs.txt,
        unzips it, and opens it.
        """
        list_output = subprocess.check_output(["unzip", "-l", filename])
        for line in list_output.splitlines():
            if re.match(r".*system_logs.txt$", str(line, encoding="utf-8")):
                subprocess.check_call(["unzip", "-o", filename])
                return open("system_logs.txt", "r")
        die("%s does not contain system_logs.txt" % filename)

    def extract_sections(self, filename):
        """Extracts memd-related sections of the feedback logs in |filename|.

        The contents of |filename| are expected to be in feedback log format.
        Opens |filename| (if needed, |filename| is first uncompressed into
        system_logs.txt) and returns the content of memd parameters and clip
        files from the feedback log.  The clips are expected to appear first (as
        per alphabetical order of the filenames).
        """
        if re.match(r"^.*\.zip", filename):
            input_file = self.unzip_and_open(filename)
        else:
            input_file = open(filename, "r")

        # |memd_parameters| is an array of lines.
        memd_parameters = []
        # |memd_clip_lines| is an array of lines.
        memd_clip_lines = []
        scan_state_start, scan_state_clips, scan_state_parameters = range(3)
        scan_state = scan_state_start
        for line in input_file:
            # In the START state look for beginning of sections.
            if scan_state == scan_state_start:
                if line.startswith("memd clips=<multiline>"):
                    scan_state = scan_state_clips
                    continue
                if line.startswith("memd.parameters=<multiline>"):
                    scan_state = scan_state_parameters
                    continue
            if scan_state == scan_state_clips:
                if "--- END ---" in line:
                    scan_state = scan_state_start
                else:
                    memd_clip_lines.append(line)
            if scan_state == scan_state_parameters:
                if "--- END ---" in line:
                    scan_state = scan_state_start
                    # Assume memd.parameters comes after memd clips,
                    # thus we're done.
                    break
                else:
                    memd_parameters.append(line)

        if scan_state != scan_state_start:
            die("missing END line in multiline section")
        if len(memd_clip_lines) == 0:
            die("missing memd_clips section")
        if "--- START ---" not in memd_clip_lines[0]:
            die("missing START line in memd clips section")
        if "--- START ---" not in memd_parameters[0]:
            die("missing START line in memd.parameters section")

        memd_clips = self.extract_clips(memd_clip_lines[1:])
        return (memd_parameters[1:], memd_clips)

    def extract_clips(self, clip_lines):
        """Extracts the content of clip files.

        |clip_lines| contains lines from a feedback report, where all clip files
        are concatenated and need to be separated by looking at their two-line
        header.  Returns an array of array of lines, each element representing
        the content of a clip file.
        """
        clips = []
        this_clip = []
        for line in clip_lines:
            if self._timestamp_re.match(line):
                clips.append(this_clip)
                this_clip = []
            this_clip.append(line)
        clips.append(this_clip)
        return clips[1:]

    def run(self):
        """Extracts memd parameters and clip files from a feedback report log.

        The log may be compressed (*.zip) or plain text (all other file names).
        The output files are placed in the specified output directory.
        """
        outdir = self._args["outdir"]
        self.setup_outdir(outdir)
        (parameters, clips) = self.extract_sections(self._args["input-file"])
        with open("%s/memd.parameters" % outdir, "w") as f:
            for line in parameters:
                f.write(line)
        clip_number = 0
        for clip in clips:
            with open("%s/memd.clip%03d.log" % (outdir, clip_number), "w") as f:
                clip_number += 1
                for line in clip:
                    f.write(line)


def main():
    """Extracts memd logs from feedback report logs."""
    parser = argparse.ArgumentParser(
        description="Extract memd logs from feedback report logs."
    )
    parser.add_argument("input-file")
    parser.add_argument("-o", "--outdir", default="memd")
    extractor = Extractor(vars(parser.parse_args()))
    extractor.run()


main()
