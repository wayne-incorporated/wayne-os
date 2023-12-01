# Feedback Utility

## perf\_data\_extract.py

This is a utility script for devs analyzing the performance profile contained in
feedback logs. It can be used to extract the `perf-data` element from a feedback
logs archive and save the extracted data to a file ready for analysis
using pprof.

## Usage

To extract the `perf-data` element from a system logs archive `system_logs.zip`
and save to `/tmp/perf-data.proto`:

`perf_data_extract.py system_logs.zip /tmp/perf-data.proto`

To show the help message, set the `-h` flag:

`perf_data_extract.py -h`
