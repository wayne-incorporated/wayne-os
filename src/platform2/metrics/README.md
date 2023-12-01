# Chromium OS Metrics

The Chromium OS "metrics" package contains utilities for client-side user metric
collection.

When Chromium is installed, Chromium will take care of aggregating and uploading
the metrics to the UMA server.

When Chromium is not installed (e.g. an embedded/headless build) and the
metrics_uploader USE flag is set, `metrics_daemon` will aggregate and upload the
metrics itself.

[TOC]


## The Metrics Library: libmetrics

libmetrics implements the basic C and C++ API for metrics collection. All
metrics collection is funneled through this library. The easiest and
recommended way for a client-side module to collect user metrics is to link
libmetrics and use its APIs to send metrics to Chromium for transport to
UMA. In order to use the library in a module, you need to do the following:

- Add a dependence (DEPEND and RDEPEND) on chromeos-base/metrics to the module's
  ebuild.

- Link the module with libmetrics (for example, by passing `-lmetrics` to the
  module's link command).  Both `libmetrics.so` and `libmetrics.a` are built
  and installed into the sysroot libdir (e.g. `$SYSROOT/usr/lib/`). By default
  `-lmetrics` links against `libmetrics.so`, which is preferred.

- Make sure `/var/lib/metrics` is writable by the daemon. For example, if you
  are using libmetrics in a daemon, you can achieve this by adding
  `-b /var/lib/metrics,,1` to the `minijail0` command that starts the daemon.

- To access the metrics library API in the module, include the
  `<metrics/metrics_library.h>` header file. The file is installed in
  `$SYSROOT/usr/include/` when the metrics library is built and installed.

- The API is documented in [metrics_library.h](./metrics_library.h).  Before
  using the API methods, a MetricsLibrary object needs to be constructed. A
  quick example:

  ```c++
  MetricsLibrary metrics;
  bool result = metrics.SendToUMA(
                 /*name=*/"Platform.MyModule.MyLabel",
                 /*sample=*/3,
                 /*min=*/1,
                 /*max=*/10,
                 /*num_buckets=*/10);
  if (!result) {
    LOG(ERROR) << "Failed to send to UMA";
  }
  ```

  For more information on the C API, see
  [c_metrics_library.h](./c_metrics_library.h).

- On the target platform, shortly after the sample is sent, it should be visible
  in Chromium through `chrome://histograms`.

- The library includes a CumulativeMetrics class which can be used for
  histograms whose samples represent accumulation of quantities on the
  same device across a period of time: for instance, how much time was spent
  playing music on each device and each day of use.  Please see the
  CumulativeMetrics section below.

### How metrics are actually sent

libmetrics always writes histogram data to `/var/lib/metrics/uma-events` using a
custom format. flock() is used to avoid races.

*** note
**Warning:** All metrics are written synchronously to disk and may block if
another process has the uma-events file locked. Unlike UMAs in Chrome, care must
be taken to not to update UMAs in performance-critical sections.
***

*** aside
**Note:** libmetrics does not check consent before writing to
/var/lib/metrics/uma-events, leaving that to the sender.
***

On most boards, the uma-events file is processed by Chromium's
`chromeos::ExternalMetrics` class. `chromeos::ExternalMetrics` periodically
flock's the file, reads all the metrics in it, and truncates the file. The
`chromeos::ExternalMetrics` sends the metrics from the file into Chrome's UMA
histogram collection system, after which they are treated like any other Chrome
UMA. In particular, Chrome will check consent before uploading the histograms.

However, on the few boards that do not run a Chrome browser, uploading is
handled by the UploadService inside metrics_daemon. The UploadService is only
instatiated if `--uploader` is passed to `metric_daemon`. Similar to Chrome, the
UploadService will periodically lock-read-truncate-unlock the uma-events
file. If we have user permission to upload stats, the UploadService will then
send the metrics after unlocking the file. Here, user permission is controlled
by the device policy's `metrics_enabled` field. (If the `metrics_enabled` field
is not set, this falls back to enabling stats if the device is enterprise
enrolled; if that isn't the case, the existence of the "/home/chronos/Consent To
Send Stats" file is used.)

## The Metrics Client: metrics_client

`metrics_client` is a command-line utility for sending histogram samples and
user actions.  It is installed under /usr/bin on the target platform and uses
libmetrics.  It is typically used for generating metrics from shell scripts.

For usage information and command-line options, run `metrics_client` on the
target platform or look for `Usage:` in
[metrics_client.cc](./metrics_client.cc).


## The Metrics Daemon: metrics_daemon

metrics_daemon is a daemon that runs in the background on the target platform
and is intended for passive or ongoing metrics collection, or metrics collection
requiring input from other modules. For example, it listens to D-Bus
signals related to the user session and screen saver states to determine if the
user is actively using the device or not and generates the corresponding
data. The metrics daemon also uses libmetrics.

The recommended way to generate metrics data from a module is to link and use
libmetrics directly. However, the module could instead send signals to or
communicate in some alternative way with the metrics daemon. Then the metrics
daemon needs to monitor for the relevant events and take appropriate action --
for example, aggregate data and send the histogram samples.

## Cumulative Metrics

The CumulativeMetrics class in libmetrics helps keep track of quantities across
boot sessions, so that the quantities can be accumulated over stretches of time
(for instance, a day or a week) without concerns about intervening reboots or
version changes, and then reported as samples.  For this purpose, some
persistent state (i.e. partial accumulations) is maintained as files on the
device.  These "backing files" are typically placed in
`/var/lib/<daemon-name>/metrics`.  (The metrics daemon is an exception, with its
backing files being in `/var/lib/metrics`.)

## Memory Daemon

The [memd](./memd/) subdirectory contains a daemon that collects data at high
frequency during episodes of heavy memory pressure.

## vmlog

[vmlog_writer](./vmlog_writer.cc) writes `/var/log/vmlog` files. It is a
space-delimited format. In order to parse, use the the first line to obtain the
list of items, because the number of columns depends on number of CPU cores.

-   time: current time
-   From /proc/vmstat
    -   pgmajfault: major faults
    -   pgmajfault_f: major faults served from disk
    -   pgmajfault_a: major faults served from zram
    -   pswpin: number of swap in (pages).
    -   pswpout: number of swap out (pages).
-   From /proc/stat
    -   cpuusage: all cpu usage ticks from `cpu` line excluding idle and iowait.
-   gpufreq: GPU frequency; how it's obtained depends on device.
-   From `/sys/devices/system/cpu/cpuN/cpufreq/scaling_cur_freq`
    -   cpufreqN: frequency of core in kHz.

## Further Information

See

https://chromium.googlesource.com/chromium/src.git/+/HEAD/tools/metrics/histograms/README.md

for more information on choosing name, type, and other parameters of new
histograms.  The rest of this README is a super-short synopsis of that
document, and with some luck it won't be too out of date.


## Synopsis: Histogram Naming Convention

Use TrackerArea.MetricName. For example:

* Platform.DailyUseTime
* Network.TimeToDrop


## Synopsis: Server Side

If the histogram data is visible in `chrome://histograms`, it will be sent by an
official Chromium build to UMA, assuming the user has opted into metrics
collection. To make the histogram visible on "chromedashboard", the histogram
description XML file needs to be updated (steps 2 and 3 after following the
"Details on how to add your own histograms" link under the Histograms tab).
Include the string "Chrome OS" in the histogram description so that it's easier
to distinguish Chromium OS specific metrics from general Chromium histograms.

The UMA server logs and keeps the collected field data even if the metric's name
is not added to the histogram XML. However, the dashboard histogram for that
metric will show field data as of the histogram XML update date; it will not
include data for older dates. If past data needs to be displayed, manual
server-side intervention is required. In other words, one should assume that
field data collection starts only after the histogram XML has been updated.

## Synopsis: FAQ

### What should my histogram's |min| and |max| values be set at?

You should set the values to a range that covers the vast majority of samples
that would appear in the field.  Values below |min| are collected in the
"underflow bucket" and values above |max| end up in the "overflow bucket".  The
reported mean of the data is precise, i.e. it does not depend on range and
number of buckets.

### How many buckets should I use in my histogram?

You should allocate as many buckets as necessary to perform proper analysis on
the collected data.  Most data is fairly noisy: 50 buckets are plenty, 100
buckets are probably overkill.  Also consider that the memory allocated in
Chromium for each histogram is proportional to the number of buckets, so don't
waste it.

### When should I use an enumeration (linear) histogram vs. a regular (exponential) histogram?

Enumeration histograms should really be used only for sampling enumerated
events and, in some cases, percentages. Normally, you should use a regular
histogram with exponential bucket layout that provides higher resolution at
the low end of the range and lower resolution at the high end. Regular
histograms are generally used for collecting performance data (e.g., timing,
memory usage, power) as well as aggregated event counts.
