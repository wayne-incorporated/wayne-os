# metric_reporter - IO usage reporting daemon

`metric_reporter` runs as a user daemon in the default crostini container
(based on checking /etc/hostname). Every 5 minutes, it will poll /proc/vmstats
to find read/write amounts to disk and swap, and emit the incremental
differences to UMA via garcon's
[ReportMetrics](/vm_tools/proto/container_host.proto) interface.
