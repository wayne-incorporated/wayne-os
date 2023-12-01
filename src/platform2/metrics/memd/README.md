# Fine-grained collection of memory stats

The Chromium OS memory daemon (`memd`) is a lightweight collector of values and
events related to system memory.

`Memd` runs continuously, but is mostly asleep when memory pressure is low.  As
pressure increases, it starts sampling rapidly various kernel-supplied
quantities, mainly from `/proc/vmstat`.  It also collects events, such as the
crossing of the _available memory_ threshold which produces a low-memory
notification.

The sampling and event collection is done in an in-memory circular buffer.
Certain "interesting" events trigger a _collection_, that is make `memd` dump a
range of samples and events around the interesting events into a _clip file_ in
`/var/log/memd`.  Clip files are also rotated, and the older ones get
eventually clobbered by new events.

The intent is that `memd` output be collected alongside the rest of the
logs collected with feedback reports.  If the report was motivated by poor
behavior of the memory subsystem, the data will be directly useful.  Otherwise
the data can be opportunistically used for analysis.
