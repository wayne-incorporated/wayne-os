# Camera trace metrics extension

See the Perfetto [Trace-based metrics][1] doc for an overview of how trace
metrics are defined and computed.

Perfetto reserves protobuf field 450 - 499 for local development, and
500 - 1000 for [vendor extensions][2]. We allocate the vendor extensions as:

- 500 - 600: Core camera metrics
- 600 - 800: Camera feature metrics
- 800 - 1000: Camera app metrics

[1]: https://perfetto.dev/docs/analysis/metrics
[2]: https://android.googlesource.com/platform/external/perfetto/+/HEAD/protos/perfetto/metrics/metrics.proto#239
