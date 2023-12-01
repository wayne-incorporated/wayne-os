# Perfetto Simple Producer

## `/usr/bin/perfetto_simple_producer`

This executable is a simple producer of perfetto that generates sample track
events. It should be only used in test images.

Sample steps:
1.  Start traced if it has't been started.
    ```
    (device) start traced
    ```

2.  Start a consumer that includes "track\_event" data source in the trace
    config, and "perfetto\_simple\_producer" category.
    ```
    (device) perfetto -c - --txt -o /tmp/perfetto-trace \
    <<EOF

    buffers: {
      size_kb: 63488
      fill_policy: DISCARD
    }
    buffers: {
        size_kb: 2048
        fill_policy: DISCARD
    }
    data_sources: {
        config {
            name: "track_event"
            track_event_config {
                enabled_categories: "perfetto_simple_producer"
            }
        }
    }
    duration_ms: 10000

    EOF
    ```

3.  Run the simple producer.
    ```
    (device) perfetto_simple_producer
    ```

4.  Collect the trace at `/tmp/perfetto-trace`. It can be uploaded to the
    [perfetto UI website](https://ui.perfetto.dev) and check if there are 4 tracks on the corresponding
    threads. And note that when uploading the file please make sure the file is
    readable by user `chronos`. Otherwise, the site will throw an error.
