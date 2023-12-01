-- Copyright 2022 The ChromiumOS Authors
-- Use of this source code is governed by a BSD-style license that can be
-- found in the LICENSE file.

SELECT RUN_METRIC('camera_sessions.sql');


-- The camera client can (re-)configure different stream sets in one camera
-- session.
DROP VIEW IF EXISTS slice_per_session_with_stream_conf_id;
CREATE VIEW slice_per_session_with_stream_conf_id AS
WITH
  streams_per_session AS (
    SELECT
      *,
      ROW_NUMBER() OVER () AS conf_id,
      ts AS start_ts,
      LEAD(ts, 1) OVER (PARTITION BY session_id) AS end_ts
    FROM
      slice_per_session
    WHERE
      name = 'Camera3DeviceOpsDelegate::ConfigureStreams'
    ORDER BY
      session_id ASC, start_ts ASC
  )
SELECT
  *
FROM
  slice_per_session
LEFT JOIN
  streams_per_session
ON (
  slice_per_session.session_id = streams_per_session.session_id AND
  slice_per_session.ts >= streams_per_session.start_ts AND
  CASE
    WHEN streams_per_session.end_ts IS NULL
      THEN TRUE
    ELSE
      slice_per_session.ts < streams_per_session.end_ts
  END
);


DROP VIEW IF EXISTS request_streams;
CREATE VIEW request_streams AS
SELECT DISTINCT
  conf_id,
  EXTRACT_ARG(arg_set_id, 'debug.stream') AS stream_id,
  EXTRACT_ARG(arg_set_id, 'debug.width') AS width,
  EXTRACT_ARG(arg_set_id, 'debug.height') AS height,
  EXTRACT_ARG(arg_set_id, 'debug.format') AS format
FROM
  slice_per_session_with_stream_conf_id
WHERE
  name = 'Request Buffer'
ORDER BY
  conf_id ASC, stream_id ASC;


DROP VIEW IF EXISTS result_buffer_latencies;
CREATE VIEW result_buffer_latencies AS
SELECT
  conf_id,
  EXTRACT_ARG(arg_set_id, 'debug.stream') AS stream_id,
  EXTRACT_ARG(arg_set_id, 'debug.frame_number') AS frame_number,
  CAST(MIN(dur) / 1e3 AS INT) AS min_latency_us,
  CAST(AVG(dur) / 1e3 AS INT) AS avg_latency_us,
  CAST(MAX(dur) / 1e3 AS INT) AS max_latency_us
FROM
  slice_per_session_with_stream_conf_id
WHERE
  name = 'Result Buffer'
GROUP BY
  conf_id, stream_id
ORDER BY
  conf_id ASC, stream_id ASC;


DROP VIEW IF EXISTS stream_metrics_per_session;
CREATE VIEW stream_metrics_per_session AS
SELECT
  session_id,
  conf_id,
  CAST(
    AVG(CASE WHEN name = 'CameraDeviceAdapter::ConfigureStreams'
        THEN dur END) / 1e3 AS INT) AS e2e_conf_latency_us,
  CAST(
    AVG(CASE WHEN name = 'HAL::ConfigureStreams'
        THEN dur END) / 1e3 AS INT) AS hal_conf_latency_us,
  CAST(
    MIN(CASE WHEN name = 'CameraDeviceAdapter::ProcessCaptureRequest'
        THEN dur END) / 1e3 AS INT) AS min_e2e_req_latency_us,
  CAST(
    AVG(CASE WHEN name = 'CameraDeviceAdapter::ProcessCaptureRequest'
        THEN dur END) / 1e3 AS INT) AS avg_e2e_req_latency_us,
  CAST(
    MAX(CASE WHEN name = 'CameraDeviceAdapter::ProcessCaptureRequest'
        THEN dur END) / 1e3 AS INT) AS max_e2e_req_latency_us,
  CAST(
    MIN(CASE WHEN name = 'HAL::ProcessCaptureRequest'
        THEN dur END) / 1e3 AS INT) AS min_hal_req_latency_us,
  CAST(
    AVG(CASE WHEN name = 'HAL::ProcessCaptureRequest'
        THEN dur END) / 1e3 AS INT) AS avg_hal_req_latency_us,
  CAST(
    MAX(CASE WHEN name = 'HAL::ProcessCaptureRequest'
        THEN dur END) / 1e3 AS INT) AS max_hal_req_latency_us
FROM
  slice_per_session_with_stream_conf_id
WHERE
  conf_id NOT NULL
GROUP BY
  session_id, conf_id;


DROP VIEW IF EXISTS session_metrics;
CREATE VIEW session_metrics AS
WITH
  open AS (
    SELECT
      session_id,
      CAST(dur / 1e3 AS INT) AS dur_ns
    FROM slice_per_session
    WHERE name = 'CameraHalAdapter::OpenDevice'
  ),
  init AS (
    SELECT
      session_id,
      CAST(dur / 1e3 AS INT) AS dur_ns
    FROM slice_per_session
    WHERE name = 'HAL::Initialize'
  ),
  close AS (
    SELECT
      session_id,
      CAST(dur / 1e3 AS INT) AS dur_ns
    FROM slice_per_session
    WHERE name = 'HAL::Close'
  )
SELECT
  session_id,
  open.dur_ns AS open_latency_us,
  init.dur_ns AS init_latency_us,
  close.dur_ns AS close_latency_us
FROM
  open
LEFT JOIN
  init USING (session_id)
LEFT JOIN
  close USING (session_id);


DROP VIEW IF EXISTS camera_core_metrics_output;
CREATE VIEW camera_core_metrics_output AS
SELECT CameraCoreMetricsPerSession(
  'sessions', (
    SELECT RepeatedField(
      CameraCoreMetrics(
        'sid', session_id,
        'open_device_latency_us', open_latency_us,
        'initialize_latency_us', init_latency_us,
        'stream_metrics', (
          SELECT
            RepeatedField(
              CameraStreamMetrics(
                'e2e_configure_streams_latency_us', e2e_conf_latency_us,
                'hal_configure_streams_latency_us', hal_conf_latency_us,
                'min_e2e_request_latency_us', min_e2e_req_latency_us,
                'avg_e2e_request_latency_us', avg_e2e_req_latency_us,
                'max_e2e_request_latency_us', max_e2e_req_latency_us,
                'min_hal_request_latency_us', min_hal_req_latency_us,
                'avg_hal_request_latency_us', avg_hal_req_latency_us,
                'max_hal_request_latency_us', max_hal_req_latency_us,
                'result_buffer_metrics', (
                  SELECT
                    RepeatedField(
                      CaptureResultBufferMetrics(
                        'stream', Stream(
                          'stream_id', request_streams.stream_id,
                          'width', request_streams.width,
                          'height', request_streams.height,
                          'format', request_streams.format
                        ),
                        'min_e2e_latency_us', min_latency_us,
                        'avg_e2e_latency_us', avg_latency_us,
                        'max_e2e_latency_us', max_latency_us
                      )
                    )
                  FROM
                    result_buffer_latencies
                  JOIN
                    request_streams
                  USING
                    (conf_id, stream_id)
                  WHERE
                    result_buffer_latencies.conf_id =
                    stream_metrics_per_session.conf_id
                )
              )
            )
          FROM
            stream_metrics_per_session
          WHERE
            stream_metrics_per_session.session_id = session_metrics.session_id
          ORDER BY
            conf_id ASC
        ),
        'close_device_latency_us', close_latency_us
      )
    )
  )
)
FROM session_metrics;
