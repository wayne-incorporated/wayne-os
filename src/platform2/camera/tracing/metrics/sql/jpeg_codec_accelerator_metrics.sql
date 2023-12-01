-- Copyright 2023 The ChromiumOS Authors
-- Use of this source code is governed by a BSD-style license that can be
-- found in the LICENSE file.

SELECT RUN_METRIC('camera_sessions.sql');


DROP VIEW IF EXISTS jea_slice;
CREATE VIEW jea_slice AS
SELECT
  session_id,
  EXTRACT_ARG(arg_set_id, "debug.width") AS width,
  EXTRACT_ARG(arg_set_id, "debug.height") AS height,
  CAST(MIN(dur) / 1e3 AS INT) AS min_dur_us,
  CAST(AVG(dur) / 1e3 AS INT) AS avg_dur_us,
  CAST(MAX(dur) / 1e3 AS INT) AS max_dur_us
FROM
  slice_per_session
WHERE
  name = 'JpegEncodeAcceleratorImpl::EncodeSync'
GROUP BY
  session_id, width, height;


DROP VIEW IF EXISTS jda_slice;
CREATE VIEW jda_slice AS
SELECT
  session_id,
  EXTRACT_ARG(arg_set_id, "debug.width") AS width,
  EXTRACT_ARG(arg_set_id, "debug.height") AS height,
  CAST(MIN(dur) / 1e3 AS INT) AS min_dur_us,
  CAST(AVG(dur) / 1e3 AS INT) AS avg_dur_us,
  CAST(MAX(dur) / 1e3 AS INT) AS max_dur_us
FROM
  slice_per_session
WHERE
  name = 'JpegDecodeAcceleratorImpl::DecodeSync'
GROUP BY
  session_id, width, height;


DROP VIEW IF EXISTS jpeg_codec_accelerator_metrics_output;
CREATE VIEW jpeg_codec_accelerator_metrics_output AS
SELECT JpegCodecAcceleratorMetricsPerSession(
  'sessions', (
    SELECT RepeatedField(
      JpegCodecAcceleratorMetrics(
        'sid', session_id,
        'jea_metrics', (
          SELECT
            RepeatedField(
              JpegEncodeAcceleratorMetrics(
                'width', width,
                'height', height,
                'min_encode_latency_us', min_dur_us,
                'avg_encode_latency_us', avg_dur_us,
                'max_encode_latency_us', max_dur_us
              )
            )
          FROM
            jea_slice
          WHERE
            jea_slice.session_id = camera_sessions.session_id
        ),
        'jda_metrics', (
          SELECT
            RepeatedField(
              JpegDecodeAcceleratorMetrics(
                'width', width,
                'height', height,
                'min_decode_latency_us', min_dur_us,
                'avg_decode_latency_us', avg_dur_us,
                'max_decode_latency_us', max_dur_us
              )
            )
          FROM
            jda_slice
          WHERE
            jda_slice.session_id = camera_sessions.session_id
        )
      )
    )
  )
)
FROM
  camera_sessions;
