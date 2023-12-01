-- Copyright 2022 The ChromiumOS Authors
-- Use of this source code is governed by a BSD-style license that can be
-- found in the LICENSE file.

SELECT RUN_METRIC('camera_sessions.sql');


-- `ae_states` extracts all the AE state transition events with the event
-- starting frame number.
DROP VIEW IF EXISTS ae_states;
CREATE VIEW ae_states AS
SELECT
  session_id,
  slice_per_session.name,
  ts,
  EXTRACT_ARG(arg_set_id, 'debug.frame_number') AS start_frame
FROM
  slice_per_session JOIN track ON slice_per_session.track_id == track.id
WHERE
  track.name = 'AE state'
ORDER BY
  session_id ASC, ts ASC;


-- `ae_conv_durations` computes the duration in frames of each AE state.
-- Duration of the Converged state is ignored.
DROP VIEW IF EXISTS ae_conv_durations;
CREATE VIEW ae_conv_durations AS
SELECT
  session_id,
  name,
  ts,
  LEAD(start_frame, 1, 0) OVER (PARTITION BY session_id ORDER BY ts ASC) -
    (CASE WHEN name = "Converged" THEN 0 ELSE start_frame END) AS dur_frames
FROM
  ae_states;


-- `ae_conv_spans` is a view that assigns a unique sequence id to each AE
-- convergence time span.
DROP VIEW IF EXISTS ae_conv_spans;
CREATE VIEW ae_conv_spans AS
SELECT
  session_id,
  ROW_NUMBER() OVER () AS span_id,
  LAG(ts, 1, 0) OVER (PARTITION BY session_id ORDER BY ts ASC) AS start_ts,
  ts AS end_ts
FROM
  ae_states
WHERE
  name = "Converged"
ORDER BY
  session_id ASC, ts ASC;


-- `ae_conv_durations_by_span` is a view that associates each convergence time
-- span with its convergence latency in number of frames.
DROP VIEW IF EXISTS ae_conv_durations_by_span;
CREATE VIEW ae_conv_durations_by_span AS
SELECT
  DISTINCT(span_id),
  ae_conv_durations.session_id,
  SUM(dur_frames) OVER (PARTITION BY span_id) AS dur_frames
FROM
  ae_conv_durations JOIN ae_conv_spans
ON
  ae_conv_durations.session_id = ae_conv_spans.session_id AND
  ae_conv_durations.ts > ae_conv_spans.start_ts AND
  ae_conv_durations.ts <= ae_conv_spans.end_ts
ORDER BY
  ae_conv_durations.session_id ASC, ts ASC;


DROP VIEW IF EXISTS gcam_ae_metrics_output;
CREATE VIEW gcam_ae_metrics_output AS
SELECT GcamAeMetricsPerSession(
  'sessions', (
    SELECT RepeatedField(
      GcamAeMetrics(
        'sid', session_id,
        'avg_process_latency_us', run_state.avg_dur_us,
        'gcam_ae_convergence', (
          SELECT RepeatedField(
            GcamAeConvergence("latency_frames", dur_frames)
          )
          FROM ae_conv_durations_by_span
          WHERE session_id = run_state.session_id
          ORDER BY span_id ASC
        )
      )
    )
  )
)
FROM
  PER_SESSION_SLICE_DURATION('GcamAe::Run') AS run_state;
