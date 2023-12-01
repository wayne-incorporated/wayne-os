-- Copyright 2022 The ChromiumOS Authors
-- Use of this source code is governed by a BSD-style license that can be
-- found in the LICENSE file.

SELECT RUN_METRIC('camera_sessions.sql');

DROP VIEW IF EXISTS hdrnet_metrics_output;
CREATE VIEW hdrnet_metrics_output AS
SELECT HdrNetMetricsPerSession(
  'sessions', (
    SELECT RepeatedField(
      HdrNetMetrics(
        'sid', session_id,
        'setup_latency_us', setup.avg_dur_us,
        'avg_preprocess_latency_us', preprocess.avg_dur_us,
        'avg_hdrnet_processor_latency_us', rgb_pipeline.avg_dur_us,
        'avg_postprocess_latency_us', postprocess.avg_dur_us
      )
    )
  )
)
FROM
  PER_SESSION_SLICE_DURATION(
    'HdrNetProcessor::LinearRgbPipeline') AS rgb_pipeline
LEFT JOIN
  PER_SESSION_SLICE_DURATION('HdrNetProcessor::Preprocess') AS preprocess
USING (session_id)
LEFT JOIN
  PER_SESSION_SLICE_DURATION('HdrNetProcessor::Postprocess') AS postprocess
USING (session_id)
LEFT JOIN
  PER_SESSION_SLICE_DURATION(
    'HdrNetStreamManipulator::SetUpPipelineOnGpuThread') AS setup
USING (session_id);
