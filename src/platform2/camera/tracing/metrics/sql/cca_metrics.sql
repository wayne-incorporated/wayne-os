-- Copyright 2022 The ChromiumOS Authors
-- Use of this source code is governed by a BSD-style license that can be
-- found in the LICENSE file.

DROP VIEW IF EXISTS cca_mode_switching_slices;
CREATE VIEW cca_mode_switching_slices AS
SELECT
  CAST(slice.dur / 1e6 AS INT64) AS switching_latency_ms
FROM
  slice
WHERE
  name = 'mode-switching';


DROP VIEW IF EXISTS cca_metrics_output;
CREATE VIEW cca_metrics_output AS
SELECT CcaMetrics(
  'mode_switching', (
    SELECT RepeatedField(
      ModeSwitching(
          'latency_ms', switching_latency_ms
      )
    )
  )
)
FROM cca_mode_switching_slices;
