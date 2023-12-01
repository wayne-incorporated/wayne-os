-- Copyright 2022 The ChromiumOS Authors
-- Use of this source code is governed by a BSD-style license that can be
-- found in the LICENSE file.

-- camera_sessions is a table of camera sessions identified by the pair of
-- OpenDevice (`open_ts` as the start of the device open) and CloseDevice
-- (`close_ts` as the end of the device close) timestamps.
DROP TABLE IF EXISTS camera_sessions;
CREATE TABLE camera_sessions AS
WITH camera_open_and_close AS (
  SELECT * FROM slice WHERE
    name = 'CameraHalAdapter::OpenDevice' OR
    name = 'Camera3DeviceOpsDelegate::Close'
  ORDER BY ts ASC)
SELECT
  ROW_NUMBER() OVER () AS session_id,
  ts AS open_ts,
  (SELECT MIN(ts + dur) FROM camera_open_and_close WHERE
     id > e.id AND name = 'Camera3DeviceOpsDelegate::Close'
  ) AS close_ts
FROM
  camera_open_and_close AS e
WHERE
  name = 'CameraHalAdapter::OpenDevice';


-- Add a pseudo camera session with session id 255 by including all the slices
-- if a trace is captured without camera open and close calls.
INSERT INTO camera_sessions (session_id, open_ts, close_ts)
SELECT
  255,
  (SELECT MIN(ts) FROM slice),
  (SELECT MAX(ts + dur) FROM slice)
WHERE NOT EXISTS (SELECT * FROM camera_sessions);


-- slice_per_session extracts the slices associated with each camera session in
-- the `camera_sessions` view.
DROP VIEW IF EXISTS slice_per_session;
CREATE VIEW slice_per_session AS
SELECT * FROM slice JOIN camera_sessions ON (
  slice.ts >= camera_sessions.open_ts AND slice.ts <= camera_sessions.close_ts);


-- PER_SESSION_SLICE_DURATION creates a view for the per-session min/avg/max
-- durations of the slice with name glob `slice_name_glob`.
SELECT CREATE_VIEW_FUNCTION(
  'PER_SESSION_SLICE_DURATION(slice_name_glob STRING)',
  'session_id INT, min_dur_us INT, avg_dur_us INT, max_dur_us INT',
  'SELECT
     session_id,
     CAST(MIN(dur) / 1e3 AS INT) AS min_dur_us,
     CAST(AVG(dur) / 1e3 AS INT) AS avg_dur_us,
     CAST(MAX(dur) / 1e3 AS INT) AS max_dur_us
   FROM
     slice_per_session
   WHERE
     name = $slice_name_glob
   GROUP BY
     session_id'
);
