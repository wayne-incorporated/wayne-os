// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import {Chart} from '@parallax/chart/chart';
import {iterableMap, iterableArray} from '@parallax/common/helpers';
import {MetaMap, MetaMapSet} from '@parallax/data/meta';

let charts: Chart[] = [];

/**
 * Add another item to the manager.
 * TODO (bnemec): Replace mock.
 *
 * @param chart Chart which will be added.
 */
export function addChart(chart: Chart) {
  charts.push(chart);
}

/**
 * Add another item to the manager.
 * TODO (bnemec): Replace mock.
 *
 * @param chart Chart which will be added.
 */
export function updateChart(chart: Chart) {
  if (charts.length === 0) {
    charts.push(chart);
  } else {
    charts[0] = chart;
  }
}

/**
 * Simple function to grab a chart.
 *
 * TODO (bnemec): Replace mock.
 * @return A chart.
 */
export function getChart() {
  return charts[0];
}
