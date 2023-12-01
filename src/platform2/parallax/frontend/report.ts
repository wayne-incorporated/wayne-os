// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

export * from '@parallax/index';
import {ParallaxError} from '@parallax/common/error';
import {newPlot} from '@parallax/interface/plot_row';

// Print errors to the console
ParallaxError.enableLogs();

window.onload = () => {
  console.log('Started');
  newPlot();
};

google.charts.load('current', {
  'packages': ['bar', 'controls', 'corechart', 'line', 'table', 'timeline'],
});

google.charts.setOnLoadCallback(() => {
  console.log('Charts loaded');
});
