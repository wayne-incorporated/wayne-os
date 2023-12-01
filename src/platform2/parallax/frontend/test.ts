// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

export * from '@parallax/index';
import '@parallax/chart/line_chart_test';
import '@parallax/common/helpers_test';
import '@parallax/common/math_test';
import '@parallax/data/meta_test';
import '@parallax/data/save_html_test';
import '@parallax/interface/doc_test';
import {ParallaxError} from '@parallax/common/error';

// Print errors to the console
ParallaxError.enableLogs();
