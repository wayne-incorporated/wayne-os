# -*- coding: utf-8 -*-
# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Library providing access to the model configuration from the host"""

import os
import sys


this_dir = os.path.dirname(__file__)
sys.path.insert(0, this_dir)
sys.path.insert(0, os.path.join(this_dir, "../../../config/python/"))
