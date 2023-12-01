# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

srcs-y += hwsec_ta.c

srcs-y += hwsec_ta_service.c
srcs-y += hwsec_session.c
srcs-y += hwsec_cmd.c
srcs-y += hwsec_space.c

srcs-y += ../../third_party/tpm2/tpm_generated.c
