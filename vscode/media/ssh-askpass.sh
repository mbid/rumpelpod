#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

if [ -z "${RUMPELPOD_VSCODE_SSH_PASSPHRASE+x}" ]; then
    printf '%s\n' "SSH key passphrase required" >&2
    exit 1
fi

printf '%s\n' "$RUMPELPOD_VSCODE_SSH_PASSPHRASE"
