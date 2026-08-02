#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

container_user=${1:-${USER:-user}}
source_path=${2:-}
user_home=$(getent passwd "$container_user" | cut -d: -f6)
if [ -z "$user_home" ]; then
    echo "could not find home directory for $container_user" >&2
    exit 1
fi

destination=${RUMPELPOD_AGENT_ENVIRONMENT_FILE:-$user_home/.config/rumpelpod/agent-environment}
destination_dir=$(dirname "$destination")
owner_group=$(id -gn "$container_user")
install -d -m 700 -o "$container_user" -g "$owner_group" "$destination_dir"
temp_file=$(mktemp "${destination}.XXXXXX")
chmod 600 "$temp_file"

cleanup() {
    if [ -n "$temp_file" ] && [ -e "$temp_file" ]; then
        if ! rm -f "$temp_file"; then
            echo "could not remove staged agent environment $temp_file" >&2
        fi
    fi
}
trap cleanup EXIT

declare -A allowed=(
    [ANTHROPIC_API_KEY]=1
    [GEMINI_API_KEY]=1
    [OPENAI_API_KEY]=1
    [XAI_API_KEY]=1
)

write_entry() {
    local entry=$1
    local name=${entry%%=*}
    local value=${entry#*=}
    if [[ ! -v "allowed[$name]" ]]; then
        return
    fi
    if [[ "$value" == *$'\n'* || "$value" == *$'\r'* ]]; then
        echo "$name contains a newline and cannot be written to a systemd environment file" >&2
        exit 1
    fi
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    printf '%s="%s"\n' "$name" "$value" >> "$temp_file"
}

if [ -n "$source_path" ]; then
    while IFS= read -r -d '' entry; do
        write_entry "$entry"
    done < "$source_path"
else
    for name in "${!allowed[@]}"; do
        if [[ -v "$name" ]]; then
            write_entry "$name=${!name}"
        fi
    done
fi

chown "$container_user:$owner_group" "$temp_file"
mv -f "$temp_file" "$destination"
temp_file=
