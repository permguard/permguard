#!/bin/sh
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

set -eu

# Determine repository root
REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"

# Ensure required directories exist
mkdir -p "${REPO_ROOT}/.agents/skills"
mkdir -p "${REPO_ROOT}/.agents/rules"
mkdir -p "${REPO_ROOT}/.agents/tools"
mkdir -p "${REPO_ROOT}/.agents/scripts"
mkdir -p "${REPO_ROOT}/.agents/knowledge"
mkdir -p "${REPO_ROOT}/.claude"

# Set up the symlink for Claude skills
CLAUDESKILLS="${REPO_ROOT}/.claude/skills"
AGENTS_skills="${REPO_ROOT}/.agents/skills"

if [ -L "${CLAUDESKILLS}" ]; then
    # If it's a symlink, check if it points to the right place
    if [ "$(readlink "${CLAUDESKILLS}")" = "../.agents/skills" ]; then
        echo "Claude skills symlink is already correctly set"
    else
        # Replace the symlink
        rm "${CLAUDESKILLS}"
        ln -s ../.agents/skills "${CLAUDESKILLS}"
        echo "Replaced Claude skills symlink with correct path"
    fi
elif [ -d "${CLAUDESKILLS}" ]; then
    # If it exists as a directory, don't overwrite it
    echo "Error: .claude/skills exists as a directory. Please migrate its contents first."
    exit 1
elif [ -f "${CLAUDESKILLS}" ]; then
    # If it exists as a regular file, don't overwrite it
    echo "Error: .claude/skills exists as a file. Please migrate its contents first."
    exit 1
else
    # Create the symlink
    ln -s ../.agents/skills "${CLAUDESKILLS}"
    echo "Created Claude skills symlink"
fi

echo "LLM workspace initialized"
echo "Claude skills: .claude/skills -> ../.agents/skills"
echo "OpenCode skills: .agents/skills"
echo "Shared instructions: AGENTS.md"