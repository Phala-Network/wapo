#!/bin/sh
set -ex

if [ -d data ]; then
    echo "data directory already exists. Please remove it first."
    exit 1
fi
mkdir -p data/protected_files
mkdir -p data/storage_files
