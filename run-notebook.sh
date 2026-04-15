#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

export MPLCONFIGDIR="$ROOT_DIR/.matplotlib"
export IPYTHONDIR="$ROOT_DIR/.ipython"
export XDG_CACHE_HOME="$ROOT_DIR/.cache"

mkdir -p "$MPLCONFIGDIR" "$IPYTHONDIR" "$XDG_CACHE_HOME"

source "$ROOT_DIR/.venv-notebook/bin/activate"
exec jupyter notebook "$ROOT_DIR/network_analyse.ipynb"
