#!/bin/sh
# One-line install:
#   curl -fsSL https://raw.githubusercontent.com/midwest-data/phi-airgap/main/install.sh | sh
#
# Env knobs:
#   PHI_AIRGAP_EXTRAS=ner,databricks   optional extras (default: core only)
#   PHI_AIRGAP_REF=<branch|tag|sha>    git ref to install (default: main)
set -eu

REPO="https://github.com/midwest-data/phi-airgap"
REF="${PHI_AIRGAP_REF:-main}"
EXTRAS="${PHI_AIRGAP_EXTRAS:-}"

say() { printf 'phi-airgap: %s\n' "$*"; }

# ponytail: uv brings its own Python 3.12, so no system-python wrangling here.
if ! command -v uv >/dev/null 2>&1; then
  say "installing uv (https://docs.astral.sh/uv/)"
  curl -fsSL https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
fi

SPEC="phi-airgap"
[ -n "$EXTRAS" ] && SPEC="phi-airgap[$EXTRAS]"

say "installing $SPEC from $REPO@$REF"
uv tool install --force --python 3.12 "$SPEC @ git+$REPO@$REF"

BIN_DIR="$(uv tool dir --bin)"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) say "add $BIN_DIR to your PATH (or run: uv tool update-shell)" ;;
esac

say "done. next: phi-airgap init && phi-airgap doctor"
