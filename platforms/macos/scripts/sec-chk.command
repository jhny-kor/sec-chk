#!/bin/zsh
set -euo pipefail

# Compatibility filename for existing shortcuts; KODA.command is canonical.
exec "${0:A:h}/koda.command" "$@"
