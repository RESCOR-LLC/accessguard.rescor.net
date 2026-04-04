#!/bin/bash
# AccessGuard setup script
# Creates a virtual environment and installs selected provider dependencies.
#
# Usage:
#   ./scripts/setup.sh                  # all providers
#   ./scripts/setup.sh aws              # AWS only
#   ./scripts/setup.sh aws azure        # AWS + Azure
#   ./scripts/setup.sh --dev            # all providers + testing/CDK tools

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$PROJECT_DIR/.venv"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; }

# ─── Check Python ───────────────────────────────────────────────────
PYTHON=""
for candidate in python3.14 python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" &>/dev/null; then
        version=$("$candidate" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+')
        major=$(echo "$version" | cut -d. -f1)
        minor=$(echo "$version" | cut -d. -f2)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 9 ]; then
            PYTHON="$candidate"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    error "Python 3.9+ is required but not found."
    exit 1
fi

info "Using $PYTHON ($($PYTHON --version 2>&1))"

# ─── Parse arguments ────────────────────────────────────────────────
PROVIDERS=()
DEV=false

if [ $# -eq 0 ]; then
    PROVIDERS=(aws azure gcp)
else
    for arg in "$@"; do
        case "$arg" in
            --dev)   DEV=true ;;
            aws)     PROVIDERS+=(aws) ;;
            azure)   PROVIDERS+=(azure) ;;
            gcp)     PROVIDERS+=(gcp) ;;
            all)     PROVIDERS=(aws azure gcp) ;;
            *)       error "Unknown argument: $arg"; echo "Usage: $0 [aws] [azure] [gcp] [all] [--dev]"; exit 1 ;;
        esac
    done
fi

# If --dev but no providers, install all
if [ ${#PROVIDERS[@]} -eq 0 ] && [ "$DEV" = true ]; then
    PROVIDERS=(aws azure gcp)
fi

info "Providers: ${PROVIDERS[*]:-core only}"
[ "$DEV" = true ] && info "Dev/test tools: yes"

# ─── Check CSP CLI prerequisites ────────────────────────────────────
for provider in "${PROVIDERS[@]}"; do
    case "$provider" in
        azure)
            if ! command -v az &>/dev/null; then
                warn "Azure CLI (az) not found. Install: https://learn.microsoft.com/en-us/cli/azure/install-azure-cli"
                warn "Azure provider will be installed but you'll need 'az login' to authenticate."
            else
                info "Azure CLI found: $(az version --output tsv 2>/dev/null | head -1)"
            fi
            ;;
        gcp)
            if ! command -v gcloud &>/dev/null; then
                warn "Google Cloud CLI (gcloud) not found. Install: https://cloud.google.com/sdk/docs/install"
                warn "GCP provider will be installed but you'll need 'gcloud auth application-default login' to authenticate."
            else
                info "Google Cloud CLI found: $(gcloud version 2>/dev/null | head -1)"
            fi
            ;;
        aws)
            if ! command -v aws &>/dev/null; then
                warn "AWS CLI not found. Not strictly required (boto3 uses ~/.aws/credentials directly)."
            else
                info "AWS CLI found: $(aws --version 2>&1 | head -1)"
            fi
            ;;
    esac
done

# ─── Create virtual environment ─────────────────────────────────────
if [ -d "$VENV_DIR" ]; then
    info "Virtual environment exists at $VENV_DIR"
else
    info "Creating virtual environment at $VENV_DIR"
    "$PYTHON" -m venv "$VENV_DIR"
fi

# Activate
source "$VENV_DIR/bin/activate"
info "Activated venv ($(python3 --version))"

# Upgrade pip
pip install --upgrade pip --quiet

# ─── Install dependencies ───────────────────────────────────────────
info "Installing core dependencies..."
pip install -r "$PROJECT_DIR/requirements/core.txt" --quiet

for provider in "${PROVIDERS[@]}"; do
    info "Installing $provider provider dependencies..."
    pip install -r "$PROJECT_DIR/requirements/$provider.txt" --quiet
done

if [ "$DEV" = true ]; then
    info "Installing dev/test dependencies..."
    pip install -r "$PROJECT_DIR/requirements/dev.txt" --quiet
fi

# ─── Verify ─────────────────────────────────────────────────────────
echo ""
info "Verifying installation..."
python3 -c "
import sys
sys.path.insert(0, '$PROJECT_DIR/src')
from providers import available_providers
providers = available_providers()
print(f'  Available providers: {providers}')
if not providers:
    print('  WARNING: No providers registered (SDKs may not be installed)')
"

echo ""
info "Setup complete. To activate the environment:"
echo "  source $VENV_DIR/bin/activate"
echo ""
info "To run AccessGuard:"
echo "  python3 src/cli.py --provider aws"
echo "  python3 src/cli.py --provider azure --org"
echo "  python3 src/cli.py --provider gcp --org"
