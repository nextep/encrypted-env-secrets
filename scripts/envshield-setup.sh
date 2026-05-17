#!/usr/bin/env bash
# ============================================================================
# envshield-setup.sh — Interactive Setup Wizard for EnvShield (Linux)
#
# Walks the user through:
#   1. Selecting a key storage backend (TPM 2.0, OS Keyring, CI/CD env var)
#   2. Generating or importing a master key
#   3. Encrypting a .env file or individual service tokens
#   4. Configuring optional integrations (Git credential helper)
#
# Requirements: Python 3, OpenSSL (libcrypto)
# Optional:     tpm2-tools, secret-tool, libsecret
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Colors & helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

ENVSHIELD_DIR="$HOME/.envshield"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI="$SCRIPT_DIR/cli/envshield-cli.py"

banner() {
    echo ""
    echo -e "${CYAN}${BOLD}"
    echo "  ┌───────────────────────────────────────────────┐"
    echo "  │           EnvShield Setup Wizard               │"
    echo "  │   Zero-dependency JIT encryption for secrets   │"
    echo "  └───────────────────────────────────────────────┘"
    echo -e "${RESET}"
}

info()    { echo -e "  ${GREEN}[✓]${RESET} $1"; }
warn()    { echo -e "  ${YELLOW}[!]${RESET} $1"; }
error()   { echo -e "  ${RED}[✗]${RESET} $1"; }
step()    { echo -e "\n  ${CYAN}${BOLD}── $1 ──${RESET}"; }
prompt()  { echo -en "  ${BOLD}$1${RESET}"; }

# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------
detect_backends() {
    HAS_TPM=false
    HAS_KEYRING=false
    HAS_PYTHON=false
    TPM_DEVICE=""

    # Python 3
    if command -v python3 &>/dev/null; then
        HAS_PYTHON=true
    fi

    # TPM 2.0
    if [ -e /dev/tpmrm0 ]; then
        TPM_DEVICE="/dev/tpmrm0"
    elif [ -e /dev/tpm0 ]; then
        TPM_DEVICE="/dev/tpm0"
    fi

    if [ -n "$TPM_DEVICE" ] && command -v tpm2_createprimary &>/dev/null; then
        HAS_TPM=true
    fi

    # secret-tool (GNOME Keyring / KDE Wallet)
    if command -v secret-tool &>/dev/null; then
        HAS_KEYRING=true
    fi
}

show_detection() {
    step "System Detection"

    if $HAS_PYTHON; then
        info "Python 3 found: $(python3 --version 2>&1)"
    else
        error "Python 3 not found. Please install python3."
        exit 1
    fi

    # Check libcrypto
    if python3 -c "import ctypes.util; assert ctypes.util.find_library('crypto')" 2>/dev/null; then
        info "libcrypto (OpenSSL) found"
    else
        error "libcrypto not found. Please install libssl-dev."
        exit 1
    fi

    if $HAS_TPM; then
        info "TPM 2.0 detected at $TPM_DEVICE (tpm2-tools installed)"
    else
        if [ -n "$TPM_DEVICE" ]; then
            warn "TPM device found at $TPM_DEVICE but tpm2-tools not installed"
            echo -e "      ${DIM}Install with: sudo apt install tpm2-tools${RESET}"
        else
            echo -e "  ${DIM}[–]${RESET} No TPM 2.0 device detected"
        fi
    fi

    if $HAS_KEYRING; then
        info "OS Keyring available (secret-tool)"
    else
        warn "secret-tool not found — OS Keyring unavailable"
        echo -e "      ${DIM}Install with: sudo apt install libsecret-tools${RESET}"
    fi
}

# ---------------------------------------------------------------------------
# Mode selection
# ---------------------------------------------------------------------------
select_mode() {
    step "Select Key Storage Mode"
    echo ""
    echo -e "  Choose where to store your master encryption key:"
    echo ""

    local n=1

    if $HAS_TPM; then
        echo -e "  ${BOLD}$n)${RESET} ${GREEN}TPM 2.0 (Hardware)${RESET} — Strongest. Key is sealed to the chip."
        echo -e "     ${DIM}Cannot be extracted even if disk is cloned.${RESET}"
        TPM_OPTION=$n
        n=$((n + 1))
    else
        TPM_OPTION=0
    fi

    if $HAS_KEYRING; then
        echo -e "  ${BOLD}$n)${RESET} ${CYAN}OS Keyring (Software)${RESET} — GNOME Keyring / KDE Wallet."
        echo -e "     ${DIM}Encrypted by the OS, unlocked with your login session.${RESET}"
        KEYRING_OPTION=$n
        n=$((n + 1))
    else
        KEYRING_OPTION=0
    fi

    echo -e "  ${BOLD}$n)${RESET} ${YELLOW}CI/CD Environment Variable${RESET} — For GitHub Actions, GitLab CI, Jenkins."
    echo -e "     ${DIM}Key is passed via ENV_SHIELD_KEY and auto-wiped from memory.${RESET}"
    CICD_OPTION=$n
    n=$((n + 1))

    echo -e "  ${BOLD}$n)${RESET} ${DIM}File-based (Development only)${RESET} — Writes env-shield.key to disk."
    echo -e "     ${DIM}Not recommended for production.${RESET}"
    FILE_OPTION=$n

    echo ""
    prompt "Enter choice [1-$n]: "
    read -r choice

    SELECTED_MODE=""
    if [ "$choice" = "$TPM_OPTION" ] 2>/dev/null; then
        SELECTED_MODE="tpm"
    elif [ "$choice" = "$KEYRING_OPTION" ] 2>/dev/null; then
        SELECTED_MODE="keyring"
    elif [ "$choice" = "$CICD_OPTION" ] 2>/dev/null; then
        SELECTED_MODE="cicd"
    elif [ "$choice" = "$FILE_OPTION" ] 2>/dev/null; then
        SELECTED_MODE="file"
    else
        error "Invalid selection."
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Key generation / import
# ---------------------------------------------------------------------------
handle_key() {
    step "Master Key Setup"
    echo ""
    echo -e "  ${BOLD}1)${RESET} Generate a new 256-bit key (recommended)"
    echo -e "  ${BOLD}2)${RESET} Import an existing key (hex string)"
    echo ""
    prompt "Enter choice [1-2]: "
    read -r key_choice

    if [ "$key_choice" = "2" ]; then
        echo ""
        prompt "Paste your 64-character hex key: "
        read -r MASTER_KEY_HEX
        if [ ${#MASTER_KEY_HEX} -ne 64 ]; then
            error "Key must be exactly 64 hex characters (32 bytes)."
            exit 1
        fi
        # Validate hex
        if ! echo "$MASTER_KEY_HEX" | grep -qE '^[0-9a-fA-F]{64}$'; then
            error "Invalid hex string."
            exit 1
        fi
        info "Custom key accepted."
    else
        MASTER_KEY_HEX=$(python3 -c "import os; print(os.urandom(32).hex())")
        info "Generated new 256-bit master key."
    fi
}

store_key() {
    step "Storing Master Key"

    case "$SELECTED_MODE" in
        tpm)
            info "Sealing key into TPM 2.0..."
            mkdir -p "$ENVSHIELD_DIR/tpm/envshield"

            local svc_dir="$ENVSHIELD_DIR/tpm/envshield"
            local primary_ctx="$svc_dir/primary.ctx"
            local key_pub="$svc_dir/key.pub"
            local key_priv="$svc_dir/key.priv"
            local key_ctx="$svc_dir/key.ctx"
            local data_file="$svc_dir/data.bin"

            echo -n "$MASTER_KEY_HEX" > "$data_file"
            chmod 600 "$data_file"

            tpm2_createprimary -C o -c "$primary_ctx" 2>/dev/null
            tpm2_create -C "$primary_ctx" -i "$data_file" -u "$key_pub" -r "$key_priv" 2>/dev/null
            tpm2_load -C "$primary_ctx" -u "$key_pub" -r "$key_priv" -c "$key_ctx" 2>/dev/null

            rm -f "$data_file" "$primary_ctx"

            info "Master key sealed to TPM."
            echo -e "     ${DIM}Sealed blobs: $key_pub, $key_priv${RESET}"
            echo -e "     ${DIM}These files are useless without this machine's TPM chip.${RESET}"
            ;;
        keyring)
            info "Storing key in OS Keyring..."
            echo -n "$MASTER_KEY_HEX" | secret-tool store --label='EnvShield Master Key' service envshield 2>/dev/null
            info "Master key stored in OS Keyring under 'envshield'."
            ;;
        cicd)
            info "CI/CD mode selected."
            echo ""
            echo -e "  ${BOLD}Add this secret to your CI/CD provider:${RESET}"
            echo ""
            echo -e "    ${CYAN}Name:${RESET}  ENV_SHIELD_KEY"
            echo -e "    ${CYAN}Value:${RESET} $MASTER_KEY_HEX"
            echo ""
            echo -e "  ${DIM}GitHub:  Settings → Secrets → Actions → New repository secret${RESET}"
            echo -e "  ${DIM}GitLab:  Settings → CI/CD → Variables → Add variable${RESET}"
            echo -e "  ${DIM}Jenkins: Manage Jenkins → Credentials → Add${RESET}"
            echo ""
            warn "Copy this key now. It will not be shown again."
            echo ""
            prompt "Press Enter when you've saved the key..."
            read -r
            ;;
        file)
            mkdir -p "$ENVSHIELD_DIR"
            local key_file="$ENVSHIELD_DIR/env-shield.key"
            echo -n "$MASTER_KEY_HEX" > "$key_file"
            chmod 600 "$key_file"
            info "Master key written to $key_file"
            warn "Do NOT commit this file. Add it to .gitignore."
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Encryption workflow
# ---------------------------------------------------------------------------
encrypt_workflow() {
    step "Encrypt Secrets"
    echo ""
    echo -e "  ${BOLD}1)${RESET} Encrypt an entire .env file"
    echo -e "  ${BOLD}2)${RESET} Encrypt a single service token (GitHub, AWS, NPM, etc.)"
    echo -e "  ${BOLD}3)${RESET} Skip — I'll encrypt later"
    echo ""
    prompt "Enter choice [1-3]: "
    read -r enc_choice

    local file_flag=""
    if [ "$SELECTED_MODE" = "file" ]; then
        file_flag="--file"
    fi

    case "$enc_choice" in
        1)
            echo ""
            prompt "Path to .env file [.env]: "
            read -r env_path
            env_path="${env_path:-.env}"

            if [ ! -f "$env_path" ]; then
                error "File not found: $env_path"
                return
            fi

            if [ "$SELECTED_MODE" = "cicd" ] || [ "$SELECTED_MODE" = "file" ]; then
                python3 "$CLI" --file "$env_path"
            else
                python3 "$CLI" "$env_path"
            fi

            info "Encrypted → .env.enc"
            ;;
        2)
            echo ""
            prompt "Service name (e.g., github, aws, npm): "
            read -r svc_name
            prompt "Token value: "
            read -rs token_val
            echo ""

            if [ "$SELECTED_MODE" = "cicd" ] || [ "$SELECTED_MODE" = "file" ]; then
                python3 "$CLI" --store "$svc_name" "$token_val" --file
            else
                python3 "$CLI" --store "$svc_name" "$token_val"
            fi
            ;;
        3)
            info "Skipped. You can encrypt later with:"
            echo -e "     ${DIM}python3 cli/envshield-cli.py .env${RESET}"
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Git credential helper setup
# ---------------------------------------------------------------------------
git_integration() {
    step "Git Credential Helper (Optional)"
    echo ""
    echo -e "  Configure EnvShield as a Git credential helper?"
    echo -e "  ${DIM}This decrypts your GitHub/GitLab PAT JIT for git push/pull.${RESET}"
    echo ""
    prompt "Set up Git integration? [y/N]: "
    read -r git_choice

    if [[ "$git_choice" =~ ^[Yy] ]]; then
        local helper_path="$SCRIPT_DIR/cli/git-credential-envshield.py"
        git config --global credential.helper "/usr/bin/env python3 $helper_path"
        info "Git credential helper configured."
        echo -e "     ${DIM}git config --global credential.helper \"...\"${RESET}"

        # Check if a GitHub token is already stored
        if [ ! -f "$ENVSHIELD_DIR/github.enc" ]; then
            echo ""
            prompt "Store a GitHub PAT now? [y/N]: "
            read -r pat_choice
            if [[ "$pat_choice" =~ ^[Yy] ]]; then
                prompt "GitHub PAT: "
                read -rs github_pat
                echo ""
                if [ "$SELECTED_MODE" = "file" ] || [ "$SELECTED_MODE" = "cicd" ]; then
                    python3 "$CLI" --store github "$github_pat" --file
                else
                    python3 "$CLI" --store github "$github_pat"
                fi
            fi
        else
            info "GitHub token already provisioned."
        fi
    else
        info "Skipped."
    fi
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
show_summary() {
    step "Setup Complete"
    echo ""
    echo -e "  ${GREEN}${BOLD}EnvShield is ready.${RESET}"
    echo ""
    echo -e "  ${BOLD}Storage mode:${RESET} $SELECTED_MODE"
    echo -e "  ${BOLD}Config dir:${RESET}   $ENVSHIELD_DIR"
    echo ""
    echo -e "  ${BOLD}Quick Reference:${RESET}"
    echo -e "     ${DIM}# Encrypt a .env file${RESET}"
    echo -e "     python3 cli/envshield-cli.py .env"
    echo ""
    echo -e "     ${DIM}# Store a service token${RESET}"
    echo -e "     python3 cli/envshield-cli.py --store aws \"AKIA...\""
    echo ""
    echo -e "     ${DIM}# Use in Python${RESET}"
    echo -e "     import envshield"
    echo -e "     os.environ['SECRET_API_KEY']  # decrypted JIT"
    echo ""
    echo -e "     ${DIM}# Use in Node.js${RESET}"
    echo -e "     require('./envshield')"
    echo -e "     process.env.SECRET_API_KEY  // decrypted JIT"
    echo ""
    echo -e "     ${DIM}# Build C library${RESET}"
    echo -e "     make && make test"
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    banner
    detect_backends
    show_detection
    select_mode
    handle_key
    store_key
    encrypt_workflow
    git_integration
    show_summary
}

main "$@"
