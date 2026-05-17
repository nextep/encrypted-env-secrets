# ============================================================================
# envshield-setup.ps1 — Interactive Setup Wizard for EnvShield (Windows)
#
# Walks the user through:
#   1. Selecting a key storage backend (Windows Credential Locker, CI/CD, File)
#   2. Generating or importing a master key
#   3. Encrypting a .env file or individual service tokens
#   4. Configuring optional integrations (Git credential helper)
#
# Requirements: Python 3, OpenSSL (libcrypto) via vcpkg or prebuilt
# Usage:        powershell -ExecutionPolicy Bypass -File envshield-setup.ps1
# ============================================================================

$ErrorActionPreference = "Stop"

$ENVSHIELD_DIR = "$env:USERPROFILE\.envshield"
$SCRIPT_DIR    = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$CLI           = Join-Path $SCRIPT_DIR "cli\envshield-cli.py"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Banner {
    Write-Host ""
    Write-Host "  ┌───────────────────────────────────────────────┐" -ForegroundColor Cyan
    Write-Host "  │           EnvShield Setup Wizard               │" -ForegroundColor Cyan
    Write-Host "  │   Zero-dependency JIT encryption for secrets   │" -ForegroundColor Cyan
    Write-Host "  └───────────────────────────────────────────────┘" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Info  { param($Msg) Write-Host "  [✓] $Msg" -ForegroundColor Green }
function Write-Warn  { param($Msg) Write-Host "  [!] $Msg" -ForegroundColor Yellow }
function Write-Err   { param($Msg) Write-Host "  [✗] $Msg" -ForegroundColor Red }
function Write-Step  { param($Msg) Write-Host "`n  ── $Msg ──" -ForegroundColor Cyan }

# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------
function Test-Python {
    try {
        $ver = & python --version 2>&1
        Write-Info "Python found: $ver"
        return $true
    } catch {
        try {
            $ver = & python3 --version 2>&1
            Write-Info "Python found: $ver"
            return $true
        } catch {
            Write-Err "Python 3 not found. Please install from python.org."
            return $false
        }
    }
}

function Get-PythonCmd {
    # Return the working python command
    try {
        & python --version 2>&1 | Out-Null
        return "python"
    } catch {
        return "python3"
    }
}

function Test-CredentialLocker {
    # Windows Credential Locker is always available via advapi32.dll
    # on Windows Vista+ (effectively all supported Windows)
    try {
        Add-Type -AssemblyName System.Runtime.InteropServices 2>$null
        return $true
    } catch {
        return $false
    }
}

# ---------------------------------------------------------------------------
# Mode selection
# ---------------------------------------------------------------------------
function Select-Mode {
    Write-Step "Select Key Storage Mode"
    Write-Host ""
    Write-Host "  Choose where to store your master encryption key:"
    Write-Host ""
    Write-Host "  1) " -NoNewline -ForegroundColor White
    Write-Host "Windows Credential Locker" -NoNewline -ForegroundColor Green
    Write-Host " — Encrypted by the OS, unlocked with your Windows login."
    Write-Host "     " -NoNewline
    Write-Host "Backed by advapi32.dll (CredWriteW/CredReadW)." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  2) " -NoNewline -ForegroundColor White
    Write-Host "CI/CD Environment Variable" -NoNewline -ForegroundColor Yellow
    Write-Host " — For GitHub Actions, GitLab CI, Jenkins."
    Write-Host "     " -NoNewline
    Write-Host "Key is passed via ENV_SHIELD_KEY and auto-wiped from memory." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  3) " -NoNewline -ForegroundColor White
    Write-Host "File-based (Development only)" -ForegroundColor DarkGray
    Write-Host "     " -NoNewline
    Write-Host "Writes env-shield.key to disk. Not recommended for production." -ForegroundColor DarkGray
    Write-Host ""

    $choice = Read-Host "  Enter choice [1-3]"
    switch ($choice) {
        "1" { return "credlocker" }
        "2" { return "cicd" }
        "3" { return "file" }
        default {
            Write-Err "Invalid selection."
            exit 1
        }
    }
}

# ---------------------------------------------------------------------------
# Key generation / import
# ---------------------------------------------------------------------------
function Get-MasterKey {
    Write-Step "Master Key Setup"
    Write-Host ""
    Write-Host "  1) Generate a new 256-bit key (recommended)"
    Write-Host "  2) Import an existing key (hex string)"
    Write-Host ""

    $choice = Read-Host "  Enter choice [1-2]"

    if ($choice -eq "2") {
        Write-Host ""
        $hexKey = Read-Host "  Paste your 64-character hex key"
        if ($hexKey.Length -ne 64) {
            Write-Err "Key must be exactly 64 hex characters (32 bytes)."
            exit 1
        }
        if ($hexKey -notmatch '^[0-9a-fA-F]{64}$') {
            Write-Err "Invalid hex string."
            exit 1
        }
        Write-Info "Custom key accepted."
        return $hexKey
    } else {
        $pyCmd = Get-PythonCmd
        $hexKey = & $pyCmd -c "import os; print(os.urandom(32).hex())"
        Write-Info "Generated new 256-bit master key."
        return $hexKey
    }
}

# ---------------------------------------------------------------------------
# Key storage
# ---------------------------------------------------------------------------
function Store-Key {
    param($Mode, $KeyHex)

    Write-Step "Storing Master Key"

    switch ($Mode) {
        "credlocker" {
            Write-Info "Storing key in Windows Credential Locker..."

            # Use cmdkey.exe which is available on all Windows versions
            $target  = "envshield"
            $user    = "envshield"

            # cmdkey stores generic credentials
            & cmdkey /generic:$target /user:$user /pass:$KeyHex 2>$null

            if ($LASTEXITCODE -eq 0) {
                Write-Info "Master key stored in Windows Credential Locker."
            } else {
                Write-Warn "cmdkey failed. Trying PowerShell approach..."
                # Fallback: write to encrypted DPAPI file
                $securePath = Join-Path $ENVSHIELD_DIR "envshield.key.dpapi"
                New-Item -ItemType Directory -Force -Path $ENVSHIELD_DIR | Out-Null
                $KeyHex | ConvertTo-SecureString -AsPlainText -Force |
                    ConvertFrom-SecureString | Out-File $securePath
                Write-Info "Key stored with DPAPI encryption at $securePath"
            }
        }
        "cicd" {
            Write-Info "CI/CD mode selected."
            Write-Host ""
            Write-Host "  Add this secret to your CI/CD provider:" -ForegroundColor White
            Write-Host ""
            Write-Host "    Name:  " -NoNewline -ForegroundColor Cyan
            Write-Host "ENV_SHIELD_KEY"
            Write-Host "    Value: " -NoNewline -ForegroundColor Cyan
            Write-Host $KeyHex
            Write-Host ""
            Write-Host "    GitHub:  Settings → Secrets → Actions → New repository secret" -ForegroundColor DarkGray
            Write-Host "    GitLab:  Settings → CI/CD → Variables → Add variable" -ForegroundColor DarkGray
            Write-Host "    Jenkins: Manage Jenkins → Credentials → Add" -ForegroundColor DarkGray
            Write-Host ""
            Write-Warn "Copy this key now. It will not be shown again."
            Read-Host "  Press Enter when you've saved the key"
        }
        "file" {
            New-Item -ItemType Directory -Force -Path $ENVSHIELD_DIR | Out-Null
            $keyFile = Join-Path $ENVSHIELD_DIR "env-shield.key"
            Set-Content -Path $keyFile -Value $KeyHex -NoNewline
            Write-Info "Master key written to $keyFile"
            Write-Warn "Do NOT commit this file. Add it to .gitignore."
        }
    }
}

# ---------------------------------------------------------------------------
# Encryption workflow
# ---------------------------------------------------------------------------
function Start-EncryptWorkflow {
    param($Mode)

    Write-Step "Encrypt Secrets"
    Write-Host ""
    Write-Host "  1) Encrypt an entire .env file"
    Write-Host "  2) Encrypt a single service token (GitHub, AWS, NPM, etc.)"
    Write-Host "  3) Skip — I'll encrypt later"
    Write-Host ""

    $choice = Read-Host "  Enter choice [1-3]"
    $pyCmd = Get-PythonCmd
    $fileFlag = if ($Mode -eq "file" -or $Mode -eq "cicd") { "--file" } else { "" }

    switch ($choice) {
        "1" {
            $envPath = Read-Host "  Path to .env file [.env]"
            if ([string]::IsNullOrWhiteSpace($envPath)) { $envPath = ".env" }

            if (-not (Test-Path $envPath)) {
                Write-Err "File not found: $envPath"
                return
            }

            if ($fileFlag) {
                & $pyCmd $CLI --file $envPath
            } else {
                & $pyCmd $CLI $envPath
            }
        }
        "2" {
            $svcName = Read-Host "  Service name (e.g., github, aws, npm)"
            $token   = Read-Host "  Token value" -MaskInput

            if ($fileFlag) {
                & $pyCmd $CLI --store $svcName $token --file
            } else {
                & $pyCmd $CLI --store $svcName $token
            }
        }
        "3" {
            Write-Info "Skipped. You can encrypt later with:"
            Write-Host "     python cli\envshield-cli.py .env" -ForegroundColor DarkGray
        }
    }
}

# ---------------------------------------------------------------------------
# Git integration
# ---------------------------------------------------------------------------
function Set-GitIntegration {
    param($Mode)

    Write-Step "Git Credential Helper (Optional)"
    Write-Host ""
    Write-Host "  Configure EnvShield as a Git credential helper?"
    Write-Host "  This decrypts your GitHub/GitLab PAT JIT for git push/pull." -ForegroundColor DarkGray
    Write-Host ""

    $choice = Read-Host "  Set up Git integration? [y/N]"

    if ($choice -match '^[Yy]') {
        $helperPath = Join-Path $SCRIPT_DIR "cli\git-credential-envshield.py"
        $pyCmd = Get-PythonCmd
        & git config --global credential.helper "$pyCmd `"$helperPath`""
        Write-Info "Git credential helper configured."

        $encFile = Join-Path $ENVSHIELD_DIR "github.enc"
        if (-not (Test-Path $encFile)) {
            Write-Host ""
            $patChoice = Read-Host "  Store a GitHub PAT now? [y/N]"
            if ($patChoice -match '^[Yy]') {
                $pat = Read-Host "  GitHub PAT" -MaskInput
                if ($Mode -eq "file" -or $Mode -eq "cicd") {
                    & $pyCmd $CLI --store github $pat --file
                } else {
                    & $pyCmd $CLI --store github $pat
                }
            }
        } else {
            Write-Info "GitHub token already provisioned."
        }
    } else {
        Write-Info "Skipped."
    }
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
function Show-Summary {
    param($Mode)

    Write-Step "Setup Complete"
    Write-Host ""
    Write-Host "  EnvShield is ready." -ForegroundColor Green
    Write-Host ""
    Write-Host "  Storage mode: " -NoNewline -ForegroundColor White
    Write-Host $Mode
    Write-Host "  Config dir:   " -NoNewline -ForegroundColor White
    Write-Host $ENVSHIELD_DIR
    Write-Host ""
    Write-Host "  Quick Reference:" -ForegroundColor White
    Write-Host "     # Encrypt a .env file" -ForegroundColor DarkGray
    Write-Host "     python cli\envshield-cli.py .env"
    Write-Host ""
    Write-Host "     # Store a service token" -ForegroundColor DarkGray
    Write-Host "     python cli\envshield-cli.py --store aws `"AKIA...`""
    Write-Host ""
    Write-Host "     # Use in Python" -ForegroundColor DarkGray
    Write-Host "     import envshield"
    Write-Host "     os.environ['SECRET_API_KEY']  # decrypted JIT"
    Write-Host ""
    Write-Host "     # Use in Node.js" -ForegroundColor DarkGray
    Write-Host "     require('./envshield')"
    Write-Host "     process.env.SECRET_API_KEY  // decrypted JIT"
    Write-Host ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
function Main {
    Write-Banner

    Write-Step "System Detection"
    if (-not (Test-Python)) { exit 1 }
    $hasCredLocker = Test-CredentialLocker
    if ($hasCredLocker) {
        Write-Info "Windows Credential Locker available"
    }

    $mode   = Select-Mode
    $keyHex = Get-MasterKey
    Store-Key -Mode $mode -KeyHex $keyHex
    Start-EncryptWorkflow -Mode $mode
    Set-GitIntegration -Mode $mode
    Show-Summary -Mode $mode
}

Main
