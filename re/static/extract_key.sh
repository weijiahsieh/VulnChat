#!/usr/bin/env bash
#
# extract_key.sh — pull an installed VulnChat APK and scan its DEX for the API key.
#
# Demonstrates that a compile-time string constant (the vulnerable build's
# BuildConfig key) is recoverable with no decompiler — just `strings`.
# Against the hardened build it finds nothing, because the key is
# Keystore-encrypted and never a literal in the APK.
#
# SCOPE: targets this project's own deliberately-vulnerable app on a device
# you control. Standard mobile-assessment technique, demo use only.
#
# Usage:
#   ./extract_key.sh [package_id]
#
# Defaults to the vulnerable debug build. Try the hardened one to see the
# contrast:
#   ./extract_key.sh com.vulnchat.vulnerable.debug
#   ./extract_key.sh com.vulnchat.hardened.debug
#
set -euo pipefail

PACKAGE="${1:-com.vulnchat.vulnerable.debug}"
PATTERN="${2:-sk-ant}"

# ── colours (fall back to plain if not a tty) ────────────────────────────────
if [ -t 1 ]; then
  RED=$'\033[31m'; GRN=$'\033[32m'; DIM=$'\033[90m'; RST=$'\033[0m'
else
  RED=""; GRN=""; DIM=""; RST=""
fi

say()  { printf '%s\n' "$*"; }
dim()  { printf '%s%s%s\n' "$DIM" "$*" "$RST"; }

# ── preflight ────────────────────────────────────────────────────────────────
command -v adb >/dev/null 2>&1 || { say "${RED}adb not found on PATH.${RST}"; exit 1; }

if ! adb get-state >/dev/null 2>&1; then
  say "${RED}No device/emulator connected.${RST} Start one and enable USB debugging."
  exit 1
fi

# ── locate the installed APK ─────────────────────────────────────────────────
dim "# resolving APK path for ${PACKAGE}"
APK_PATH="$(adb shell pm path "$PACKAGE" 2>/dev/null | sed 's/package://' | tr -d '\r' | head -n1 || true)"

if [ -z "$APK_PATH" ]; then
  say "${RED}Package not installed:${RST} ${PACKAGE}"
  say "Installed VulnChat packages:"
  adb shell pm list packages 2>/dev/null | grep -i vulnchat | sed 's/package:/  /' || say "  (none)"
  exit 1
fi
dim "# found: ${APK_PATH}"

# ── work in an isolated temp dir ─────────────────────────────────────────────
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

dim "# pulling APK"
adb pull "$APK_PATH" "$WORK/app.apk" >/dev/null

dim "# extracting classes.dex"
# An APK may contain classes.dex, classes2.dex, … — extract all of them.
unzip -o "$WORK/app.apk" 'classes*.dex' -d "$WORK" >/dev/null 2>&1 || true

shopt -s nullglob
DEX_FILES=("$WORK"/classes*.dex)
if [ ${#DEX_FILES[@]} -eq 0 ]; then
  say "${RED}No DEX files found in the APK.${RST}"
  exit 1
fi

# ── scan ─────────────────────────────────────────────────────────────────────
say ""
say "Scanning ${#DEX_FILES[@]} DEX file(s) in ${PACKAGE} for /${PATTERN}/ …"
say ""

HITS="$(strings "${DEX_FILES[@]}" | grep -E "$PATTERN" || true)"

if [ -n "$HITS" ]; then
  say "${RED}╔══════════════════════════════════════════╗${RST}"
  say "${RED}║  API KEY MATERIAL FOUND IN PLAINTEXT      ║${RST}"
  say "${RED}╚══════════════════════════════════════════╝${RST}"
  printf '%s%s%s\n' "$RED" "$HITS" "$RST"
  say ""
  dim "# a compile-time constant is not hidden — this is why the hardened"
  dim "# build moves the key into the Android Keystore instead."
  exit 0
else
  say "${GRN}No '${PATTERN}' match in the DEX.${RST}"
  say ""
  dim "# nothing to extract statically. If this is the hardened build, the key"
  dim "# is Keystore-encrypted and only exists in memory at runtime — try"
  dim "# frida/hook_apikey.js to recover it dynamically."
  exit 0
fi
