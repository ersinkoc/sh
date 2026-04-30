#!/usr/bin/env bash
# mitigate-copyfail.sh
# CVE-2026-31431 ("Copy Fail") mitigation
# Disables the vulnerable algif_aead kernel module until a patched kernel is installed.
#
# References:
#   https://copy.fail/
#   https://xint.io/blog/copy-fail-linux-distributions
#   https://cert.europa.eu/publications/security-advisories/2026-005/
#   https://ubuntu.com/blog/copy-fail-vulnerability-fixes-available
#
# Usage:
#   sudo ./mitigate-copyfail.sh           # apply mitigation
#   sudo ./mitigate-copyfail.sh --check   # report status only, no changes
#   sudo ./mitigate-copyfail.sh --revert  # remove the blacklist (after kernel patch)

set -euo pipefail

# ---------- presentation ----------
if [[ -t 1 ]]; then
    BOLD=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'
    YLW=$'\033[33m'; BLU=$'\033[34m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
    BOLD=''; RED=''; GRN=''; YLW=''; BLU=''; DIM=''; RST=''
fi

ok()    { printf '%s[ OK ]%s %s\n'   "$GRN"  "$RST" "$*"; }
info()  { printf '%s[INFO]%s %s\n'   "$BLU"  "$RST" "$*"; }
warn()  { printf '%s[WARN]%s %s\n'   "$YLW"  "$RST" "$*" >&2; }
err()   { printf '%s[FAIL]%s %s\n'   "$RED"  "$RST" "$*" >&2; }
hdr()   { printf '\n%s== %s ==%s\n'  "$BOLD" "$*" "$RST"; }

CONF_PATH="/etc/modprobe.d/disable-algif-aead.conf"
MODE="apply"

# ---------- argument parsing ----------
case "${1:-}" in
    --check)  MODE="check" ;;
    --revert) MODE="revert" ;;
    --help|-h)
        sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    "") MODE="apply" ;;
    *)
        err "Unknown argument: $1 (use --check, --revert, or no argument)"
        exit 2
        ;;
esac

# ---------- root check ----------
if [[ $EUID -ne 0 ]] && [[ "$MODE" != "check" ]]; then
    err "This command requires root privileges (run with sudo)."
    exit 1
fi

# ---------- environment summary ----------
hdr "System info"
KERNEL="$(uname -r)"
info "Kernel:    ${KERNEL}"
if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    info "Distro:    ${PRETTY_NAME:-unknown}"
    DISTRO_ID="${ID:-unknown}"
else
    DISTRO_ID="unknown"
fi
info "Hostname:  $(hostname)"
info "Date:      $(date -u +%FT%TZ)"

# ---------- vulnerability state ----------
hdr "Vulnerability state"

MODULE_LOADED=0
if grep -qE '^algif_aead[[:space:]]' /proc/modules 2>/dev/null; then
    MODULE_LOADED=1
    warn "algif_aead module is CURRENTLY LOADED — system is actively vulnerable."
else
    info "algif_aead module not loaded (good — but persistent blacklist is still required to prevent auto-load)."
fi

BLACKLISTED=0
if [[ -f "$CONF_PATH" ]] && grep -q '^install algif_aead /bin/false' "$CONF_PATH" 2>/dev/null; then
    BLACKLISTED=1
    info "Persistent blacklist already in place: $CONF_PATH"
fi

# Detect AF_ALG users to avoid breaking legitimate workloads
AFALG_USERS=""
if command -v lsof >/dev/null 2>&1; then
    AFALG_USERS="$(lsof 2>/dev/null | awk '/AF_ALG/ {print $1}' | sort -u || true)"
    if [[ -n "$AFALG_USERS" ]]; then
        warn "Processes using AF_ALG sockets detected:"
        printf '%s       %s\n' "$DIM" "$AFALG_USERS" | tr '\n' ' '
        printf '%s\n' "$RST"
        warn "When the module is unloaded these will fall back to non-accelerated crypto (usually fine)."
    else
        info "No active processes using AF_ALG sockets."
    fi
else
    warn "lsof not found — AF_ALG usage check skipped."
fi

# ---------- mode dispatch ----------
case "$MODE" in
    check)
        hdr "Result"
        if [[ "$MODULE_LOADED" -eq 1 ]] || [[ "$BLACKLISTED" -eq 0 ]]; then
            warn "Mitigation does not appear to be applied. Run 'sudo $0' to apply."
            exit 2
        fi
        ok "Mitigation is applied (blacklist present, module not loaded)."
        exit 0
        ;;

    revert)
        hdr "Reverting mitigation"
        if [[ -f "$CONF_PATH" ]]; then
            rm -f "$CONF_PATH"
            ok "Blacklist removed: $CONF_PATH"
        else
            info "Blacklist file does not exist."
        fi
        if command -v update-initramfs >/dev/null 2>&1; then
            info "Updating initramfs..."
            update-initramfs -u >/dev/null
            ok "initramfs updated."
        elif command -v dracut >/dev/null 2>&1; then
            info "Updating initramfs (dracut)..."
            dracut -f >/dev/null
            ok "initramfs updated."
        fi
        warn "WARNING: Only safe to revert if a patched kernel is installed. Verify with uname -r."
        exit 0
        ;;

    apply)
        hdr "Applying mitigation"

        # 1) Persistent blacklist
        if [[ "$BLACKLISTED" -eq 0 ]]; then
            printf 'install algif_aead /bin/false\n' > "$CONF_PATH"
            chmod 0644 "$CONF_PATH"
            ok "Persistent blacklist written: $CONF_PATH"
        else
            ok "Blacklist already in place."
        fi

        # 2) Live unload
        if [[ "$MODULE_LOADED" -eq 1 ]]; then
            if rmmod algif_aead 2>/dev/null; then
                ok "algif_aead module unloaded at runtime."
            else
                warn "Module appears to be in use, could not unload. A reboot will clear it."
            fi
        fi

        # 3) initramfs update (prevents auto-load at boot)
        case "$DISTRO_ID" in
            ubuntu|debian)
                if command -v update-initramfs >/dev/null 2>&1; then
                    info "Updating initramfs to prevent auto-load at boot..."
                    update-initramfs -u >/dev/null
                    ok "initramfs updated."
                fi
                ;;
            rhel|centos|rocky|almalinux|fedora|amzn)
                if command -v dracut >/dev/null 2>&1; then
                    info "Updating initramfs (dracut)..."
                    dracut -f >/dev/null
                    ok "initramfs updated."
                fi
                ;;
            opensuse*|sles|sled)
                if command -v dracut >/dev/null 2>&1; then
                    info "Updating initramfs (dracut)..."
                    dracut -f >/dev/null
                    ok "initramfs updated."
                fi
                ;;
            *)
                warn "Could not auto-detect distro (${DISTRO_ID}). Update initramfs manually."
                ;;
        esac

        # 4) Verification
        hdr "Verification"
        if grep -qE '^algif_aead[[:space:]]' /proc/modules 2>/dev/null; then
            err "algif_aead is still loaded. A reboot is required."
            exit 3
        fi
        if ! [[ -f "$CONF_PATH" ]]; then
            err "Blacklist file is missing — mitigation not applied."
            exit 3
        fi
        ok "Mitigation is active. CVE-2026-31431 exploit path is closed."

        # 5) Next steps
        hdr "Next steps"
        cat <<EOF
${BOLD}1.${RST} Update distro packages and install the patched kernel:
     ${DIM}# Ubuntu/Debian${RST}
     sudo apt update && sudo apt full-upgrade
     ${DIM}# RHEL/Rocky/Alma${RST}
     sudo dnf update kernel
     ${DIM}# SUSE${RST}
     sudo zypper update kernel-default

${BOLD}2.${RST} Reboot after the patched kernel is installed and verify with uname -r.

${BOLD}3.${RST} On multi-tenant systems (K8s nodes, CI runners, sandboxes) consider
   blocking AF_ALG via seccomp even after patching — it shuts the door
   on this whole class of bug if another AF_ALG flaw shows up later.

${BOLD}4.${RST} To revert (only after a patched kernel is installed):
     sudo $0 --revert
EOF
        exit 0
        ;;
esac
