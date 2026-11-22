#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>
#
# Idempotent POSIX sh installer for tegrad (Tegra Agent).

set -eu

TEGRAD_USER="tegrad"
TEGRAD_GROUP="tegrad"
TEGRAD_SRV_USER="tegrad-srv"
TEGRAD_SRV_GROUP="tegrad-srv"

TEGRAD_BIN_DIR="/opt/tegrad/bin"
TEGRAD_BIN="/opt/tegrad/bin/tegrad"
TEGRAD_WRAPPER="/usr/local/bin/tegrad"
TEGRAD_STATE_DIR="/var/lib/tegrad"
TEGRAD_CONFIG_FILE="/var/lib/tegrad/config.json"
TEGRAD_SERVERS_DIR="/var/lib/tegrad-servers"
TEGRAD_BACKUPS_DIR="/var/lib/tegrad-backups"
TEGRAD_RUN_DIR="/run/tegrad-server"

SYSTEMD_DIR="/etc/systemd/system"
DROPIN_DIR="/etc/systemd/system/tegrad-server@.service.d"
DROPIN_FILE="/etc/systemd/system/tegrad-server@.service.d/10-network.conf"
POLKIT_RULES_DIR="/etc/polkit-1/rules.d"
POLKIT_RULE_FILE="/etc/polkit-1/rules.d/50-tegrad.rules"
TMPFILES_FILE="/etc/tmpfiles.d/tegrad.conf"

DEFAULT_API_URL="https://api.tegramc.com"
RELEASE_BASE_URL="https://github.com/codebyant/tegrad/releases/download"
NETWORK_DENY_RANGES="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 127.0.0.0/8 fc00::/7 fe80::/10 ::1/128"
# TODO(release-key): replace placeholder test public key with production offline Ed25519 release signing public key before first public release.
RELEASE_PUBLIC_KEY_PEM='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAIVL40Zt5HSRFMkLhXy6rbLfP+ntqXtMAl5YOBpiB2xI=
-----END PUBLIC KEY-----'

TMP_DOWNLOAD_DIR=""

cleanup_tmp() {
  if [ -n "${TMP_DOWNLOAD_DIR:-}" ] && [ -d "${TMP_DOWNLOAD_DIR}" ]; then
    rm -rf -- "${TMP_DOWNLOAD_DIR:?}"
  fi
}

log_info() {
  printf '%s\n' "$1"
}

log_err() {
  printf 'Error: %s\n' "$1" >&2
}

die() {
  log_err "$1"
  exit 1
}

usage() {
  cat <<'EOF'
Usage: install.sh [options]

Install or update tegrad (idempotent):
  --binary <path>       Install a local tegrad binary
  --version <vX.Y.Z>    Download release binary and verify Ed25519 signature + SHA256SUMS
  --api-url <url>       Write api_url to /var/lib/tegrad/config.json (must be https://)
  --allow-lan <cidr>    Allow a LAN CIDR in IPAddressAllow (repeatable)

Uninstall:
  --uninstall           Stop services and remove units, polkit rule, wrapper, and binary
  --purge               With --uninstall, also remove state, servers, and system users
  --yes                 Skip interactive confirmation for --purge

Other:
  -h, --help            Show this help message
EOF
}

is_uint_no_leading_zero() {
  _u_val="$1"
  case "$_u_val" in
    "") return 1 ;;
    0) return 0 ;;
    0*) return 1 ;;
    *[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

is_valid_ipv4() {
  _v4_in="$1"
  case "$_v4_in" in
    ""|.*|*.|*..*|*[!0-9.]*) return 1 ;;
  esac

  _v4_rest="$_v4_in"
  _v4_count=0
  while :; do
    _v4_count=$((_v4_count + 1))
    case "$_v4_rest" in
      *.*)
        _v4_oct="${_v4_rest%%.*}"
        _v4_rest="${_v4_rest#*.}"
        ;;
      *)
        _v4_oct="$_v4_rest"
        _v4_rest=""
        ;;
    esac

    if ! is_uint_no_leading_zero "$_v4_oct"; then
      return 1
    fi
    if [ "$_v4_oct" -gt 255 ]; then
      return 1
    fi

    if [ -z "$_v4_rest" ]; then
      break
    fi
  done

  [ "$_v4_count" -eq 4 ]
}

pad_hex4_lower() {
  _p_in=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  while [ "${#_p_in}" -lt 4 ]; do
    _p_in="0${_p_in}"
  done
  printf '%s' "$_p_in"
}

is_valid_ipv6() {
  _v6_in="$1"
  case "$_v6_in" in
    ""|*[!0-9a-fA-F:]*) return 1 ;;
    *:*) ;;
    *) return 1 ;;
  esac
  # Reject triple colons
  case "$_v6_in" in
    *:::* ) return 1 ;;
  esac
  # Reject leading or trailing single colon
  case "$_v6_in" in
    :*)
      case "$_v6_in" in
        ::*) ;;
        *) return 1 ;;
      esac
      ;;
  esac
  case "$_v6_in" in
    *:)
      case "$_v6_in" in
        *::) ;;
        *) return 1 ;;
      esac
      ;;
  esac

  # Check for :: compression (at most one occurrence)
  _v6_has_dc=0
  case "$_v6_in" in
    *::*)
      _v6_has_dc=1
      _v6_left="${_v6_in%%::*}"
      _v6_right="${_v6_in#*::}"
      case "$_v6_right" in
        *::*) return 1 ;;
      esac
      ;;
    *)
      _v6_left="$_v6_in"
      _v6_right=""
      ;;
  esac

  _v6_groups=0
  for _v6_side in "$_v6_left" "$_v6_right"; do
    if [ -z "$_v6_side" ]; then
      continue
    fi
    _v6_rem="$_v6_side"
    while :; do
      case "$_v6_rem" in
        *:*)
          _v6_grp="${_v6_rem%%:*}"
          _v6_rem="${_v6_rem#*:}"
          ;;
        *)
          _v6_grp="$_v6_rem"
          _v6_rem=""
          ;;
      esac
      if [ -z "$_v6_grp" ] || [ "${#_v6_grp}" -gt 4 ]; then
        return 1
      fi
      _v6_groups=$((_v6_groups + 1))
      if [ -z "$_v6_rem" ]; then
        break
      fi
    done
  done

  if [ "$_v6_has_dc" -eq 1 ]; then
    [ "$_v6_groups" -lt 8 ]
  else
    [ "$_v6_groups" -eq 8 ]
  fi
}

is_valid_ip() {
  if is_valid_ipv4 "$1"; then
    return 0
  fi
  if is_valid_ipv6 "$1"; then
    return 0
  fi
  return 1
}

is_valid_cidr() {
  _c_in="$1"
  case "$_c_in" in
    */*) ;;
    *) return 1 ;;
  esac
  _c_addr="${_c_in%%/*}"
  _c_prefix="${_c_in#*/}"
  case "$_c_prefix" in
    */*) return 1 ;;
  esac
  if ! is_uint_no_leading_zero "$_c_prefix"; then
    return 1
  fi
  if is_valid_ipv4 "$_c_addr"; then
    [ "$_c_prefix" -le 32 ]
    return $?
  fi
  if is_valid_ipv6 "$_c_addr"; then
    [ "$_c_prefix" -le 128 ]
    return $?
  fi
  return 1
}

expand_ipv6_groups() {
  _e_in="$1"
  _e_left=""
  _e_right=""
  _e_has_dc=0
  case "$_e_in" in
    *::*)
      _e_has_dc=1
      _e_left="${_e_in%%::*}"
      _e_right="${_e_in#*::}"
      ;;
    *)
      _e_left="$_e_in"
      ;;
  esac

  _e_lcount=0
  _e_lout=""
  if [ -n "$_e_left" ]; then
    _e_rem="$_e_left"
    while :; do
      case "$_e_rem" in
        *:*) _e_g="${_e_rem%%:*}"; _e_rem="${_e_rem#*:}" ;;
        *) _e_g="$_e_rem"; _e_rem="" ;;
      esac
      _e_p=$(pad_hex4_lower "$_e_g")
      _e_lout="${_e_lout}${_e_lout:+:}${_e_p}"
      _e_lcount=$((_e_lcount + 1))
      [ -z "$_e_rem" ] && break
    done
  fi

  _e_rcount=0
  _e_rout=""
  if [ -n "$_e_right" ]; then
    _e_rem="$_e_right"
    while :; do
      case "$_e_rem" in
        *:*) _e_g="${_e_rem%%:*}"; _e_rem="${_e_rem#*:}" ;;
        *) _e_g="$_e_rem"; _e_rem="" ;;
      esac
      _e_p=$(pad_hex4_lower "$_e_g")
      _e_rout="${_e_rout}${_e_rout:+:}${_e_p}"
      _e_rcount=$((_e_rcount + 1))
      [ -z "$_e_rem" ] && break
    done
  fi

  _e_mout=""
  if [ "$_e_has_dc" -eq 1 ]; then
    _e_zeros=$((8 - _e_lcount - _e_rcount))
    while [ "$_e_zeros" -gt 0 ]; do
      _e_mout="${_e_mout}${_e_mout:+:}0000"
      _e_zeros=$((_e_zeros - 1))
    done
  fi

  _e_full="$_e_lout"
  if [ -n "$_e_mout" ]; then
    _e_full="${_e_full}${_e_full:+:}${_e_mout}"
  fi
  if [ -n "$_e_rout" ]; then
    _e_full="${_e_full}${_e_full:+:}${_e_rout}"
  fi
  printf '%s' "$_e_full"
}

is_private_or_loopback_ip() {
  _p_ip="$1"
  if is_valid_ipv4 "$_p_ip"; then
    _p_a="${_p_ip%%.*}"
    _p_rest="${_p_ip#*.}"
    _p_b="${_p_rest%%.*}"
    # 10.0.0.0/8
    [ "$_p_a" -eq 10 ] && return 0
    # 127.0.0.0/8
    [ "$_p_a" -eq 127 ] && return 0
    # 169.254.0.0/16
    [ "$_p_a" -eq 169 ] && [ "$_p_b" -eq 254 ] && return 0
    # 172.16.0.0/12
    [ "$_p_a" -eq 172 ] && [ "$_p_b" -ge 16 ] && [ "$_p_b" -le 31 ] && return 0
    # 192.168.0.0/16
    [ "$_p_a" -eq 192 ] && [ "$_p_b" -eq 168 ] && return 0
    # 100.64.0.0/10
    [ "$_p_a" -eq 100 ] && [ "$_p_b" -ge 64 ] && [ "$_p_b" -le 127 ] && return 0
    return 1
  fi

  if is_valid_ipv6 "$_p_ip"; then
    _p_exp=$(expand_ipv6_groups "$_p_ip")
    # ::1/128
    if [ "$_p_exp" = "0000:0000:0000:0000:0000:0000:0000:0001" ]; then
      return 0
    fi
    _p_first="${_p_exp%%:*}"
    # fc00::/7 (fc00..fdff) and fe80::/10 (fe80..febf)
    case "$_p_first" in
      fc*|fd*|fe8*|fe9*|fea*|feb*) return 0 ;;
    esac
    return 1
  fi

  return 1
}

parse_resolv_conf_file() {
  _rc_file="$1"
  if [ ! -r "$_rc_file" ]; then
    return 0
  fi
  while IFS= read -r _rc_line || [ -n "$_rc_line" ]; do
    # Strip comments
    _rc_clean="${_rc_line%%#*}"
    _rc_clean="${_rc_clean%%;*}"
    # Normalize tabs to spaces
    _rc_clean=$(printf '%s' "$_rc_clean" | tr '\t' ' ')
    # Trim leading spaces
    while [ "${_rc_clean# }" != "$_rc_clean" ]; do
      _rc_clean="${_rc_clean# }"
    done
    case "$_rc_clean" in
      nameserver\ *)
        _rc_rest="${_rc_clean#nameserver }"
        while [ "${_rc_rest# }" != "$_rc_rest" ]; do
          _rc_rest="${_rc_rest# }"
        done
        _rc_addr="${_rc_rest%% *}"
        if is_valid_ip "$_rc_addr"; then
          printf '%s\n' "$_rc_addr"
        fi
        ;;
    esac
  done < "$_rc_file"
}

collect_resolvers() {
  _cr_primary="${1:-/etc/resolv.conf}"
  _cr_systemd="${2:-/run/systemd/resolve/resolv.conf}"
  _cr_list=""
  _cr_has_stub=0

  if [ -r "$_cr_primary" ]; then
    _cr_list=$(parse_resolv_conf_file "$_cr_primary")
  fi

  # intentional word splitting on validated IP list
  # shellcheck disable=SC2086
  for _cr_ip in $_cr_list; do
    if [ "$_cr_ip" = "127.0.0.53" ] || [ "$_cr_ip" = "127.0.0.54" ]; then
      _cr_has_stub=1
      break
    fi
  done

  if [ "$_cr_has_stub" -eq 1 ] && [ -r "$_cr_systemd" ]; then
    _cr_extra=$(parse_resolv_conf_file "$_cr_systemd")
    if [ -n "$_cr_extra" ]; then
      _cr_list="${_cr_list}${_cr_list:+
}${_cr_extra}"
    fi
  fi

  printf '%s' "$_cr_list"
}

append_unique_token() {
  _au_list="$1"
  _au_tok="$2"
  case " $_au_list " in
    *" $_au_tok "*) printf '%s' "$_au_list" ;;
    *) printf '%s' "${_au_list}${_au_list:+ }${_au_tok}" ;;
  esac
}

render_network_dropin() {
  _rd_resolvers="$1"
  _rd_allow_lan="$2"
  _rd_allow=""

  # intentional word splitting on validated IP list
  # shellcheck disable=SC2086
  for _rd_ip in $_rd_resolvers; do
    if is_valid_ip "$_rd_ip" && is_private_or_loopback_ip "$_rd_ip"; then
      _rd_allow=$(append_unique_token "$_rd_allow" "$_rd_ip")
    fi
  done

  # intentional word splitting on validated CIDR list
  # shellcheck disable=SC2086
  for _rd_cidr in $_rd_allow_lan; do
    if is_valid_cidr "$_rd_cidr"; then
      _rd_allow=$(append_unique_token "$_rd_allow" "$_rd_cidr")
    fi
  done

  printf '# SPDX-License-Identifier: AGPL-3.0-only\n'
  printf '# Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>\n'
  printf '# Generated by tegrad installer. Re-run installer to refresh DNS resolvers.\n'
  printf '\n'
  printf '[Service]\n'
  printf 'IPAddressDeny=%s\n' "$NETWORK_DENY_RANGES"
  if [ -n "$_rd_allow" ]; then
    printf 'IPAddressAllow=%s\n' "$_rd_allow"
  fi
}

validate_api_url() {
  _au_url="$1"
  case "$_au_url" in
    https://*) ;;
    *) die "--api-url must start with https://" ;;
  esac
  # Reject whitespace, quotes, backslashes, or embedded credentials
  case "$_au_url" in
    *[[:space:]]*|*\"*|*\\*|*@*)
      die "--api-url contains forbidden characters or embedded credentials"
      ;;
  esac
  _au_rest="${_au_url#https://}"
  if [ -z "$_au_rest" ] || [ "${_au_rest#/}" != "$_au_rest" ]; then
    die "--api-url must include a valid host"
  fi
}

validate_version() {
  _ver="$1"
  case "$_ver" in
    v[0-9]*) ;;
    *) die "--version must look like vX.Y.Z (got '$_ver')" ;;
  esac
  case "$_ver" in
    *..*|*/*|*[!0-9A-Za-z._-]*)
      die "--version contains invalid characters"
      ;;
  esac
}

detect_arch() {
  _arch=$(uname -m)
  case "$_arch" in
    x86_64) printf 'x64' ;;
    aarch64) printf 'arm64' ;;
    *) die "Unsupported architecture: $_arch (supported: x86_64, aarch64)" ;;
  esac
}

check_environment() {
  _os=$(uname -s)
  if [ "$_os" != "Linux" ]; then
    die "tegrad installer only supports Linux (detected: $_os)"
  fi

  detect_arch >/dev/null

  if [ ! -d /run/systemd/system ] || ! command -v systemctl >/dev/null 2>&1; then
    die "systemd must be running as PID 1"
  fi

  if [ ! -d "$POLKIT_RULES_DIR" ] \
    && ! command -v polkitd >/dev/null 2>&1 \
    && [ ! -x /usr/lib/polkit-1/polkitd ] \
    && [ ! -x /usr/libexec/polkitd ]; then
    die "polkit with JavaScript rules support ($POLKIT_RULES_DIR) is required. Install polkit (e.g. 'polkitd') and re-run."
  fi

  if [ "$(id -u)" -ne 0 ] && ! command -v sudo >/dev/null 2>&1; then
    die "Root privileges or 'sudo' are required"
  fi

  if [ -n "${OPT_VERSION:-}" ] && [ ! -x "$TEGRAD_BIN" ] && ! command -v openssl >/dev/null 2>&1; then
    die "'openssl' is required to verify Ed25519 release signatures for --version installs"
  fi
}

detect_nologin_shell() {
  if [ -x /usr/sbin/nologin ]; then
    printf '/usr/sbin/nologin'
  elif [ -x /sbin/nologin ]; then
    printf '/sbin/nologin'
  else
    printf '/bin/false'
  fi
}

download_file() {
  _dl_url="$1"
  _dl_out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --proto '=https' --tlsv1.2 -o "$_dl_out" "$_dl_url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --https-only -O "$_dl_out" "$_dl_url"
  else
    die "Either 'curl' or 'wget' is required to download releases"
  fi
}

verify_sha256sums_signature() {
  _vs_sums="$1"
  _vs_sig="$2"
  _vs_tmp="$3"
  _vs_pem="${4:-$RELEASE_PUBLIC_KEY_PEM}"

  if ! command -v openssl >/dev/null 2>&1; then
    die "'openssl' is required to verify Ed25519 release signatures"
  fi

  _vs_raw=$(tr -d '\r\n\t ' < "$_vs_sig")
  if [ -z "$_vs_raw" ]; then
    die "SHA256SUMS.sig is empty"
  fi
  case "$_vs_raw" in
    *[!A-Za-z0-9_-]*)
      die "Invalid base64url characters in SHA256SUMS.sig"
      ;;
  esac
  if [ "${#_vs_raw}" -ne 86 ]; then
    die "Invalid Ed25519 signature length in SHA256SUMS.sig"
  fi

  _vs_b64=$(printf '%s' "$_vs_raw" | tr '_-' '/+')
  case $(( ${#_vs_b64} % 4 )) in
    0) ;;
    2) _vs_b64="${_vs_b64}==" ;;
    3) _vs_b64="${_vs_b64}=" ;;
    *) die "Invalid base64url encoding in SHA256SUMS.sig" ;;
  esac

  printf '%s' "$_vs_b64" | openssl base64 -d -A > "${_vs_tmp}/SHA256SUMS.sig.bin" \
    || die "Failed to decode SHA256SUMS.sig"

  printf '%s\n' "$_vs_pem" > "${_vs_tmp}/release-pubkey.pem"
  { printf 'TEGRA_SHA256SUMS_V1\000'; cat "$_vs_sums"; } > "${_vs_tmp}/SHA256SUMS.input"

  if ! openssl pkeyutl -verify \
    -pubin -inkey "${_vs_tmp}/release-pubkey.pem" \
    -rawin \
    -in "${_vs_tmp}/SHA256SUMS.input" \
    -sigfile "${_vs_tmp}/SHA256SUMS.sig.bin" >/dev/null 2>&1; then
    die "Ed25519 signature verification failed for SHA256SUMS"
  fi
}

fetch_release_binary() {
  _fr_ver="$1"
  _fr_arch=$(detect_arch)
  _fr_asset="tegrad-linux-${_fr_arch}"
  _fr_bin_url="${RELEASE_BASE_URL}/${_fr_ver}/${_fr_asset}"
  _fr_sums_url="${RELEASE_BASE_URL}/${_fr_ver}/SHA256SUMS"
  _fr_sig_url="${RELEASE_BASE_URL}/${_fr_ver}/SHA256SUMS.sig"

  if ! command -v sha256sum >/dev/null 2>&1; then
    die "'sha256sum' is required to verify release downloads"
  fi

  TMP_DOWNLOAD_DIR=$(mktemp -d)
  trap cleanup_tmp EXIT

  log_info "Downloading ${_fr_asset} (${_fr_ver})..."
  download_file "$_fr_bin_url" "${TMP_DOWNLOAD_DIR}/${_fr_asset}" \
    || die "Failed to download ${_fr_bin_url}"
  download_file "$_fr_sums_url" "${TMP_DOWNLOAD_DIR}/SHA256SUMS" \
    || die "Failed to download ${_fr_sums_url}"
  download_file "$_fr_sig_url" "${TMP_DOWNLOAD_DIR}/SHA256SUMS.sig" \
    || die "Failed to download ${_fr_sig_url}"

  if [ -x "$TEGRAD_BIN" ]; then
    # Verify Ed25519 signature and SHA-256 using the already-installed root-owned binary
    "$TEGRAD_BIN" verify-update \
      --sums "${TMP_DOWNLOAD_DIR}/SHA256SUMS" \
      --sig "${TMP_DOWNLOAD_DIR}/SHA256SUMS.sig" \
      --binary "${TMP_DOWNLOAD_DIR}/${_fr_asset}" \
      --asset "${_fr_asset}" >/dev/null \
      || die "Release signature or SHA-256 verification failed for ${_fr_asset}"
    log_info "Ed25519 signature and SHA-256 verified for ${_fr_asset}."
    DOWNLOADED_BINARY="${TMP_DOWNLOAD_DIR}/${_fr_asset}"
    return 0
  fi

  # Fresh install: verify Ed25519 signature of SHA256SUMS with OpenSSL BEFORE trusting checksums or running binary
  verify_sha256sums_signature \
    "${TMP_DOWNLOAD_DIR}/SHA256SUMS" \
    "${TMP_DOWNLOAD_DIR}/SHA256SUMS.sig" \
    "${TMP_DOWNLOAD_DIR}"

  _fr_expected=""
  while IFS= read -r _fr_line || [ -n "$_fr_line" ]; do
    # Standard sha256sum format: "<hash>  <filename>" or "<hash> *<filename>"
    _fr_hash="${_fr_line%%[[:space:]]*}"
    _fr_name="${_fr_line#*[[:space:]]}"
    while [ "${_fr_name# }" != "$_fr_name" ]; do
      _fr_name="${_fr_name# }"
    done
    _fr_name="${_fr_name#\*}"
    if [ "$_fr_name" = "$_fr_asset" ]; then
      _fr_expected="$_fr_hash"
      break
    fi
  done < "${TMP_DOWNLOAD_DIR}/SHA256SUMS"

  if [ -z "$_fr_expected" ]; then
    die "Checksum for ${_fr_asset} not found in SHA256SUMS"
  fi

  _fr_actual=$(sha256sum "${TMP_DOWNLOAD_DIR}/${_fr_asset}" | awk '{print $1}')
  if [ "$_fr_actual" != "$_fr_expected" ]; then
    die "SHA-256 mismatch for ${_fr_asset} (expected ${_fr_expected}, got ${_fr_actual})"
  fi

  # Only execute the downloaded binary after cryptographic signature and SHA-256 have passed
  chmod 0755 "${TMP_DOWNLOAD_DIR}/${_fr_asset}"
  "${TMP_DOWNLOAD_DIR}/${_fr_asset}" verify-update \
    --sums "${TMP_DOWNLOAD_DIR}/SHA256SUMS" \
    --sig "${TMP_DOWNLOAD_DIR}/SHA256SUMS.sig" \
    --binary "${TMP_DOWNLOAD_DIR}/${_fr_asset}" \
    --asset "${_fr_asset}" >/dev/null \
    || die "Downloaded binary failed verify-update self-check"

  log_info "Ed25519 signature and SHA-256 verified for ${_fr_asset}."
  DOWNLOADED_BINARY="${TMP_DOWNLOAD_DIR}/${_fr_asset}"
}

render_template_file() {
  _rt_src="$1"
  _rt_dst="$2"
  _rt_mode="$3"
  _rt_tmp="${_rt_dst}.tmp.$$"

  sed \
    -e "s|@TEGRAD_BIN_DIR@|${TEGRAD_BIN_DIR}|g" \
    -e "s|@TEGRAD_BIN@|${TEGRAD_BIN}|g" \
    -e "s|@TEGRAD_STATE_DIR@|${TEGRAD_STATE_DIR}|g" \
    -e "s|@TEGRAD_SERVERS_DIR@|${TEGRAD_SERVERS_DIR}|g" \
    -e "s|@TEGRAD_BACKUPS_DIR@|${TEGRAD_BACKUPS_DIR}|g" \
    -e "s|@TEGRAD_RUN_DIR@|${TEGRAD_RUN_DIR}|g" \
    "$_rt_src" > "$_rt_tmp"

  chown root:root "$_rt_tmp"
  chmod "$_rt_mode" "$_rt_tmp"
  mv -f "$_rt_tmp" "$_rt_dst"
}

ensure_users_and_groups() {
  _nl_shell=$(detect_nologin_shell)

  if ! getent group "$TEGRAD_SRV_GROUP" >/dev/null 2>&1; then
    groupadd --system "$TEGRAD_SRV_GROUP"
  fi
  if ! id -u "$TEGRAD_SRV_USER" >/dev/null 2>&1; then
    useradd --system \
      --gid "$TEGRAD_SRV_GROUP" \
      --home-dir /nonexistent \
      --no-create-home \
      --shell "$_nl_shell" \
      "$TEGRAD_SRV_USER"
  fi

  if ! getent group "$TEGRAD_GROUP" >/dev/null 2>&1; then
    groupadd --system "$TEGRAD_GROUP"
  fi
  if ! id -u "$TEGRAD_USER" >/dev/null 2>&1; then
    useradd --system \
      --gid "$TEGRAD_GROUP" \
      --home-dir "$TEGRAD_STATE_DIR" \
      --no-create-home \
      --shell "$_nl_shell" \
      "$TEGRAD_USER"
  fi

  # Ensure tegrad is in tegrad-srv group (to manage server files)
  _tegrad_groups=" $(id -nG "$TEGRAD_USER") "
  case "$_tegrad_groups" in
    *" $TEGRAD_SRV_GROUP "*) ;;
    *) usermod -aG "$TEGRAD_SRV_GROUP" "$TEGRAD_USER" ;;
  esac

  # Ensure tegrad-srv is NOT in tegrad group
  _srv_groups=" $(id -nG "$TEGRAD_SRV_USER") "
  case "$_srv_groups" in
    *" $TEGRAD_GROUP "*)
      if command -v gpasswd >/dev/null 2>&1; then
        gpasswd -d "$TEGRAD_SRV_USER" "$TEGRAD_GROUP" >/dev/null
      else
        die "User $TEGRAD_SRV_USER must not belong to group $TEGRAD_GROUP"
      fi
      ;;
  esac
}

ensure_directories() {
  install -d -o root -g root -m 0755 "$TEGRAD_BIN_DIR"
  install -d -o "$TEGRAD_USER" -g "$TEGRAD_GROUP" -m 0700 "$TEGRAD_STATE_DIR"
  install -d -o "$TEGRAD_USER" -g "$TEGRAD_GROUP" -m 0700 "${TEGRAD_STATE_DIR}/update"
  install -d -o "$TEGRAD_SRV_USER" -g "$TEGRAD_SRV_GROUP" -m 2770 "$TEGRAD_SERVERS_DIR"
  chmod 2770 "$TEGRAD_SERVERS_DIR"
  install -d -o "$TEGRAD_USER" -g "$TEGRAD_GROUP" -m 0700 "$TEGRAD_BACKUPS_DIR"
  chmod 0700 "$TEGRAD_BACKUPS_DIR"
  install -d -o root -g root -m 0755 "$DROPIN_DIR"
  install -d -o root -g root -m 0755 "$POLKIT_RULES_DIR"
}

install_wrapper() {
  _wr_tmp="${TEGRAD_WRAPPER}.tmp.$$"
  cat <<EOF > "$_wr_tmp"
#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>
set -eu
if [ "\$(id -u)" -eq 0 ]; then
  exec runuser -u ${TEGRAD_USER} -- ${TEGRAD_BIN} "\$@"
fi
if [ "\$(id -un)" = "${TEGRAD_USER}" ]; then
  exec ${TEGRAD_BIN} "\$@"
fi
exec sudo -u ${TEGRAD_USER} -- ${TEGRAD_BIN} "\$@"
EOF
  chown root:root "$_wr_tmp"
  chmod 0755 "$_wr_tmp"
  mv -f "$_wr_tmp" "$TEGRAD_WRAPPER"
}

ensure_config() {
  _cfg_url="$1"
  _cfg_force="$2"

  if [ -f "$TEGRAD_CONFIG_FILE" ] && [ "$_cfg_force" -eq 0 ]; then
    chown "${TEGRAD_USER}:${TEGRAD_GROUP}" "$TEGRAD_CONFIG_FILE"
    chmod 0600 "$TEGRAD_CONFIG_FILE"
    return 0
  fi

  _cfg_tmp="${TEGRAD_CONFIG_FILE}.tmp.$$"
  printf '{\n  "api_url": "%s"\n}\n' "$_cfg_url" > "$_cfg_tmp"
  chown "${TEGRAD_USER}:${TEGRAD_GROUP}" "$_cfg_tmp"
  chmod 0600 "$_cfg_tmp"
  mv -f "$_cfg_tmp" "$TEGRAD_CONFIG_FILE"
}

do_uninstall() {
  _un_purge="$1"
  _un_yes="$2"

  if [ "$_un_purge" -eq 1 ] && [ "$_un_yes" -ne 1 ]; then
    printf 'WARNING: --purge will permanently delete %s, %s, and users %s/%s.\n' \
      "$TEGRAD_STATE_DIR" "$TEGRAD_SERVERS_DIR" "$TEGRAD_USER" "$TEGRAD_SRV_USER"
    printf 'Type "yes" to confirm: '
    if ! IFS= read -r _un_confirm; then
      die "Aborted."
    fi
    if [ "$_un_confirm" != "yes" ]; then
      die "Confirmation did not match 'yes'. Aborted."
    fi
  fi

  log_info "Stopping tegrad services..."
  systemctl disable --now tegrad-update.path >/dev/null 2>&1 || true
  systemctl stop tegrad-update.service >/dev/null 2>&1 || true
  systemctl disable --now tegrad.service >/dev/null 2>&1 || true

  # Stop any running server template instances
  _un_units=$(systemctl list-units --all --no-legend --plain 'tegrad-server@*' 2>/dev/null | awk '{print $1}' || true)
  # intentional word splitting on unit names from systemctl
  # shellcheck disable=SC2086
  for _un_u in $_un_units; do
    systemctl stop "$_un_u" >/dev/null 2>&1 || true
  done

  rm -f -- \
    "${SYSTEMD_DIR}/tegrad.service" \
    "${SYSTEMD_DIR}/tegrad-update.path" \
    "${SYSTEMD_DIR}/tegrad-update.service" \
    "${SYSTEMD_DIR}/tegrad-server@.service" \
    "${SYSTEMD_DIR}/tegrad-server@.socket" \
    "${DROPIN_FILE}" \
    "${POLKIT_RULE_FILE}" \
    "${TMPFILES_FILE}" \
    "${TEGRAD_WRAPPER}" \
    "${TEGRAD_BIN}" \
    "${TEGRAD_BIN}.prev"

  rmdir "$DROPIN_DIR" 2>/dev/null || true
  rmdir "$TEGRAD_BIN_DIR" 2>/dev/null || true
  rmdir /opt/tegrad 2>/dev/null || true

  systemctl daemon-reload >/dev/null 2>&1 || true

  if [ "$_un_purge" -eq 1 ]; then
    log_info "Purging data directories and system users..."
    rm -rf -- "${TEGRAD_STATE_DIR:?}"
    rm -rf -- "${TEGRAD_SERVERS_DIR:?}"
    rm -rf -- "${TEGRAD_BACKUPS_DIR:?}"
    rm -rf -- "${TEGRAD_RUN_DIR:?}"
    if id -u "$TEGRAD_USER" >/dev/null 2>&1; then
      userdel "$TEGRAD_USER" 2>/dev/null || true
    fi
    if id -u "$TEGRAD_SRV_USER" >/dev/null 2>&1; then
      userdel "$TEGRAD_SRV_USER" 2>/dev/null || true
    fi
    if getent group "$TEGRAD_GROUP" >/dev/null 2>&1; then
      groupdel "$TEGRAD_GROUP" 2>/dev/null || true
    fi
    if getent group "$TEGRAD_SRV_GROUP" >/dev/null 2>&1; then
      groupdel "$TEGRAD_SRV_GROUP" 2>/dev/null || true
    fi
    log_info "tegrad uninstalled and purged."
  else
    log_info "tegrad uninstalled. Data in ${TEGRAD_STATE_DIR} and ${TEGRAD_SERVERS_DIR} and system users were preserved."
  fi
}

main() {
  OPT_BINARY=""
  OPT_VERSION=""
  OPT_API_URL=""
  OPT_ALLOW_LAN=""
  OPT_UNINSTALL=0
  OPT_PURGE=0
  OPT_YES=0

  # Save original args for potential single sudo re-exec
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --binary)
        [ "$#" -ge 2 ] || die "--binary requires a path"
        OPT_BINARY="$2"
        shift 2
        ;;
      --version)
        [ "$#" -ge 2 ] || die "--version requires a version tag (e.g. v0.1.0)"
        OPT_VERSION="$2"
        shift 2
        ;;
      --api-url)
        [ "$#" -ge 2 ] || die "--api-url requires a URL"
        OPT_API_URL="$2"
        shift 2
        ;;
      --allow-lan)
        [ "$#" -ge 2 ] || die "--allow-lan requires a CIDR"
        if ! is_valid_cidr "$2"; then
          die "Invalid CIDR for --allow-lan: $2"
        fi
        OPT_ALLOW_LAN=$(append_unique_token "$OPT_ALLOW_LAN" "$2")
        shift 2
        ;;
      --uninstall)
        OPT_UNINSTALL=1
        shift
        ;;
      --purge)
        OPT_PURGE=1
        shift
        ;;
      --yes)
        OPT_YES=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "Unknown argument: $1 (use --help for usage)"
        ;;
    esac
  done

  if [ "$OPT_PURGE" -eq 1 ] && [ "$OPT_UNINSTALL" -ne 1 ]; then
    die "--purge can only be used together with --uninstall"
  fi

  if [ "$OPT_UNINSTALL" -eq 0 ]; then
    if [ -n "$OPT_BINARY" ] && [ -n "$OPT_VERSION" ]; then
      die "Cannot specify both --binary and --version"
    fi
    if [ -z "$OPT_BINARY" ] && [ -z "$OPT_VERSION" ]; then
      die "Specify either --binary <path> or --version <vX.Y.Z>"
    fi
    if [ -n "$OPT_BINARY" ] && [ ! -f "$OPT_BINARY" ]; then
      die "Binary not found: $OPT_BINARY"
    fi
    if [ -n "$OPT_VERSION" ]; then
      validate_version "$OPT_VERSION"
    fi
    if [ -n "$OPT_API_URL" ]; then
      validate_api_url "$OPT_API_URL"
    fi
  fi

  # Pre-flight checks before changing anything or escalating privileges
  check_environment

  # Single sudo elevation if not root
  if [ "$(id -u)" -ne 0 ]; then
    if [ "$OPT_UNINSTALL" -eq 1 ]; then
      log_info "Root privileges are required to uninstall tegrad (stopping services and removing system files)."
    else
      log_info "Root privileges are required to install tegrad. This script will:"
      log_info "  - Create system users/groups: ${TEGRAD_USER}, ${TEGRAD_SRV_USER}"
      log_info "  - Create directories: ${TEGRAD_BIN_DIR}, ${TEGRAD_STATE_DIR} (0700), ${TEGRAD_SERVERS_DIR} (2770)"
      log_info "  - Install binary (${TEGRAD_BIN}), wrapper (${TEGRAD_WRAPPER}), systemd units, tmpfiles.d, polkit rule, and network drop-in"
      log_info "  - Reload systemd and enable/start tegrad.service"
    fi
    # Re-exec with sudo using parsed flags
    set --
    [ -n "$OPT_BINARY" ] && set -- "$@" --binary "$OPT_BINARY"
    [ -n "$OPT_VERSION" ] && set -- "$@" --version "$OPT_VERSION"
    [ -n "$OPT_API_URL" ] && set -- "$@" --api-url "$OPT_API_URL"
    # intentional word splitting on validated CIDR list
    # shellcheck disable=SC2086
    for _lan_c in $OPT_ALLOW_LAN; do
      set -- "$@" --allow-lan "$_lan_c"
    done
    [ "$OPT_UNINSTALL" -eq 1 ] && set -- "$@" --uninstall
    [ "$OPT_PURGE" -eq 1 ] && set -- "$@" --purge
    [ "$OPT_YES" -eq 1 ] && set -- "$@" --yes
    exec sudo -- "$0" "$@"
  fi

  if [ "$OPT_UNINSTALL" -eq 1 ]; then
    do_uninstall "$OPT_PURGE" "$OPT_YES"
    exit 0
  fi

  SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
  for _req_file in \
    "${SCRIPT_DIR}/units/tegrad.service" \
    "${SCRIPT_DIR}/units/tegrad-update.path" \
    "${SCRIPT_DIR}/units/tegrad-update.service" \
    "${SCRIPT_DIR}/units/tegrad-server@.service" \
    "${SCRIPT_DIR}/units/tegrad-server@.socket" \
    "${SCRIPT_DIR}/tmpfiles/tegrad.conf" \
    "${SCRIPT_DIR}/polkit/50-tegrad.rules"; do
    if [ ! -f "$_req_file" ]; then
      die "Missing installer asset: $_req_file"
    fi
  done

  BINARY_SRC="$OPT_BINARY"
  if [ -n "$OPT_VERSION" ]; then
    DOWNLOADED_BINARY=""
    fetch_release_binary "$OPT_VERSION"
    BINARY_SRC="$DOWNLOADED_BINARY"
  fi

  log_info "Configuring system users and groups..."
  ensure_users_and_groups

  log_info "Configuring directories..."
  ensure_directories

  log_info "Installing tegrad binary and wrapper..."
  _bin_tmp="${TEGRAD_BIN}.tmp.$$"
  install -o root -g root -m 0755 "$BINARY_SRC" "$_bin_tmp"
  mv -f "$_bin_tmp" "$TEGRAD_BIN"
  install_wrapper

  if [ -n "$OPT_API_URL" ]; then
    ensure_config "$OPT_API_URL" 1
  else
    ensure_config "$DEFAULT_API_URL" 0
  fi

  log_info "Installing systemd units, tmpfiles.d, and polkit rule..."
  render_template_file "${SCRIPT_DIR}/units/tegrad.service" "${SYSTEMD_DIR}/tegrad.service" 0644
  render_template_file "${SCRIPT_DIR}/units/tegrad-update.path" "${SYSTEMD_DIR}/tegrad-update.path" 0644
  render_template_file "${SCRIPT_DIR}/units/tegrad-update.service" "${SYSTEMD_DIR}/tegrad-update.service" 0644
  render_template_file "${SCRIPT_DIR}/units/tegrad-server@.service" "${SYSTEMD_DIR}/tegrad-server@.service" 0644
  render_template_file "${SCRIPT_DIR}/units/tegrad-server@.socket" "${SYSTEMD_DIR}/tegrad-server@.socket" 0644
  render_template_file "${SCRIPT_DIR}/tmpfiles/tegrad.conf" "${TMPFILES_FILE}" 0644
  render_template_file "${SCRIPT_DIR}/polkit/50-tegrad.rules" "${POLKIT_RULE_FILE}" 0644

  if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create "$TMPFILES_FILE"
  else
    install -d -o root -g "$TEGRAD_GROUP" -m 0750 "$TEGRAD_RUN_DIR"
  fi

  log_info "Generating network isolation drop-in..."
  _resolvers=$(collect_resolvers /etc/resolv.conf /run/systemd/resolve/resolv.conf)
  _dropin_tmp="${DROPIN_FILE}.tmp.$$"
  render_network_dropin "$_resolvers" "$OPT_ALLOW_LAN" > "$_dropin_tmp"
  chown root:root "$_dropin_tmp"
  chmod 0644 "$_dropin_tmp"
  mv -f "$_dropin_tmp" "$DROPIN_FILE"

  log_info "Reloading systemd and starting tegrad.service and tegrad-update.path..."
  systemctl daemon-reload
  systemctl enable --now tegrad.service
  systemctl enable --now tegrad-update.path

  log_info "Pronto. Agora, para vincular este servidor, rode \`tegrad link\`."
}

if [ "${TEGRAD_INSTALL_SOURCE_ONLY:-0}" != "1" ]; then
  main "$@"
fi
