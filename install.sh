# Copyright 2025 Nitro Agility S.r.l.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euf

# Minimal, portable installer for permguard CLI
# Usage: ./install.sh [-b bindir] [-d] [-x] [tag]
#   -b  install dir (default: ./bin)
#   -d  debug logs
#   -x  shell trace
#   tag optional Git tag (e.g. v0.0.11 or 0.0.11). If omitted, uses latest.

OWNER="permguard"
REPO="permguard"
PROJECT="permguard"        # used for checksum filename prefix
BINARY="permguard"         # installed binary name

# ----- logging -----
LOG_LEVEL=${LOG_LEVEL:-info} # info|debug
log() { printf '%s %s\n' "[permguard-install]" "$*"; }
dbg() { [ "$LOG_LEVEL" = "debug" ] && log "DEBUG: $*"; return 0; }

# ----- args -----
BINDIR="${BINDIR:-./bin}"
while getopts "b:dxh?" opt; do
  case "$opt" in
    b) BINDIR="$OPTARG" ;;
    d) LOG_LEVEL=debug ;;
    x) set -x ;;
    h|?) printf 'Usage: %s [-b bindir] [-d] [-x] [tag]\n' "$0"; exit 2 ;;
  esac
done
shift $((OPTIND-1))
REQUESTED_TAG="${1:-}"

# ----- utils -----
have() { command -v "$1" >/dev/null 2>&1; }
die() { log "ERROR: $*"; exit 1; }

http_backend() {
  # FORCE: WGET=1 per forzare wget; CURL=1 per forzare curl
  if [ "${WGET:-}" = "1" ] && have wget; then echo wget && return; fi
  if [ "${CURL:-}" = "1" ] && have curl; then echo curl && return; fi
  if have curl; then echo curl && return; fi
  if have wget; then echo wget && return; fi
  echo none
}

http_get() {
  # stdout <- body
  b="$(http_backend)"; [ "$b" = none ] && die "need curl or wget"
  if [ "$b" = curl ]; then
    # Se curl-snap fallisce, prova wget
    curl -fsSL "$1" || { have wget && wget -q -O - "$1"; }
  else
    wget -q -O - "$1" || { have curl && curl -fsSL "$1"; }
  fi
}

http_download() {
  # $1 dest, $2 url
  dbg "GET $2 -> $1"
  b="$(http_backend)"; [ "$b" = none ] && die "need curl or wget"
  if [ "$b" = curl ]; then
    curl -fsSL -o "$1" "$2" || {
      dbg "curl failed, trying wget…"
      have wget && wget -q -O "$1" "$2" || return 1
    }
  else
    wget -q -O "$1" "$2" || {
      dbg "wget failed, trying curl…"
      have curl && curl -fsSL -o "$1" "$2" || return 1
    }
  fi
}

sha256() {
  if have shasum;      then shasum -a 256 "$1" | awk '{print $1}'; return; fi
  if have sha256sum;   then sha256sum     "$1" | awk '{print $1}'; return; fi
  if have gsha256sum;  then gsha256sum    "$1" | awk '{print $1}'; return; fi
  if have openssl;     then openssl dgst -sha256 "$1" | awk '{print $2}'; return; fi
  die "no SHA-256 tool found (shasum/sha256sum/openssl)"
}

verify_sha256() {
  file="$1"; checksums_file="$2"
  base="$(basename "$file")"
  want="$(grep " $base\$" "$checksums_file" 2>/dev/null | awk '{print $1}')"
  [ -n "$want" ] || die "checksum entry for $base not found in $(basename "$checksums_file")"
  got="$(sha256 "$file")"
  [ "$want" = "$got" ] || die "checksum mismatch for $base (want $want, got $got)"
}

mktempdir() {
  if have mktemp; then
    mktemp -d 2>/dev/null || mktemp -d -t permguard
  else
    d="./permguard-tmp.$$"   # non nascosta (evita problemi con curl snap)
    mkdir -p "$d"; echo "$d"
  fi
}

# ----- platform detect -----
uname_os() {
  os="$(uname -s 2>/dev/null | tr '[:upper:]' '[:lower:]' || echo unknown)"
  case "$os" in
    cygwin_nt*|mingw*|msys_nt*) echo windows ;;
    *) echo "$os" ;;
  esac
}
uname_arch() {
  a="$(uname -m 2>/dev/null || echo unknown)"
  case "$a" in
    x86_64) echo amd64 ;;
    i386|i686|x86) echo 386 ;;
    aarch64) echo arm64 ;;
    armv5*|armv6*|armv7*) echo arm ;;
    *) echo "$a" ;;
  esac
}
OS="$(uname_os)"
ARCH="$(uname_arch)"
case "$OS" in linux|darwin|windows) : ;; *) die "unsupported OS: $OS" ;; esac
case "$ARCH" in amd64|arm64|386|arm) : ;; *) die "unsupported arch: $ARCH" ;; esac

# pretty variants for current (Title OS + mapped arch) assets you have
osTitle() {
  case "$OS" in
    linux) echo Linux ;;
    darwin) echo Darwin ;;
    windows) echo Windows ;;
  esac
}
archPretty() {
  case "$ARCH" in
    amd64) echo x86_64 ;;
    386)   echo i386 ;;
    *)     echo "$ARCH" ;;
  esac
}

# ----- release tag -----
if [ -z "$REQUESTED_TAG" ]; then
  log "resolving latest release tag…"
  latest_json="$(curl -fsSL -H "Accept: application/json" "https://github.com/${OWNER}/${REPO}/releases/latest" 2>/dev/null || true)"
  [ -n "$latest_json" ] || latest_json="$(http_get "https://github.com/${OWNER}/${REPO}/releases/latest")"
  TAG="$(printf '%s' "$latest_json" | tr -s '\n' ' ' | sed -n 's/.*"tag_name":"\([^"]*\)".*/\1/p')"
  [ -n "${TAG:-}" ] || die "cannot determine latest tag"
else
  case "$REQUESTED_TAG" in
    -*) die "invalid tag '$REQUESTED_TAG' (for local scripts DO NOT use -- before args)";;
    v*) TAG="$REQUESTED_TAG" ;;
    *)  TAG="v$REQUESTED_TAG" ;;
  esac
fi
VER_NO_V="${TAG#v}"
log "using tag: $TAG"

BASE="https://github.com/${OWNER}/${REPO}/releases/download/${TAG}"

# choose archive extension
EXT="tar.gz"
[ "$OS" = "windows" ] && EXT="zip"

# ---- robust asset selection: try download candidates in order ----
C1="${PROJECT}_cli_$(osTitle)_$(archPretty).${EXT}"   # es: permguard_cli_Linux_arm64.tar.gz
# lowercase variant; map amd64->x86_64, 386->i386
case "$ARCH" in
  amd64) C2="${PROJECT}_cli_${OS}_x86_64.${EXT}" ;;
  386)   C2="${PROJECT}_cli_${OS}_i386.${EXT}" ;;
  *)     C2="${PROJECT}_cli_${OS}_${ARCH}.${EXT}" ;;
esac

tmp="$(mktempdir)"
trap 'rm -rf "$tmp"' EXIT INT HUP TERM

ASSET=""
ARCHIVE=""
for cand in "$C1" "$C2"; do
  try="${tmp}/${cand}"
  if http_download "$try" "${BASE}/${cand}"; then
    ASSET="$cand"
    ARCHIVE="$try"
    dbg "download ok with candidate: $cand"
    break
  else
    dbg "candidate failed: $cand"
    rm -f "$try" || true
  fi
done
[ -n "$ASSET" ] || die "no matching asset found for ${OS}/${ARCH}"

# checksum filename (matches releases: checksums.txt)
CHECKSUM="checksums.txt"
SUMFILE="${tmp}/${CHdECKSUM}"

log "downloading checksums: ${CHECKSUM}"
http_download "$SUMFILE" "${BASE}/${CHECKSUM}"

log "verifying sha256…"
verify_sha256 "$ARCHIVE" "$SUMFILE"

# extract
extract_dir="${tmp}/x"
mkdir -p "$extract_dir"
case "$ASSET" in
  *.tar.gz|*.tgz) tar -C "$extract_dir" --no-same-owner -xzf "$ARCHIVE" ;;
  *.zip)          unzip -q "$ARCHIVE" -d "$extract_dir" ;;
  *) die "unknown archive format: $ASSET" ;;
esac

# find the binary
binname="$BINARY"
[ "$OS" = "windows" ] && binname="${binname}.exe"
found="$( (cd "$extract_dir" && find . -type f -name "$binname" | head -n1) || true )"
[ -n "$found" ] || die "cannot find ${binname} inside archive"

# install
mkdir -p "$BINDIR"
install -m 0755 "${extract_dir}/${found#./}" "${BINDIR}/$binname"
log "installed: ${BINDIR}/$binname"

# friendly note
case ":$PATH:" in
  *:"$BINDIR":*) : ;;
  *) log "note: $BINDIR is not on PATH; add it to use '${BINARY}' directly." ;;
esac
