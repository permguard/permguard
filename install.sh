#!/usr/bin/env sh
set -euf

# Minimal, portable installer for permguard CLI
# Usage: ./install-permguard.sh [-b bindir] [-d] [-x] [tag]
#   -b  install dir (default: ./bin)
#   -d  debug logs
#   -x  shell trace
#   tag optional Git tag (e.g. v0.0.10). If omitted, uses latest.

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

http_get() {
  # stdout <- body
  if have curl; then
    curl -fsSL "$1"
  elif have wget; then
    wget -q -O - "$1"
  else
    die "need curl or wget"
  fi
}

http_download() {
  # $1 dest, $2 url
  dbg "GET $2 -> $1"
  if have curl; then
    curl -fsSL -o "$1" "$2"
  else
    wget -q -O "$1" "$2"
  fi
}

sha256() {
  if have shasum;   then shasum -a 256 "$1" | awk '{print $1}'; return; fi
  if have sha256sum;then sha256sum     "$1" | awk '{print $1}'; return; fi
  if have gsha256sum; then gsha256sum  "$1" | awk '{print $1}'; return; fi
  if have openssl;  then openssl dgst -sha256 "$1" | awk '{print $2}'; return; fi
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
  if have mktemp; then mktemp -d 2>/dev/null || mktemp -d -t permguard; else
    d="./.permguard-tmp.$$"; mkdir -p "$d"; echo "$d"
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
  latest_json="$(http_get "https://github.com/${OWNER}/${REPO}/releases/latest" || true)"
  # GitHub returns a HTML/JSON hybrid; use API-like header to get JSON if possible:
  if [ -z "$latest_json" ]; then
    latest_json="$( http_get "https://github.com/${OWNER}/${REPO}/releases/latest" )"
  fi
  # fallback to API redirect JSON (Accept:application/json)
  latest_json="$(curl -fsSL -H "Accept: application/json" "https://github.com/${OWNER}/${REPO}/releases/latest" 2>/dev/null || true)"
  TAG="$(printf '%s' "$latest_json" | tr -s '\n' ' ' | sed -n 's/.*"tag_name":"\([^"]*\)".*/\1/p')"
  [ -n "${TAG:-}" ] || die "cannot determine latest tag"
else
  TAG="$REQUESTED_TAG"
fi
VER_NO_V="${TAG#v}"
log "using tag: $TAG"

BASE="https://github.com/${OWNER}/${REPO}/releases/download/${TAG}"

# choose archive extension
EXT="tar.gz"
[ "$OS" = "windows" ] && EXT="zip"

# candidate asset names (both current TitleCase pattern and all-lowercase)
C1="${PROJECT}_cli_$(osTitle)_$(archPretty).${EXT}"
C2="${PROJECT}_cli_${OS}_${ARCH}"
case "$ARCH" in
  amd64) C2="${C2/_amd64/_x86_64}" ;;  # your artifacts use x86_64
  386)   C2="${C2/_386/_i386}" ;;
esac
C2="${C2}.${EXT}"

ASSET=""
for cand in "$C1" "$C2"; do
  # HEAD check (cheap existence test)
  if have curl; then
    code="$(curl -sIL -o /dev/null -w '%{http_code}' "${BASE}/${cand}" || true)"
  else
    code="$(wget --spider -q "${BASE}/${cand}" >/dev/null 2>&1; echo $?)"
    [ "$code" = "0" ] && code=200
  fi
  dbg "probe ${cand} -> ${code}"
  [ "${code}" = "200" ] && { ASSET="$cand"; break; }
done
[ -n "$ASSET" ] || die "no matching asset found for ${OS}/${ARCH}"

# checksum filename (matches your releases: permguard_<version>_checksums.txt)
CHECKSUM="${PROJECT}_${VER_NO_V}_checksums.txt"

tmp="$(mktempdir)"
trap 'rm -rf "$tmp"' EXIT INT HUP TERM

ARCHIVE="${tmp}/${ASSET}"
SUMFILE="${tmp}/${CHECKSUM}"

log "downloading: ${ASSET}"
http_download "$ARCHIVE" "${BASE}/${ASSET}"

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

# find the binary (supports archives that contain it at root)
binname="$BINARY"
[ "$OS" = "windows" ] && binname="${binname}.exe"
found="$( (cd "$extract_dir" && find . -type f -name "$binname" -maxdepth 2 | head -n1) || true )"
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
