#!/bin/sh
# Install agentlink on Linux or macOS, verify the release checksum, and
# optionally pair the machine and install the user service.
#
#   curl -fsSL https://raw.githubusercontent.com/zltl/agentlink/main/install.sh | sh -s -- \
#     --relay wss://relay.example:7443 \
#     --fingerprint "sha256:..." \
#     --token "$AGENTLINK_TOKEN" \
#     --name laptop
#
# The agentlink binary parses the relay port. wss://host and wss://host:443 dial
# 443. An explicit port is kept. A bare host with no scheme defaults to 7443.
# Do not append :7443 to a wss:// URL that is served on 443.
# --trust webpki (or --ca system) verifies a public certificate instead of a
# leaf pin. --fingerprint may be `system` or `webpki` as well.
#
# --token is the relay admin token. The installer mints a one-time pairing
# token and stores it in the node data directory, not in the service unit.
# Pass --pairing-token instead when you already have one.
#
# Checksums are always verified. SHA256SUMS.minisig is required and checked
# with the pinned project public key (deploy/minisign.pub) unless
# AGENTLINK_UPDATE_PUBKEY overrides it. Set AGENTLINK_CHECKSUM_ONLY=1 to skip
# the signature (not the default). minisign must be on PATH.

set -eu

REPO="${AGENTLINK_REPO:-zltl/agentlink}"
RELAY="${AGENTLINK_RELAY:-}"
FINGERPRINT="${AGENTLINK_FINGERPRINT:-}"
TRUST="${AGENTLINK_TRUST:-}"
TOKEN="${AGENTLINK_TOKEN:-}"
PAIRING="${AGENTLINK_PAIRING_TOKEN:-}"
NAME=""
ACCESS="full"
MAX_ACCESS="full"
SCOPE="user"
VERSION="${AGENTLINK_VERSION:-}"
PREFIX=""
NO_SERVICE=0
AUTO=0
HEADLESS=0
DRY_RUN=0

usage() {
    echo "usage: install.sh --relay URL (--fingerprint sha256:...|system|webpki | --trust system|webpki) (--token ADMIN | --pairing-token TOKEN) [--name NAME] [--access PRESET] [--max-access PRESET] [--scope user|system] [--version VER] [--prefix DIR] [--auto-update] [--headless] [--no-service]" >&2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --relay) RELAY=$2; shift 2 ;;
        --fingerprint) FINGERPRINT=$2; shift 2 ;;
        --trust|--ca) TRUST=$2; shift 2 ;;
        --token) TOKEN=$2; shift 2 ;;
        --pairing-token) PAIRING=$2; shift 2 ;;
        --name) NAME=$2; shift 2 ;;
        --access) ACCESS=$2; shift 2 ;;
        --max-access) MAX_ACCESS=$2; shift 2 ;;
        --scope) SCOPE=$2; shift 2 ;;
        --version) VERSION=$2; shift 2 ;;
        --prefix) PREFIX=$2; shift 2 ;;
        --auto-update) AUTO=1; shift ;;
        --headless) HEADLESS=1; shift ;;
        --no-service) NO_SERVICE=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage; exit 1 ;;
    esac
done

OS=$(uname -s)
ARCH=$(uname -m)
case "$OS" in
    Linux) OS=linux ;;
    Darwin) OS=macos ;;
    *) echo "unsupported OS: $OS" >&2; exit 1 ;;
esac
case "$ARCH" in
    x86_64|amd64) ARCH=x86_64 ;;
    aarch64|arm64) ARCH=aarch64 ;;
    *) echo "unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

if [ "${AGENTLINK_ENROLL:-0}" = "1" ] && [ -n "$TOKEN" ] && [ -z "$PAIRING" ]; then
    PAIRING=$TOKEN
    TOKEN=""
fi

if [ "$DRY_RUN" -eq 1 ]; then
    PAIRING_DISP=""
    TOKEN_DISP=""
    [ -n "$PAIRING" ] && PAIRING_DISP="[redacted]"
    [ -n "$TOKEN" ] && TOKEN_DISP="[redacted]"
    echo "dry-run os=$OS arch=$ARCH relay=$RELAY fingerprint=$FINGERPRINT pairing=$PAIRING_DISP token=$TOKEN_DISP enroll=${AGENTLINK_ENROLL:-0} download=${AGENTLINK_DOWNLOAD_BASE:-} trust=$TRUST max_access=$MAX_ACCESS"
    exit 0
fi

if [ "$SCOPE" != "user" ] && [ "$SCOPE" != "system" ]; then
    echo "--scope must be user or system" >&2
    exit 1
fi
if [ "$SCOPE" = "system" ] && [ "$(id -u)" -ne 0 ]; then
    echo "system scope writes /etc or /Library and needs root" >&2
    exit 1
fi
if [ -n "$TOKEN" ] || [ -n "$PAIRING" ]; then
    if [ -z "$RELAY" ]; then
        echo "pass --relay or set AGENTLINK_RELAY; there is no built-in relay" >&2
        exit 1
    fi
fi
if [ "$NO_SERVICE" -eq 0 ] && [ -n "$RELAY" ]; then
    if [ -z "$FINGERPRINT" ] && [ -z "$TRUST" ]; then
        echo "--fingerprint or --trust is required to pair" >&2
        exit 1
    fi
    if [ -z "$TOKEN" ] && [ -z "$PAIRING" ]; then
        echo "pass --token or --pairing-token to pair" >&2
        exit 1
    fi
fi

if [ -z "$PREFIX" ]; then
    if [ "$SCOPE" = "system" ] || [ "$(id -u)" -eq 0 ]; then
        PREFIX=/usr/local/bin
    else
        PREFIX="${HOME}/.local/bin"
    fi
fi

download() {
    url=$1
    dest=$2
    case "$url" in
        */minisign.pub|*/minisign.pub\?*)
            echo "refusing to download a public key from the release host" >&2
            exit 1
            ;;
    esac
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$dest" -A "agentlink-install" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$dest" --user-agent="agentlink-install" "$url"
    else
        echo "need curl or wget" >&2
        exit 1
    fi
}

fetch_text() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -A "agentlink-install" -H "Accept: application/vnd.github+json" "$1"
    else
        wget -q -O - --user-agent="agentlink-install" --header="Accept: application/vnd.github+json" "$1"
    fi
}

if [ -z "$VERSION" ]; then
    # Public mirrors (AGENTLINK_DOWNLOAD_BASE) ship SHA256SUMS with the current
    # archives. Prefer that over GitHub — private repos 404 without a token.
    if [ -n "${AGENTLINK_DOWNLOAD_BASE:-}" ]; then
        mirror="${AGENTLINK_DOWNLOAD_BASE%/}"
        sums=$(fetch_text "${mirror}/SHA256SUMS") || {
            echo "could not read SHA256SUMS from ${mirror}" >&2
            exit 1
        }
        if [ "$OS" = "macos" ]; then
            ver=$(printf '%s\n' "$sums" | sed -n 's/.*[[:space:]]agentlink-\([0-9][0-9.]*\)-universal-apple-darwin\.tar\.gz$/\1/p' | head -n 1)
            if [ -z "$ver" ]; then
                ver=$(printf '%s\n' "$sums" | sed -n "s/.*[[:space:]]agentlink-\([0-9][0-9.]*\)-${ARCH}-apple-darwin\.tar\.gz\$/\1/p" | head -n 1)
            fi
        else
            ver=$(printf '%s\n' "$sums" | sed -n "s/.*[[:space:]]agentlink-\([0-9][0-9.]*\)-${ARCH}-unknown-linux-musl\.tar\.gz\$/\1/p" | head -n 1)
        fi
        if [ -z "$ver" ]; then
            echo "SHA256SUMS at ${mirror} has no archive for ${OS}/${ARCH}" >&2
            exit 1
        fi
        tag="v${ver}"
    else
        body=$(fetch_text "https://api.github.com/repos/${REPO}/releases/latest")
        tag=$(printf '%s\n' "$body" | tr ',' '\n' | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
        if [ -z "$tag" ]; then
            echo "could not read the latest release tag from GitHub (set AGENTLINK_DOWNLOAD_BASE to a mirror that serves SHA256SUMS, or pass --version)" >&2
            exit 1
        fi
    fi
else
    case "$VERSION" in
        v*) tag=$VERSION ;;
        *) tag="v${VERSION}" ;;
    esac
fi
ver=${tag#v}

if [ "$OS" = "macos" ]; then
    asset="agentlink-${ver}-universal-apple-darwin.tar.gz"
else
    asset="agentlink-${ver}-${ARCH}-unknown-linux-musl.tar.gz"
fi

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
if [ -n "${AGENTLINK_DOWNLOAD_BASE:-}" ]; then
    base="${AGENTLINK_DOWNLOAD_BASE%/}"
else
    base="https://github.com/${REPO}/releases/download/${tag}"
fi
download "${base}/${asset}" "${tmpdir}/${asset}"
download "${base}/SHA256SUMS" "${tmpdir}/SHA256SUMS"

want=$(awk -v name="$asset" '
    $2 == name || $2 == ("*" name) { print $1; exit }
' "${tmpdir}/SHA256SUMS")
if [ -z "$want" ]; then
    echo "SHA256SUMS has no entry for ${asset}" >&2
    exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
    got=$(sha256sum "${tmpdir}/${asset}" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    got=$(shasum -a 256 "${tmpdir}/${asset}" | awk '{print $1}')
else
    echo "need sha256sum or shasum to verify the download" >&2
    exit 1
fi
want=$(printf '%s' "$want" | tr 'A-F' 'a-f')
got=$(printf '%s' "$got" | tr 'A-F' 'a-f')
if [ "$want" != "$got" ]; then
    echo "checksum mismatch for ${asset}" >&2
    exit 1
fi

# Pinned project key. Same material as deploy/minisign.pub.
EMBEDDED_PUBKEY='untrusted comment: minisign public key
RWTCrF4TYAywjeqH2h25khhV1Ska9eBdU0l2FdPvtYp0b7emGttpZmcx'
if [ "${AGENTLINK_CHECKSUM_ONLY:-}" != "1" ]; then
    if ! command -v minisign >/dev/null 2>&1; then
        echo "minisign is required to verify SHA256SUMS (or set AGENTLINK_CHECKSUM_ONLY=1)" >&2
        exit 1
    fi
    download "${base}/SHA256SUMS.minisig" "${tmpdir}/SHA256SUMS.minisig"
    pubkey="${AGENTLINK_UPDATE_PUBKEY:-$EMBEDDED_PUBKEY}"
    if [ -f "$pubkey" ]; then
        pubfile=$pubkey
    else
        pubfile=${tmpdir}/minisign.pub
        printf '%s\n' "$pubkey" > "$pubfile"
    fi
    if ! minisign -V -p "$pubfile" -x "${tmpdir}/SHA256SUMS.minisig" -m "${tmpdir}/SHA256SUMS"; then
        echo "minisign rejected SHA256SUMS" >&2
        exit 1
    fi
fi

tar -xzf "${tmpdir}/${asset}" -C "$tmpdir"
if [ ! -f "${tmpdir}/agentlink" ]; then
    echo "archive did not contain agentlink" >&2
    exit 1
fi

mkdir -p "$PREFIX"
install_bin="${PREFIX}/agentlink"
cp "${tmpdir}/agentlink" "$install_bin"
chmod 755 "$install_bin"

case ":$PATH:" in
    *":${PREFIX}:"*) ;;
    *) echo "installed ${install_bin}; add ${PREFIX} to PATH if your shell does not search it" >&2 ;;
esac

if [ "$NO_SERVICE" -eq 1 ] || [ -z "$RELAY" ]; then
    echo "installed ${install_bin}" >&2
    if [ "$NO_SERVICE" -eq 0 ]; then
        echo "pass --relay, --fingerprint or --trust, and --token to pair and install the service" >&2
    fi
    exit 0
fi

if [ -z "$NAME" ]; then
    NAME=$(uname -n)
fi

install_service() {
    bin=$1
    set -- "$bin" --relay "$RELAY"
    if [ -n "$FINGERPRINT" ]; then
        set -- "$@" --fingerprint "$FINGERPRINT"
    fi
    if [ -n "$TRUST" ]; then
        set -- "$@" --trust "$TRUST"
    fi
    # Prefer env for the admin token so it is not visible in `ps` argv.
    if [ -n "$TOKEN" ]; then
        export AGENTLINK_TOKEN="$TOKEN"
    fi
    set -- "$@" service install --scope "$SCOPE" --name "$NAME" --access "$ACCESS"
    if [ -n "$MAX_ACCESS" ]; then
        set -- "$@" --max-access "$MAX_ACCESS"
    fi
    if [ -n "$PAIRING" ]; then
        set -- "$@" --pairing-token "$PAIRING"
    fi
    if [ "$AUTO" -eq 1 ]; then
        set -- "$@" --auto-update
    fi
    if [ "$HEADLESS" -eq 1 ]; then
        set -- "$@" --headless
    fi
    "$@"
}

install_service "$install_bin"
echo "agentlink ${ver} is installed at ${install_bin}" >&2
