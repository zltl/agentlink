#!/bin/sh
# Install agentlink on Linux or macOS, verify the release signature and
# checksum, and optionally pair the machine and install the user service.
#
# Recommended onboarding (one-time invite minted by `agentlink pair`):
#   curl -fsSL --proto '=https' --tlsv1.2 https://raw.githubusercontent.com/zltl/agentlink/main/install.sh | \
#     env AGENTLINK_INVITE="agentlink-invite:v1:..." sh -s -- --name laptop
#
# Or with an explicit relay, certificate trust, and one-time pairing token:
#   curl -fsSL --proto '=https' --tlsv1.2 https://raw.githubusercontent.com/zltl/agentlink/main/install.sh | \
#     env AGENTLINK_PAIRING_TOKEN="..." AGENTLINK_FINGERPRINT="sha256:..." sh -s -- \
#     --relay wss://relay.example:7443 \
#     --name laptop
#
# Prefer AGENTLINK_INVITE / AGENTLINK_PAIRING_TOKEN / AGENTLINK_TOKEN in the
# environment so secrets do not appear in `ps` argv. `--invite`,
# `--pairing-token`, and `--token` remain accepted.
#
# On Linux, pass `--desktop` to install the glibc desktop/GUI archive
# (`*-unknown-linux-gnu.tar.gz`) or `--headless` (default archive: static
# `*-unknown-linux-musl.tar.gz`, headless user service).
#
# The agentlink binary parses the relay port. wss://host and wss://host:443 dial
# 443. An explicit port is kept. A bare host with no scheme defaults to 7443.
# Do not append :7443 to a wss:// URL that is served on 443.
# --trust webpki (or --ca system) verifies a public certificate instead of a
# leaf pin. --fingerprint may be `system` or `webpki` as well.
#
# Downloads require https:// (pass --allow-insecure-http or set
# AGENTLINK_ALLOW_INSECURE_HTTP=1 only when intentionally overriding).
# Checksums are always verified. SHA256SUMS.minisig is required and checked
# with the pinned project public key (deploy/minisign.pub) unless
# AGENTLINK_UPDATE_PUBKEY overrides it. minisign must be on PATH (checked before
# downloading the archive). Existing installs can upgrade via
# `agentlink update --yes` without external minisign.

set -eu

REPO="${AGENTLINK_REPO:-zltl/agentlink}"
RELAY="${AGENTLINK_RELAY:-}"
FINGERPRINT="${AGENTLINK_FINGERPRINT:-}"
TRUST="${AGENTLINK_TRUST:-}"
INVITE="${AGENTLINK_INVITE:-}"
TOKEN="${AGENTLINK_TOKEN:-}"
PAIRING="${AGENTLINK_PAIRING_TOKEN:-}"
NAME=""
ACCESS="exec"
MAX_ACCESS="exec"
SCOPE="user"
VERSION="${AGENTLINK_VERSION:-}"
PREFIX=""
NO_SERVICE=0
AUTO=0
DESKTOP=0
HEADLESS=0
ALLOW_INSECURE_HTTP=0
if [ "${AGENTLINK_ALLOW_INSECURE_HTTP:-0}" = "1" ]; then
    ALLOW_INSECURE_HTTP=1
fi
DRY_RUN=0

usage() {
    echo "usage: install.sh [--invite INVITE | --relay URL (--fingerprint sha256:...|system|webpki | --trust system|webpki) (--pairing-token TOKEN | --token ADMIN)] [--name NAME] [--access PRESET] [--max-access PRESET] [--scope user|system] [--version VER] [--prefix DIR] [--auto-update] [--desktop | --headless] [--no-service] [--allow-insecure-http] [--dry-run]" >&2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --relay) RELAY=$2; shift 2 ;;
        --fingerprint) FINGERPRINT=$2; shift 2 ;;
        --trust|--ca) TRUST=$2; shift 2 ;;
        --invite) INVITE=$2; shift 2 ;;
        --token) TOKEN=$2; shift 2 ;;
        --pairing-token) PAIRING=$2; shift 2 ;;
        --name) NAME=$2; shift 2 ;;
        --access) ACCESS=$2; shift 2 ;;
        --max-access) MAX_ACCESS=$2; shift 2 ;;
        --scope) SCOPE=$2; shift 2 ;;
        --version) VERSION=$2; shift 2 ;;
        --prefix) PREFIX=$2; shift 2 ;;
        --auto-update) AUTO=1; shift ;;
        --desktop) DESKTOP=1; shift ;;
        --headless) HEADLESS=1; shift ;;
        --no-service) NO_SERVICE=1; shift ;;
        --allow-insecure-http) ALLOW_INSECURE_HTTP=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage; exit 1 ;;
    esac
done

if [ "$DESKTOP" -eq 1 ] && [ "$HEADLESS" -eq 1 ]; then
    echo "cannot combine --desktop and --headless" >&2
    exit 1
fi

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
    INVITE_DISP=""
    [ -n "$PAIRING" ] && PAIRING_DISP="[redacted]"
    [ -n "$TOKEN" ] && TOKEN_DISP="[redacted]"
    [ -n "$INVITE" ] && INVITE_DISP="[redacted]"
    echo "dry-run os=$OS arch=$ARCH relay=$RELAY fingerprint=$FINGERPRINT pairing=$PAIRING_DISP token=$TOKEN_DISP invite=$INVITE_DISP enroll=${AGENTLINK_ENROLL:-0} download=${AGENTLINK_DOWNLOAD_BASE:-} trust=$TRUST max_access=$MAX_ACCESS desktop=$DESKTOP headless=$HEADLESS"
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
if [ -z "$INVITE" ]; then
    if [ -n "$TOKEN" ] || [ -n "$PAIRING" ]; then
        if [ -z "$RELAY" ]; then
            echo "pass --relay (or --invite) or set AGENTLINK_RELAY / AGENTLINK_INVITE; there is no built-in relay" >&2
            exit 1
        fi
    fi
    if [ "$NO_SERVICE" -eq 0 ] && [ -n "$RELAY" ]; then
        if [ -z "$FINGERPRINT" ] && [ -z "$TRUST" ]; then
            echo "--fingerprint or --trust is required to pair" >&2
            exit 1
        fi
        if [ -z "$TOKEN" ] && [ -z "$PAIRING" ]; then
            echo "pass --pairing-token, --invite, or --token to pair" >&2
            exit 1
        fi
    fi
fi

# Pre-check minisign BEFORE downloading any release archive.
if [ "${AGENTLINK_CHECKSUM_ONLY:-}" != "1" ]; then
    if ! command -v minisign >/dev/null 2>&1; then
        cat >&2 <<'EOF'
minisign is required to verify SHA256SUMS.minisig before downloading the release archive.
Install minisign first:
  macOS:         brew install minisign
  Debian/Ubuntu: sudo apt-get install -y minisign
  Fedora:        sudo dnf install -y minisign
  Arch:          sudo pacman -S minisign
  Alpine:        sudo apk add minisign
If agentlink is already installed, run `agentlink update --yes` instead (it verifies
release signatures in-process with the embedded public key and does not need minisign).
EOF
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

is_loopback_http() {
    case "$1" in
        http://*)
            rest=${1#http://}
            auth=${rest%%/*}
            case "$auth" in
                *@*) return 1 ;;
                127.0.0.1|localhost|\[::1\]) return 0 ;;
                127.0.0.1:*)
                    port=${auth#127.0.0.1:}
                    case "$port" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac
                    ;;
                localhost:*)
                    port=${auth#localhost:}
                    case "$port" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac
                    ;;
                \[::1\]:*)
                    port=${auth#\[::1\]:}
                    case "$port" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac
                    ;;
                *) return 1 ;;
            esac
            ;;
        *) return 1 ;;
    esac
}

check_url() {
    url=$1
    case "$url" in
        https://*) return 0 ;;
        http://*)
            if is_loopback_http "$url"; then
                return 0
            fi
            if [ "$ALLOW_INSECURE_HTTP" -eq 1 ]; then
                echo "warning: allowing insecure http:// URL because --allow-insecure-http / AGENTLINK_ALLOW_INSECURE_HTTP=1 is set: $url" >&2
                return 0
            fi
            echo "refusing non-HTTPS URL: $url (use https://, or pass --allow-insecure-http / AGENTLINK_ALLOW_INSECURE_HTTP=1)" >&2
            exit 1
            ;;
        *)
            echo "refusing unsupported URL scheme: $url (only https:// is allowed)" >&2
            exit 1
            ;;
    esac
}

download() {
    url=$1
    dest=$2
    check_url "$url"
    case "$url" in
        */minisign.pub|*/minisign.pub\?*)
            echo "refusing to fetch a public key from the release host" >&2
            exit 1
            ;;
    esac
    if command -v curl >/dev/null 2>&1; then
        case "$url" in
            https://*)
                curl -fsSL --proto '=https' --tlsv1.2 -o "$dest" -A "agentlink-install" "$url"
                ;;
            *)
                curl -fsSL --proto '=http,https' -o "$dest" -A "agentlink-install" "$url"
                ;;
        esac
    elif command -v wget >/dev/null 2>&1; then
        case "$url" in
            https://*)
                if wget --help 2>&1 | grep -q -- '--https-only'; then
                    wget -q --https-only --secure-protocol=TLSv1_2 -O "$dest" --user-agent="agentlink-install" "$url"
                else
                    wget -q -O "$dest" --user-agent="agentlink-install" "$url"
                fi
                ;;
            *)
                wget -q -O "$dest" --user-agent="agentlink-install" "$url"
                ;;
        esac
    else
        echo "need curl or wget" >&2
        exit 1
    fi
}

fetch_text() {
    url=$1
    check_url "$url"
    if command -v curl >/dev/null 2>&1; then
        case "$url" in
            https://*)
                curl -fsSL --proto '=https' --tlsv1.2 -A "agentlink-install" -H "Accept: application/vnd.github+json" "$url"
                ;;
            *)
                curl -fsSL --proto '=http,https' -A "agentlink-install" -H "Accept: application/vnd.github+json" "$url"
                ;;
        esac
    elif command -v wget >/dev/null 2>&1; then
        case "$url" in
            https://*)
                if wget --help 2>&1 | grep -q -- '--https-only'; then
                    wget -q --https-only --secure-protocol=TLSv1_2 -O - --user-agent="agentlink-install" --header="Accept: application/vnd.github+json" "$url"
                else
                    wget -q -O - --user-agent="agentlink-install" --header="Accept: application/vnd.github+json" "$url"
                fi
                ;;
            *)
                wget -q -O - --user-agent="agentlink-install" --header="Accept: application/vnd.github+json" "$url"
                ;;
        esac
    else
        echo "need curl or wget" >&2
        exit 1
    fi
}

lookup_checksum() {
    awk -v name="$1" '
        $2 == name || $2 == ("*" name) { print $1; exit }
    ' "$2"
}

tmpdir=$(mktemp -d)
tmp_install=""
cleanup() {
    [ -n "$tmp_install" ] && rm -f "$tmp_install"
    rm -rf "$tmpdir"
}
trap cleanup EXIT

sums_downloaded=0
if [ -z "$VERSION" ]; then
    # Public mirrors (AGENTLINK_DOWNLOAD_BASE) ship SHA256SUMS with the current
    # archives. Prefer that over GitHub — private repos 404 without a token.
    if [ -n "${AGENTLINK_DOWNLOAD_BASE:-}" ]; then
        mirror="${AGENTLINK_DOWNLOAD_BASE%/}"
        download "${mirror}/SHA256SUMS" "${tmpdir}/SHA256SUMS" || {
            echo "could not read SHA256SUMS from ${mirror}" >&2
            exit 1
        }
        sums_downloaded=1
        ver=""
        if [ "$OS" = "macos" ]; then
            ver=$(sed -n 's/.*[[:space:]][*]*agentlink-\([0-9][0-9.]*\)-universal-apple-darwin\.tar\.gz$/\1/p' "${tmpdir}/SHA256SUMS" | head -n 1)
            if [ -z "$ver" ]; then
                ver=$(sed -n "s/.*[[:space:]][*]*agentlink-\([0-9][0-9.]*\)-${ARCH}-apple-darwin\.tar\.gz\$/\1/p" "${tmpdir}/SHA256SUMS" | head -n 1)
            fi
        elif [ "$DESKTOP" -eq 1 ]; then
            ver=$(sed -n "s/.*[[:space:]][*]*agentlink-\([0-9][0-9.]*\)-${ARCH}-unknown-linux-gnu\.tar\.gz\$/\1/p" "${tmpdir}/SHA256SUMS" | head -n 1)
        else
            ver=$(sed -n "s/.*[[:space:]][*]*agentlink-\([0-9][0-9.]*\)-${ARCH}-unknown-linux-musl\.tar\.gz\$/\1/p" "${tmpdir}/SHA256SUMS" | head -n 1)
            if [ -z "$ver" ] && [ "$HEADLESS" -eq 0 ]; then
                ver=$(sed -n "s/.*[[:space:]][*]*agentlink-\([0-9][0-9.]*\)-${ARCH}-unknown-linux-gnu\.tar\.gz\$/\1/p" "${tmpdir}/SHA256SUMS" | head -n 1)
            fi
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

if [ -n "${AGENTLINK_DOWNLOAD_BASE:-}" ]; then
    base="${AGENTLINK_DOWNLOAD_BASE%/}"
else
    base="https://github.com/${REPO}/releases/download/${tag}"
fi

# Fetch and signature-verify SHA256SUMS BEFORE downloading the release archive.
if [ "$sums_downloaded" -eq 0 ]; then
    download "${base}/SHA256SUMS" "${tmpdir}/SHA256SUMS"
fi

# Pinned project key. Same material as deploy/minisign.pub.
EMBEDDED_PUBKEY='untrusted comment: minisign public key
RWTCrF4TYAywjeqH2h25khhV1Ska9eBdU0l2FdPvtYp0b7emGttpZmcx'
if [ "${AGENTLINK_CHECKSUM_ONLY:-}" != "1" ]; then
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

# Pick the matching archive from the verified SHA256SUMS manifest.
asset=""
want=""
if [ "$OS" = "macos" ]; then
    for cand in \
        "agentlink-${ver}-universal-apple-darwin.tar.gz" \
        "agentlink-${ver}-${ARCH}-apple-darwin.tar.gz"; do
        want=$(lookup_checksum "$cand" "${tmpdir}/SHA256SUMS")
        if [ -n "$want" ]; then
            asset=$cand
            break
        fi
    done
    if [ -z "$asset" ]; then
        asset="agentlink-${ver}-universal-apple-darwin.tar.gz"
    fi
elif [ "$DESKTOP" -eq 1 ]; then
    asset="agentlink-${ver}-${ARCH}-unknown-linux-gnu.tar.gz"
    want=$(lookup_checksum "$asset" "${tmpdir}/SHA256SUMS")
    if [ -z "$want" ]; then
        echo "SHA256SUMS has no Linux glibc desktop archive (${asset}); pass --headless for the static musl archive or build with cargo" >&2
        exit 1
    fi
else
    asset="agentlink-${ver}-${ARCH}-unknown-linux-musl.tar.gz"
    want=$(lookup_checksum "$asset" "${tmpdir}/SHA256SUMS")
    if [ -z "$want" ] && [ "$HEADLESS" -eq 0 ]; then
        fallback="agentlink-${ver}-${ARCH}-unknown-linux-gnu.tar.gz"
        want=$(lookup_checksum "$fallback" "${tmpdir}/SHA256SUMS")
        if [ -n "$want" ]; then
            asset=$fallback
        fi
    fi
fi

if [ -z "$want" ]; then
    echo "SHA256SUMS has no entry for ${asset}" >&2
    exit 1
fi

download "${base}/${asset}" "${tmpdir}/${asset}"

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

tar -xzf "${tmpdir}/${asset}" -C "$tmpdir"
if [ ! -f "${tmpdir}/agentlink" ]; then
    echo "archive did not contain agentlink" >&2
    exit 1
fi

mkdir -p "$PREFIX"
install_bin="${PREFIX}/agentlink"
# Stage beside the destination and atomically rename to avoid ETXTBSY when
# upgrading over a running binary on Linux.
tmp_install="${install_bin}.tmp.$$"
cp "${tmpdir}/agentlink" "$tmp_install"
chmod 755 "$tmp_install"
mv -f "$tmp_install" "$install_bin"
tmp_install=""

case ":$PATH:" in
    *":${PREFIX}:"*) ;;
    *) echo "installed ${install_bin}; add ${PREFIX} to PATH if your shell does not search it" >&2 ;;
esac

if [ "$NO_SERVICE" -eq 1 ] || { [ -z "$RELAY" ] && [ -z "$INVITE" ]; }; then
    echo "installed ${install_bin}" >&2
    if [ "$NO_SERVICE" -eq 0 ]; then
        echo "pass --invite 'agentlink-invite:v1:...' (or --relay, --fingerprint or --trust, and --pairing-token) to pair and install the service" >&2
    fi
    exit 0
fi

if [ -z "$NAME" ]; then
    NAME=$(uname -n)
fi

install_service() {
    bin=$1
    set -- "$bin"
    if [ -n "$RELAY" ]; then
        set -- "$@" --relay "$RELAY"
    fi
    if [ -n "$FINGERPRINT" ]; then
        set -- "$@" --fingerprint "$FINGERPRINT"
    fi
    if [ -n "$TRUST" ]; then
        set -- "$@" --trust "$TRUST"
    fi
    # Prefer env for pairing/admin tokens so they are not visible in `ps` argv.
    if [ -n "$PAIRING" ]; then
        export AGENTLINK_PAIRING_TOKEN="$PAIRING"
    fi
    if [ -n "$TOKEN" ]; then
        export AGENTLINK_TOKEN="$TOKEN"
    elif [ "${AGENTLINK_ENROLL:-0}" = "1" ]; then
        unset AGENTLINK_TOKEN || true
    fi
    set -- "$@" service install --scope "$SCOPE" --name "$NAME" --access "$ACCESS"
    if [ -n "$INVITE" ]; then
        set -- "$@" --invite "$INVITE"
    fi
    if [ -n "$MAX_ACCESS" ]; then
        set -- "$@" --max-access "$MAX_ACCESS"
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
