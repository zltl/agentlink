# Install agentlink on Windows, verify the release checksum, and optionally
# pair the machine and install the service.
#
# User scope (the default) registers start-on-login in
# HKCU\Software\Microsoft\Windows\CurrentVersion\Run. That starts the tray at
# sign-in. It does not use a scheduled task and does not need an administrator.
# System scope registers a Windows service. That service runs in session 0 and
# cannot drive the desktop.
#
#   $env:AGENTLINK_RELAY = "wss://relay.example:7443"
#   $env:AGENTLINK_FINGERPRINT = "sha256:..."
#   $env:AGENTLINK_TOKEN = "..."
#   irm https://raw.githubusercontent.com/zltl/agentlink/main/install.ps1 | iex
#
# The agentlink binary parses the relay port. wss://host and wss://host:443 dial
# 443. An explicit port is kept. A bare host with no scheme defaults to 7443.
# Do not append :7443 to a wss:// URL that is served on 443.
# -Trust webpki (or -Ca system) verifies a public certificate. -Fingerprint may
# be system or webpki as well.
#
# Or, after saving this file:
#   ./install.ps1 -Relay wss://relay.example:7443 -Fingerprint sha256:... -Token $env:AGENTLINK_TOKEN -Name laptop
#
# Checksums are always verified. SHA256SUMS.minisig is required and checked
# with the pinned project public key unless AGENTLINK_UPDATE_PUBKEY overrides
# it. Set AGENTLINK_CHECKSUM_ONLY=1 to skip the signature (not the default).
# minisign must be on PATH.

[CmdletBinding()]
param(
    [string]$Relay = $env:AGENTLINK_RELAY,
    [string]$Fingerprint = $env:AGENTLINK_FINGERPRINT,
    [string]$Trust = $(if ($env:AGENTLINK_TRUST) { $env:AGENTLINK_TRUST } else { $env:AGENTLINK_CA }),
    [string]$Token = $env:AGENTLINK_TOKEN,
    [string]$PairingToken = $env:AGENTLINK_PAIRING_TOKEN,
    [string]$Name = $env:COMPUTERNAME,
    [ValidateSet("read-only", "read-write", "exec", "desktop", "remote-view", "remote-control", "full", "all", "full-access", "full_access")]
    [string]$Access = "full",
    [string]$MaxAccess = "full",
    [ValidateSet("user", "system")]
    [string]$Scope = "user",
    [string]$Version = $env:AGENTLINK_VERSION,
    [string]$Repo = $(if ($env:AGENTLINK_REPO) { $env:AGENTLINK_REPO } else { "zltl/agentlink" }),
    [string]$Prefix = "",
    [switch]$NoService,
    [switch]$AutoUpdate,
    [switch]$Headless,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch {}

# Replaced by the relay when this script is served from /install.ps1.
$AgentlinkServeRelay = ""
$AgentlinkServeFingerprint = ""
$AgentlinkServeDownload = ""
$AgentlinkServeEnroll = "0"
if (-not $Relay -and $AgentlinkServeRelay) { $Relay = $AgentlinkServeRelay }
if (-not $Fingerprint -and $AgentlinkServeFingerprint) { $Fingerprint = $AgentlinkServeFingerprint }
if ($AgentlinkServeEnroll -eq "1" -and $Token -and -not $PairingToken) {
    $PairingToken = $Token
    $Token = ""
}
if ($DryRun) {
    $pairingDisp = if ($PairingToken) { "[redacted]" } else { "" }
    $tokenDisp = if ($Token) { "[redacted]" } else { "" }
    $dlDisp = if ($AgentlinkServeDownload) { $AgentlinkServeDownload } elseif ($env:AGENTLINK_DOWNLOAD_BASE) { $env:AGENTLINK_DOWNLOAD_BASE } else { "" }
    Write-Output "dry-run enroll=$AgentlinkServeEnroll relay=$Relay pairing=$pairingDisp token=$tokenDisp download=$dlDisp"
    exit 0
}

function Get-AgentlinkText([string]$Url) {
    Invoke-RestMethod -Uri $Url -Headers @{
        "User-Agent" = "agentlink-install"
        "Accept"     = "application/vnd.github+json"
    }
}

function Save-AgentlinkFile([string]$Url, [string]$Dest) {
    if ($Url -match '/minisign\.pub($|\?)') {
        throw "refusing to download a public key from the release host"
    }
    Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing -Headers @{ "User-Agent" = "agentlink-install" }
}

$arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "aarch64" } else { "x86_64" }
$downloadOverride = if ($AgentlinkServeDownload) { $AgentlinkServeDownload.TrimEnd("/") } elseif ($env:AGENTLINK_DOWNLOAD_BASE) { $env:AGENTLINK_DOWNLOAD_BASE.TrimEnd("/") } else { "" }
if (-not $Version) {
    if ($downloadOverride) {
        $sumsRaw = (Invoke-WebRequest -Uri "$downloadOverride/SHA256SUMS" -UseBasicParsing -Headers @{ "User-Agent" = "agentlink-install" }).Content
        if ($sumsRaw -match "agentlink-([0-9][0-9.]*)-$arch-pc-windows-msvc\.zip") {
            $tag = "v" + $Matches[1]
        } else {
            throw "SHA256SUMS at $downloadOverride has no archive for windows/$arch"
        }
    } else {
        $latest = Get-AgentlinkText "https://api.github.com/repos/$Repo/releases/latest"
        $tag = $latest.tag_name
        if (-not $tag) { throw "could not read the latest release tag" }
    }
} elseif ($Version.StartsWith("v")) {
    $tag = $Version
} else {
    $tag = "v$Version"
}
$ver = $tag.TrimStart("v")
$asset = "agentlink-$ver-$arch-pc-windows-msvc.zip"
if ($downloadOverride) {
    $base = $downloadOverride
} else {
    $base = "https://github.com/$Repo/releases/download/$tag"
}
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("agentlink-install-" + [guid]::NewGuid().ToString("n"))
New-Item -ItemType Directory -Path $tmp | Out-Null

try {
    $archive = Join-Path $tmp $asset
    $sumsFile = Join-Path $tmp "SHA256SUMS"
    Save-AgentlinkFile "$base/$asset" $archive
    Save-AgentlinkFile "$base/SHA256SUMS" $sumsFile
    $want = $null
    foreach ($line in Get-Content $sumsFile) {
        $parts = $line.Trim() -split "\s+"
        if ($parts.Length -ge 2 -and ($parts[1] -eq $asset -or $parts[1] -eq "*$asset")) {
            $want = $parts[0].ToLower()
            break
        }
    }
    if (-not $want) { throw "SHA256SUMS has no entry for $asset" }
    $got = (Get-FileHash -Algorithm SHA256 $archive).Hash.ToLower()
    if ($want -ne $got) { throw "checksum mismatch for $asset" }

    if ($env:AGENTLINK_CHECKSUM_ONLY -ne "1") {
        $minisign = Get-Command minisign -ErrorAction SilentlyContinue
        if (-not $minisign) { throw "minisign is required to verify SHA256SUMS (or set AGENTLINK_CHECKSUM_ONLY=1)" }
        $sig = Join-Path $tmp "SHA256SUMS.minisig"
        Save-AgentlinkFile "$base/SHA256SUMS.minisig" $sig
        $embedded = "untrusted comment: minisign public key`nRWTCrF4TYAywjeqH2h25khhV1Ska9eBdU0l2FdPvtYp0b7emGttpZmcx"
        $pubkey = if ($env:AGENTLINK_UPDATE_PUBKEY) { $env:AGENTLINK_UPDATE_PUBKEY } else { $embedded }
        if (Test-Path $pubkey) {
            $pubfile = $pubkey
        } else {
            $pubfile = Join-Path $tmp "minisign.pub"
            Set-Content -Path $pubfile -Value $pubkey -Encoding ascii
        }
        & minisign -V -p $pubfile -x $sig -m $sumsFile
        if ($LASTEXITCODE -ne 0) { throw "minisign rejected SHA256SUMS" }
    }

    Expand-Archive -Path $archive -DestinationPath $tmp -Force
    $extracted = Join-Path $tmp "agentlink.exe"
    if (-not (Test-Path $extracted)) { throw "archive did not contain agentlink.exe" }

    if (-not $Prefix) {
        if ($Scope -eq "system") {
            $Prefix = Join-Path $env:ProgramFiles "agentlink"
        } else {
            $Prefix = Join-Path $env:LOCALAPPDATA "agentlink"
        }
    }
    New-Item -ItemType Directory -Path $Prefix -Force | Out-Null
    $dest = Join-Path $Prefix "agentlink.exe"
    Copy-Item $extracted $dest -Force

    if (($Token -or $PairingToken) -and -not $Relay) {
        throw "pass -Relay or set AGENTLINK_RELAY; there is no built-in relay"
    }
    if ($NoService -or -not $Relay) {
        Write-Host "installed $dest"
        if (-not $NoService) {
            Write-Host "pass -Relay, -Fingerprint or -Trust, and -Token or -PairingToken to pair"
        }
        return
    }
    if (-not $Fingerprint -and -not $Trust) { throw "-Fingerprint or -Trust is required to pair" }
    if (-not $Token -and -not $PairingToken) { throw "pass -Token or -PairingToken to pair" }

    $argList = @("--relay", $Relay)
    if ($Fingerprint) { $argList += @("--fingerprint", $Fingerprint) }
    if ($Trust) { $argList += @("--trust", $Trust) }
    # Prefer env for the admin token so it is not visible in process argv.
    if ($Token) { $env:AGENTLINK_TOKEN = $Token }
    $argList += @("service", "install", "--scope", $Scope, "--name", $Name, "--access", $Access)
    if ($MaxAccess) { $argList += @("--max-access", $MaxAccess) }
    if ($PairingToken) { $argList += @("--pairing-token", $PairingToken) }
    if ($AutoUpdate) { $argList += "--auto-update" }
    if ($Headless) { $argList += "--headless" }
    & $dest @argList
    if ($LASTEXITCODE -ne 0) { throw "agentlink service install failed" }
    Write-Host "agentlink $ver is installed at $dest"
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
