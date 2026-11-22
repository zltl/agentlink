# Install agentlink on Windows, verify the release signature and checksum, add
# the install directory to PATH, and optionally pair the machine and install
# the background service.
#
# User scope (the default) installs `agentlink.exe` (console CLI) and
# `agentlink-gui.exe` (GUI launcher, when present in the archive) into
# %LOCALAPPDATA%\agentlink, adds it to the current user's PATH (opt out with
# -NoPath or AGENTLINK_NO_PATH=1), and registers start-on-login in
# HKCU\Software\Microsoft\Windows\CurrentVersion\Run. That starts the tray at
# sign-in without a scheduled task or administrator privileges.
# System scope registers a Windows service in session 0 (cannot drive desktop).
#
# Recommended onboarding (one-time invite minted by `agentlink pair`):
#   $env:AGENTLINK_INVITE = "agentlink-invite:v1:..."
#   irm https://raw.githubusercontent.com/zltl/agentlink/main/install.ps1 | iex
#
# Or with an explicit relay, certificate trust, and one-time pairing token:
#   $env:AGENTLINK_RELAY = "wss://relay.example:7443"
#   $env:AGENTLINK_FINGERPRINT = "sha256:..."
#   $env:AGENTLINK_PAIRING_TOKEN = "..."
#   irm https://raw.githubusercontent.com/zltl/agentlink/main/install.ps1 | iex
#
# The agentlink binary parses the relay port. wss://host and wss://host:443 dial
# 443. An explicit port is kept. A bare host with no scheme defaults to 7443.
# Do not append :7443 to a wss:// URL that is served on 443.
# -Trust webpki (or -Ca system) verifies a public certificate. -Fingerprint may
# be system or webpki as well.
#
# Or, after saving this file:
#   ./install.ps1 -Invite "agentlink-invite:v1:..." -Name laptop
#   ./install.ps1 -Relay wss://relay.example:7443 -Fingerprint sha256:... -PairingToken $env:AGENTLINK_PAIRING_TOKEN -Name laptop
#
# Downloads require https:// (pass -AllowInsecureHttp or set
# AGENTLINK_ALLOW_INSECURE_HTTP=1 only when intentionally overriding).
# Checksums are always verified. SHA256SUMS.minisig is required and checked
# with the pinned project public key unless AGENTLINK_UPDATE_PUBKEY overrides
# it. minisign must be on PATH (checked before downloading the archive).
# Existing installs can upgrade via `agentlink update --yes` without minisign.

[CmdletBinding()]
param(
    [string]$Relay = $env:AGENTLINK_RELAY,
    [string]$Fingerprint = $env:AGENTLINK_FINGERPRINT,
    [string]$Trust = $(if ($env:AGENTLINK_TRUST) { $env:AGENTLINK_TRUST } else { $env:AGENTLINK_CA }),
    [string]$Invite = $env:AGENTLINK_INVITE,
    [string]$PairingToken = $env:AGENTLINK_PAIRING_TOKEN,
    [string]$Token = $env:AGENTLINK_TOKEN,
    [string]$Name = $env:COMPUTERNAME,
    [ValidateSet("read-only", "read-write", "exec", "desktop", "remote-view", "remote-control", "full", "all", "full-access", "full_access")]
    [string]$Access = "exec",
    [string]$MaxAccess = "exec",
    [ValidateSet("user", "system")]
    [string]$Scope = "user",
    [string]$Version = $env:AGENTLINK_VERSION,
    [string]$Repo = $(if ($env:AGENTLINK_REPO) { $env:AGENTLINK_REPO } else { "zltl/agentlink" }),
    [string]$Prefix = "",
    [switch]$NoService,
    [switch]$NoPath,
    [switch]$AutoUpdate,
    [switch]$Headless,
    [switch]$AllowInsecureHttp,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
try {
    $tls = [Net.SecurityProtocolType]::Tls12
    if ([Enum]::GetNames([Net.SecurityProtocolType]) -contains "Tls13") {
        $tls = $tls -bor [Net.SecurityProtocolType]::Tls13
    }
    [Net.ServicePointManager]::SecurityProtocol = $tls
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
    $inviteDisp = if ($Invite) { "[redacted]" } else { "" }
    $dlDisp = if ($AgentlinkServeDownload) { $AgentlinkServeDownload } elseif ($env:AGENTLINK_DOWNLOAD_BASE) { $env:AGENTLINK_DOWNLOAD_BASE } else { "" }
    Write-Output "dry-run enroll=$AgentlinkServeEnroll relay=$Relay pairing=$pairingDisp token=$tokenDisp invite=$inviteDisp download=$dlDisp max_access=$MaxAccess"
    exit 0
}

$allowHttp = $AllowInsecureHttp.IsPresent -or ($env:AGENTLINK_ALLOW_INSECURE_HTTP -eq "1")
$skipPath = $NoPath.IsPresent -or ($env:AGENTLINK_NO_PATH -eq "1")

if (-not $Invite) {
    if (($Token -or $PairingToken) -and -not $Relay) {
        throw "pass -Relay (or -Invite) or set AGENTLINK_RELAY / AGENTLINK_INVITE; there is no built-in relay"
    }
    if (-not $NoService -and $Relay) {
        if (-not $Fingerprint -and -not $Trust) { throw "-Fingerprint or -Trust is required to pair" }
        if (-not $Token -and -not $PairingToken) { throw "pass -PairingToken, -Invite, or -Token to pair" }
    }
}

# Pre-check minisign BEFORE downloading any release archive.
if ($env:AGENTLINK_CHECKSUM_ONLY -ne "1") {
    $minisignCmd = Get-Command minisign -ErrorAction SilentlyContinue
    if (-not $minisignCmd) {
        throw @"
minisign is required to verify SHA256SUMS.minisig before downloading the release archive.
Install minisign first:
  winget install jedisct1.minisign
  # or: scoop install minisign
  # or: choco install minisign
If agentlink is already installed, run 'agentlink update --yes' instead (it verifies
release signatures in-process with the embedded public key and does not need minisign).
"@
    }
}

function Test-AgentlinkLoopbackHttp([System.Uri]$Uri) {
    if ($Uri.Scheme -ne "http") { return $false }
    if (-not [string]::IsNullOrEmpty($Uri.UserInfo)) { return $false }
    $hostName = $Uri.Host.Trim('[', ']').ToLowerInvariant()
    return ($hostName -eq "127.0.0.1" -or $hostName -eq "::1" -or $hostName -eq "localhost")
}

function Assert-AgentlinkDownloadUrl([string]$Url, [bool]$AllowLoopbackHttp = $true) {
    $uri = $null
    if (-not [System.Uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$uri)) {
        throw "invalid download URL: $Url"
    }
    if ($uri.AbsolutePath -match '/minisign\.pub$') {
        throw "refusing to download a public key from the release host"
    }
    if ($uri.Scheme -eq "https") {
        return
    }
    if ($AllowLoopbackHttp -and (Test-AgentlinkLoopbackHttp $uri)) {
        return
    }
    if ($uri.Scheme -eq "http" -and $allowHttp) {
        Write-Warning "allowing insecure http:// download URL because -AllowInsecureHttp / AGENTLINK_ALLOW_INSECURE_HTTP=1 is set: $Url"
        return
    }
    throw "refusing non-HTTPS download URL '$Url'. Use an https:// URL (or pass -AllowInsecureHttp / set AGENTLINK_ALLOW_INSECURE_HTTP=1 to override)."
}

function Invoke-AgentlinkHttp([string]$Url, [string]$DestPath, [string]$AcceptHeader) {
    $current = $Url
    $initialUri = $null
    if (-not [System.Uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$initialUri)) {
        throw "invalid download URL: $Url"
    }
    # Only allow loopback http:// when the caller initially targeted loopback http://
    # (prevents an https:// host/mirror from redirecting to http://127.0.0.1/...).
    $initialIsLoopbackHttp = Test-AgentlinkLoopbackHttp $initialUri
    $maxRedirects = 5
    for ($hop = 0; $hop -le $maxRedirects; $hop++) {
        Assert-AgentlinkDownloadUrl -Url $current -AllowLoopbackHttp:($initialIsLoopbackHttp)
        $req = [System.Net.HttpWebRequest]([System.Net.WebRequest]::Create($current))
        $req.Method = "GET"
        $req.UserAgent = "agentlink-install"
        $req.AllowAutoRedirect = $false
        if ($AcceptHeader) {
            $req.Accept = $AcceptHeader
        }
        $resp = $null
        try {
            $resp = [System.Net.HttpWebResponse]$req.GetResponse()
        } catch [System.Net.WebException] {
            if ($_.Exception.Response) {
                $resp = [System.Net.HttpWebResponse]$_.Exception.Response
                $code = [int]$resp.StatusCode
                if ($code -notin @(301, 302, 303, 307, 308)) {
                    $resp.Dispose()
                    throw
                }
            } else {
                throw
            }
        }
        try {
            $code = [int]$resp.StatusCode
            if ($code -in @(301, 302, 303, 307, 308)) {
                $loc = $resp.Headers["Location"]
                if (-not $loc) {
                    throw "redirect without Location header from $current"
                }
                if ($hop -eq $maxRedirects) {
                    throw "too many redirects downloading $Url"
                }
                $nextUri = New-Object System.Uri(([System.Uri]$current), $loc)
                $current = $nextUri.AbsoluteUri
                continue
            }
            $stream = $resp.GetResponseStream()
            if ($DestPath) {
                $fs = [System.IO.File]::Create($DestPath)
                try {
                    $stream.CopyTo($fs)
                } finally {
                    $fs.Dispose()
                }
                return $null
            } else {
                $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
                try {
                    return $reader.ReadToEnd()
                } finally {
                    $reader.Dispose()
                }
            }
        } finally {
            if ($resp) { $resp.Dispose() }
        }
    }
}

function Get-AgentlinkJson([string]$Url) {
    $raw = Invoke-AgentlinkHttp -Url $Url -DestPath "" -AcceptHeader "application/vnd.github+json"
    return ($raw | ConvertFrom-Json)
}

function Save-AgentlinkFile([string]$Url, [string]$Dest) {
    Invoke-AgentlinkHttp -Url $Url -DestPath $Dest -AcceptHeader "" | Out-Null
}

function Ensure-AgentlinkNative {
    if (-not ("AgentlinkInstallNative" -as [type])) {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class AgentlinkInstallNative {
    public static readonly IntPtr HWND_BROADCAST = new IntPtr(0xffff);
    public const uint WM_SETTINGCHANGE = 0x001A;
    public const uint SMTO_ABORTIFHUNG = 0x0002;
    public const uint TRAY_QUIT = 0x8003;

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr SendMessageTimeoutW(
        IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam,
        uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr FindWindowW(string lpClassName, string lpWindowName);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool PostMessageW(IntPtr hWnd, uint Msg, UIntPtr wParam, IntPtr lParam);
}
"@
    }
}

function Get-AgentlinkProcessesInDir([string]$Dir) {
    $targets = @(
        [System.IO.Path]::GetFullPath((Join-Path $Dir "agentlink.exe")),
        [System.IO.Path]::GetFullPath((Join-Path $Dir "agentlink-gui.exe"))
    )
    $found = @()
    foreach ($procName in @("agentlink", "agentlink-gui")) {
        foreach ($proc in (Get-Process -Name $procName -ErrorAction SilentlyContinue)) {
            if ($proc.Id -eq $PID) { continue }
            try {
                $procPath = $proc.Path
                if (-not $procPath) { continue }
                $full = [System.IO.Path]::GetFullPath($procPath)
                foreach ($t in $targets) {
                    if ([string]::Equals($full, $t, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $found += $proc
                        break
                    }
                }
            } catch {}
        }
    }
    return $found
}

function Stop-RunningAgentlink([string]$Dir, [string]$InstallScope) {
    $wasRunning = $false
    $existingCli = Join-Path $Dir "agentlink.exe"
    $runningProcs = Get-AgentlinkProcessesInDir $Dir
    if ($runningProcs.Count -gt 0) {
        $wasRunning = $true
    }

    if ($InstallScope -eq "system") {
        $svc = Get-Service -Name "agentlink-node" -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne "Stopped") {
            $wasRunning = $true
            Write-Host "stopping agentlink-node Windows service..."
            try {
                Stop-Service -Name "agentlink-node" -Force -ErrorAction Stop
            } catch {
                Write-Warning "failed to stop agentlink-node service cleanly: $_"
            }
        }
    }

    if ($wasRunning -and (Test-Path $existingCli)) {
        Write-Host "stopping running agentlink tray/service before replacing binaries..."
        try {
            & $existingCli service stop --scope $InstallScope 2>$null | Out-Null
        } catch {}
    }

    if ($InstallScope -eq "user" -and (Get-AgentlinkProcessesInDir $Dir).Count -gt 0) {
        try {
            Ensure-AgentlinkNative
            $hwnd = [AgentlinkInstallNative]::FindWindowW("AgentlinkTray", $null)
            if ($hwnd -ne [IntPtr]::Zero) {
                [void][AgentlinkInstallNative]::PostMessageW($hwnd, [AgentlinkInstallNative]::TRAY_QUIT, [UIntPtr]::Zero, [IntPtr]::Zero)
            }
        } catch {}
    }

    # Wait up to 5 seconds for graceful shutdown so file locks release cleanly.
    for ($i = 0; $i -lt 25; $i++) {
        if ((Get-AgentlinkProcessesInDir $Dir).Count -eq 0) { break }
        Start-Sleep -Milliseconds 200
    }

    $still = Get-AgentlinkProcessesInDir $Dir
    if ($still.Count -gt 0) {
        Write-Warning "agentlink processes in $Dir did not exit within 5s; terminating before upgrade."
        foreach ($proc in $still) {
            try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {}
        }
        for ($i = 0; $i -lt 15; $i++) {
            if ((Get-AgentlinkProcessesInDir $Dir).Count -eq 0) { break }
            Start-Sleep -Milliseconds 200
        }
    }

    return $wasRunning
}

function Add-AgentlinkToPath([string]$Dir, [string]$InstallScope) {
    $normDir = [System.IO.Path]::GetFullPath($Dir).TrimEnd('\')
    $regRoot = if ($InstallScope -eq "system") { [Microsoft.Win32.Registry]::LocalMachine } else { [Microsoft.Win32.Registry]::CurrentUser }
    $subKeyPath = if ($InstallScope -eq "system") { "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" } else { "Environment" }

    try {
        $key = $regRoot.OpenSubKey($subKeyPath, $true)
        if (-not $key) {
            Write-Warning "could not open registry key $subKeyPath to update PATH; add $Dir to PATH manually."
            return
        }
        try {
            $raw = $key.GetValue("Path", "", [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $kind = [Microsoft.Win32.RegistryValueKind]::ExpandString
            try { $kind = $key.GetValueKind("Path") } catch {}
            $entries = @()
            if ($raw) {
                $entries = $raw -split ';' | Where-Object { $_ -and $_.Trim().Length -gt 0 }
            }
            $alreadyPresent = $false
            foreach ($entry in $entries) {
                $expanded = [Environment]::ExpandEnvironmentVariables($entry.Trim()).TrimEnd('\')
                if ([string]::Equals($expanded, $normDir, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $alreadyPresent = $true
                    break
                }
            }
            if (-not $alreadyPresent) {
                $newValue = if ($entries.Count -gt 0) { ($entries -join ';') + ';' + $normDir } else { $normDir }
                if ($kind -ne [Microsoft.Win32.RegistryValueKind]::ExpandString -and $newValue.Contains('%')) {
                    $kind = [Microsoft.Win32.RegistryValueKind]::ExpandString
                }
                $key.SetValue("Path", $newValue, $kind)
                try {
                    Ensure-AgentlinkNative
                    $result = [UIntPtr]::Zero
                    [void][AgentlinkInstallNative]::SendMessageTimeoutW(
                        [AgentlinkInstallNative]::HWND_BROADCAST,
                        [AgentlinkInstallNative]::WM_SETTINGCHANGE,
                        [UIntPtr]::Zero,
                        "Environment",
                        [AgentlinkInstallNative]::SMTO_ABORTIFHUNG,
                        5000,
                        [ref]$result
                    )
                } catch {}
                Write-Host "added $normDir to $InstallScope PATH (open a new shell if needed)"
            }
        } finally {
            $key.Dispose()
        }
    } catch {
        Write-Warning "could not update $InstallScope PATH ($_); add $Dir to PATH manually."
    }

    # Also update the current PowerShell process PATH immediately.
    $procEntries = @()
    if ($env:PATH) {
        $procEntries = $env:PATH -split ';' | Where-Object { $_ -and $_.Trim().Length -gt 0 }
    }
    $inProc = $false
    foreach ($entry in $procEntries) {
        if ([string]::Equals($entry.Trim().TrimEnd('\'), $normDir, [System.StringComparison]::OrdinalIgnoreCase)) {
            $inProc = $true
            break
        }
    }
    if (-not $inProc) {
        $env:PATH = if ($env:PATH) { "$normDir;$env:PATH" } else { $normDir }
    }
}

$arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "aarch64" } else { "x86_64" }
$downloadOverride = if ($AgentlinkServeDownload) { $AgentlinkServeDownload.TrimEnd("/") } elseif ($env:AGENTLINK_DOWNLOAD_BASE) { $env:AGENTLINK_DOWNLOAD_BASE.TrimEnd("/") } else { "" }

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("agentlink-install-" + [guid]::NewGuid().ToString("n"))
New-Item -ItemType Directory -Path $tmp | Out-Null

try {
    $sumsFile = Join-Path $tmp "SHA256SUMS"
    $sumsDownloaded = $false
    if (-not $Version) {
        if ($downloadOverride) {
            Save-AgentlinkFile "$downloadOverride/SHA256SUMS" $sumsFile
            $sumsDownloaded = $true
            $sumsRaw = Get-Content -Path $sumsFile -Raw
            if ($sumsRaw -match "agentlink-([0-9][0-9.]*)-$arch-pc-windows-msvc\.zip") {
                $tag = "v" + $Matches[1]
            } else {
                throw "SHA256SUMS at $downloadOverride has no archive for windows/$arch"
            }
        } else {
            $latest = Get-AgentlinkJson "https://api.github.com/repos/$Repo/releases/latest"
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

    # Fetch and signature-verify SHA256SUMS BEFORE downloading the release archive.
    if (-not $sumsDownloaded) {
        Save-AgentlinkFile "$base/SHA256SUMS" $sumsFile
    }
    if ($env:AGENTLINK_CHECKSUM_ONLY -ne "1") {
        $sig = Join-Path $tmp "SHA256SUMS.minisig"
        Save-AgentlinkFile "$base/SHA256SUMS.minisig" $sig
        $embedded = "untrusted comment: minisign public key`nRWTCrF4TYAywjeqH2h25khhV1Ska9eBdU0l2FdPvtYp0b7emGttpZmcx"
        $pubkey = if ($env:AGENTLINK_UPDATE_PUBKEY) { $env:AGENTLINK_UPDATE_PUBKEY } else { $embedded }
        if (-not $pubkey.Contains("`n") -and -not $pubkey.Contains("`r") -and (Test-Path -LiteralPath $pubkey)) {
            $pubfile = $pubkey
        } else {
            $pubfile = Join-Path $tmp "minisign.pub"
            Set-Content -Path $pubfile -Value $pubkey -Encoding ascii
        }
        & minisign -V -p $pubfile -x $sig -m $sumsFile
        if ($LASTEXITCODE -ne 0) { throw "minisign rejected SHA256SUMS" }
    }

    $want = $null
    foreach ($line in Get-Content $sumsFile) {
        $parts = $line.Trim() -split "\s+"
        if ($parts.Length -ge 2 -and ($parts[1] -eq $asset -or $parts[1] -eq "*$asset")) {
            $want = $parts[0].ToLower()
            break
        }
    }
    if (-not $want) { throw "SHA256SUMS has no entry for $asset" }

    $archive = Join-Path $tmp $asset
    Save-AgentlinkFile "$base/$asset" $archive
    $got = (Get-FileHash -Algorithm SHA256 $archive).Hash.ToLower()
    if ($want -ne $got) { throw "checksum mismatch for $asset" }

    # Zip-slip safe extraction via .NET ZipFile (avoids PS 5.1 Expand-Archive vulnerability).
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $extractDir = Join-Path $tmp "extract"
    New-Item -ItemType Directory -Path $extractDir | Out-Null
    $extractRootTrimmed = [System.IO.Path]::GetFullPath($extractDir).TrimEnd('\', '/')
    $extractRoot = $extractRootTrimmed + [System.IO.Path]::DirectorySeparatorChar
    $zip = [System.IO.Compression.ZipFile]::OpenRead($archive)
    try {
        foreach ($entry in $zip.Entries) {
            $entryName = $entry.FullName
            if ([string]::IsNullOrEmpty($entryName)) { continue }
            if ([System.IO.Path]::IsPathRooted($entryName) -or $entryName -match '^[A-Za-z]:') {
                throw "zip entry uses an absolute path: $entryName"
            }
            $relPath = $entryName -replace '/', [System.IO.Path]::DirectorySeparatorChar
            $destPath = [System.IO.Path]::GetFullPath((Join-Path $extractDir $relPath))
            if (-not [string]::Equals($destPath, $extractRootTrimmed, [System.StringComparison]::OrdinalIgnoreCase) -and
                -not $destPath.StartsWith($extractRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "zip entry escapes extract directory: $entryName"
            }
            if ($entryName.EndsWith("/") -or $entryName.EndsWith("\") -or [string]::IsNullOrEmpty($entry.Name)) {
                New-Item -ItemType Directory -Path $destPath -Force | Out-Null
            } else {
                $parentDir = [System.IO.Path]::GetDirectoryName($destPath)
                if ($parentDir) {
                    New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
                }
                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $destPath, $true)
            }
        }
    } finally {
        $zip.Dispose()
    }

    $extracted = Join-Path $extractDir "agentlink.exe"
    if (-not (Test-Path $extracted)) { throw "archive did not contain agentlink.exe" }
    $extractedGui = Join-Path $extractDir "agentlink-gui.exe"

    if (-not $Prefix) {
        if ($Scope -eq "system") {
            $Prefix = Join-Path $env:ProgramFiles "agentlink"
        } else {
            $Prefix = Join-Path $env:LOCALAPPDATA "agentlink"
        }
    }
    New-Item -ItemType Directory -Path $Prefix -Force | Out-Null
    $wasRunning = Stop-RunningAgentlink -Dir $Prefix -InstallScope $Scope

    $dest = Join-Path $Prefix "agentlink.exe"
    Copy-Item $extracted $dest -Force
    $guiDest = $null
    if (Test-Path $extractedGui) {
        $guiDest = Join-Path $Prefix "agentlink-gui.exe"
        Copy-Item $extractedGui $guiDest -Force
    }

    if (-not $skipPath) {
        Add-AgentlinkToPath -Dir $Prefix -InstallScope $Scope
    }

    if ($NoService -or (-not $Relay -and -not $Invite)) {
        if ($guiDest) {
            Write-Host "installed $dest and $guiDest"
        } else {
            Write-Host "installed $dest"
        }
        if ($wasRunning) {
            Write-Host "restarting previously running agentlink service..."
            try {
                & $dest service start --scope $Scope 2>$null | Out-Null
            } catch {
                Write-Warning "could not restart agentlink service automatically: $_"
            }
        }
        if (-not $NoService) {
            Write-Host "pass -Invite 'agentlink-invite:v1:...' (or -Relay, -Fingerprint or -Trust, and -PairingToken) to pair and install the service"
        }
        return
    }

    $argList = @()
    if ($Relay) { $argList += @("--relay", $Relay) }
    if ($Fingerprint) { $argList += @("--fingerprint", $Fingerprint) }
    if ($Trust) { $argList += @("--trust", $Trust) }
    # Prefer env for pairing/admin tokens so they are not visible in process argv.
    if ($PairingToken) { $env:AGENTLINK_PAIRING_TOKEN = $PairingToken }
    if ($Token) {
        $env:AGENTLINK_TOKEN = $Token
    } elseif ($AgentlinkServeEnroll -eq "1") {
        Remove-Item Env:AGENTLINK_TOKEN -ErrorAction SilentlyContinue
    }
    $argList += @("service", "install", "--scope", $Scope, "--name", $Name, "--access", $Access)
    if ($Invite) { $argList += @("--invite", $Invite) }
    if ($MaxAccess) { $argList += @("--max-access", $MaxAccess) }
    if ($AutoUpdate) { $argList += "--auto-update" }
    if ($Headless) { $argList += "--headless" }
    & $dest @argList
    if ($LASTEXITCODE -ne 0) { throw "agentlink service install failed" }
    if ($guiDest) {
        Write-Host "agentlink $ver is installed at $dest (with GUI launcher $guiDest)"
    } else {
        Write-Host "agentlink $ver is installed at $dest"
    }
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
