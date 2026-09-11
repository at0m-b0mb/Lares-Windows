<#
.SYNOPSIS
    Installs Lares, the autonomous Windows hardening agent.

.DESCRIPTION
    Downloads the right executable for this machine's architecture, verifies it
    against the published SHA256SUMS, puts it on PATH, and optionally registers
    it to start with Windows.

    There is no Python, no pip and no compiler involved. The executables are
    self-contained.

.NOTES
    You are about to run a script from the internet. That is a thing worth being
    suspicious of, and a security tool asking you to do it without comment would
    be a poor advertisement for itself. Read it first:

        irm https://raw.githubusercontent.com/at0m-b0mb/Lares-Windows/main/install.ps1 -OutFile install.ps1
        notepad install.ps1
        .\install.ps1

    It does five things and nothing else: picks an architecture, downloads two
    files from github.com, checks a hash, copies to %LOCALAPPDATA%, and adds
    that folder to your user PATH.

.PARAMETER Full
    Download the large single file with the model already inside it (about
    1.1 GB) instead of the small one that fetches a model later. x64 only.

.PARAMETER Desktop
    Also install the desktop application.

.PARAMETER StartWithWindows
    Register a scheduled task so the agent runs at logon.

.PARAMETER Version
    A specific release tag, for example v0.1.0. Defaults to the latest.

.EXAMPLE
    irm https://raw.githubusercontent.com/at0m-b0mb/Lares-Windows/main/install.ps1 | iex

.EXAMPLE
    .\install.ps1 -Full -Desktop -StartWithWindows
#>

[CmdletBinding()]
param(
    [switch]$Full,
    [switch]$Desktop,
    [switch]$StartWithWindows,
    [string]$Version = "latest",
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\Lares"
)

$ErrorActionPreference = "Stop"
$Repo = "at0m-b0mb/Lares-Windows"

function Write-Step   { param($m) Write-Host "  $m" -ForegroundColor Cyan }
function Write-Ok     { param($m) Write-Host "  $m" -ForegroundColor Green }
function Write-Note   { param($m) Write-Host "  $m" -ForegroundColor DarkGray }
function Write-Warn   { param($m) Write-Host "  $m" -ForegroundColor Yellow }

Write-Host ""
Write-Host "  Lares" -ForegroundColor White
Write-Host "  An autonomous Windows hardening agent with a local model." -ForegroundColor DarkGray
Write-Host ""

# --------------------------------------------------------------------------
# Which machine is this
# --------------------------------------------------------------------------

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { "x64" }
    "ARM64" { "arm64" }
    "x86"   { "x86" }
    default { $env:PROCESSOR_ARCHITECTURE }
}

# A 32-bit PowerShell on a 64-bit machine reports x86; the machine is what
# matters for choosing a binary, not the shell that happens to be running.
if ($env:PROCESSOR_ARCHITEW6432) {
    $arch = switch ($env:PROCESSOR_ARCHITEW6432) {
        "AMD64" { "x64" }
        "ARM64" { "arm64" }
        default { $arch }
    }
}

Write-Step "Architecture: $arch"

if ($arch -eq "x86") {
    throw "Lares does not ship a 32-bit build. This machine needs a 64-bit Windows."
}

if ($arch -eq "arm64" -and $Full) {
    Write-Warn "There is no model-embedded build for ARM64."
    Write-Note "llama-cpp-python publishes no ARM64 wheel, so a bundled model could"
    Write-Note "not be loaded. The ARM64 build uses the built-in planner, which does"
    Write-Note "the same scanning, fixing, verifying and rolling back without it."
    $Full = $false
}

# --------------------------------------------------------------------------
# Which release
# --------------------------------------------------------------------------

if ($Version -eq "latest") {
    Write-Step "Looking up the latest release"
    $release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" `
        -Headers @{ "User-Agent" = "lares-installer" }
    $Version = $release.tag_name
}
Write-Ok "Release $Version"

$base = "https://github.com/$Repo/releases/download/$Version"
$exeName = if ($Full) { "lares-full-$arch.exe" } else { "lares-$arch.exe" }

# --------------------------------------------------------------------------
# Download and verify
# --------------------------------------------------------------------------

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$temp = Join-Path $env:TEMP "lares-install-$(Get-Random)"
New-Item -ItemType Directory -Force -Path $temp | Out-Null

try {
    Write-Step "Downloading the checksums"
    $sumsPath = Join-Path $temp "SHA256SUMS.txt"
    Invoke-WebRequest "$base/SHA256SUMS.txt" -OutFile $sumsPath -UseBasicParsing

    $expected = @{}
    foreach ($line in Get-Content $sumsPath) {
        if ($line -match '^\s*([0-9a-fA-F]{64})\s+\*?(\S+)\s*$') {
            $expected[$Matches[2]] = $Matches[1].ToLower()
        }
    }

    $wanted = @($exeName)
    if ($Desktop) { $wanted += "lares-desktop-$arch.exe" }

    foreach ($name in $wanted) {
        if (-not $expected.ContainsKey($name)) {
            throw "$name is not listed in SHA256SUMS.txt for $Version. Refusing to install it."
        }

        $size = if ($name -like "*full*") { " (about 1.1 GB, this will take a while)" } else { "" }
        Write-Step "Downloading $name$size"
        $target = Join-Path $temp $name
        Invoke-WebRequest "$base/$name" -OutFile $target -UseBasicParsing

        Write-Step "Verifying $name"
        $actual = (Get-FileHash $target -Algorithm SHA256).Hash.ToLower()
        if ($actual -ne $expected[$name]) {
            throw "$name failed its checksum. Expected $($expected[$name]), got $actual. Nothing was installed."
        }
        Write-Ok "$name matches its published hash"

        # The console build is always installed as lares.exe regardless of which
        # variant was downloaded, so that the command is the same either way.
        $installedName = if ($name -like "lares-desktop-*") { "lares-desktop.exe" } else { "lares.exe" }
        Copy-Item $target (Join-Path $InstallDir $installedName) -Force
    }
}
finally {
    Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Ok "Installed to $InstallDir"

# --------------------------------------------------------------------------
# PATH
# --------------------------------------------------------------------------

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$InstallDir*") {
    Write-Step "Adding it to your PATH"
    $joined = if ([string]::IsNullOrEmpty($userPath)) { $InstallDir } else { "$userPath;$InstallDir" }
    [Environment]::SetEnvironmentVariable("Path", $joined, "User")
    $env:Path = "$env:Path;$InstallDir"
    Write-Note "Open a new terminal for this to take effect everywhere."
}

# --------------------------------------------------------------------------
# Start with Windows
# --------------------------------------------------------------------------

if ($StartWithWindows) {
    Write-Step "Registering it to run at logon"
    $exe = Join-Path $InstallDir "lares.exe"
    $action = New-ScheduledTaskAction -Execute $exe -Argument "watch"
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    # Highest available, because remediation needs an elevated token. Without
    # this the agent runs and reports but cannot change anything.
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries -StartWhenAvailable

    Register-ScheduledTask -TaskName "Lares" -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Force | Out-Null
    Write-Ok "Scheduled task 'Lares' created"
    Write-Note "Remove it with: Unregister-ScheduledTask -TaskName Lares -Confirm:`$false"
}

# --------------------------------------------------------------------------

Write-Host ""
Write-Ok "Done."
Write-Host ""
Write-Note "Check what this machine can run:    lares doctor"
Write-Note "See what is wrong, change nothing:  lares scan"
Write-Note "See what it would do, and why:      lares plan"
Write-Note "Let it fix things:                  lares run"
Write-Note "Leave it running:                   lares watch"
Write-Host ""
Write-Warn "Start with 'lares scan' and read it before letting it change anything."
Write-Note "Applying fixes needs an elevated prompt. In a VM, take a snapshot first."
Write-Host ""
