<#
.SYNOPSIS
    Installs Lares, the autonomous Windows hardening agent.

.DESCRIPTION
    Picks the right executable for this machine's architecture, downloads it,
    verifies it against the published SHA256SUMS, puts it on your PATH, and
    optionally registers it to run at logon.

    No Python, no pip, no compiler. The executables are self-contained.

    You are about to run a script from the internet, which is a thing worth
    being suspicious of - a security tool asking you to do it without comment
    would be a poor advertisement for itself. Read it first:

        irm https://raw.githubusercontent.com/at0m-b0mb/Lares-Windows/main/install.ps1 -OutFile install.ps1
        notepad install.ps1
        .\install.ps1

    It does five things and nothing else: picks an architecture, downloads from
    github.com, checks a SHA-256, copies into %LOCALAPPDATA%, and adds that one
    folder to your user PATH. It never touches the machine-wide PATH and never
    needs administrator rights unless you ask for -StartWithWindows.

.PARAMETER Full
    Download the large single file with the model already inside it (about
    1.1 GB) rather than the small one that fetches a model later. Built for
    both x64 and ARM64, though the ARM64 one exists only when its model
    backend compiled in CI.

.PARAMETER Desktop
    Also install the desktop application.

.PARAMETER Freehand
    Also install lares-freehand.exe, the lane with no catalogue in it: it
    reads the machine, asks the model what is wrong, and runs the PowerShell
    the model writes back. It is useless without a model, so pair it with
    -Full unless you already have one downloaded.

    Note that -Full -Freehand downloads the model twice, once inside each
    executable, which is about 2.2 GB. There is no way around that: the model
    is carried inside the file, which is the point of those builds.

.PARAMETER StartWithWindows
    Register a scheduled task so the agent runs at logon. Needs administrator.

.PARAMETER Version
    A specific release tag, for example v0.1.0. Defaults to the latest.

.PARAMETER WhatIf
    Report what would be downloaded and where it would go, and change nothing.

.EXAMPLE
    irm https://raw.githubusercontent.com/at0m-b0mb/Lares-Windows/main/install.ps1 | iex

.EXAMPLE
    .\install.ps1 -Full -Desktop -StartWithWindows
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Full,
    [switch]$Desktop,
    [switch]$Freehand,
    [switch]$StartWithWindows,
    [string]$Version = "latest",
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\Lares"
)

$ErrorActionPreference = "Stop"

# Invoke-WebRequest draws a progress bar that costs roughly an order of
# magnitude in throughput on Windows PowerShell 5.1. Turning it off is the
# single biggest difference between a download that takes a minute and one
# that takes fifteen.
$ProgressPreference = "SilentlyContinue"

# Windows PowerShell 5.1 on an un-updated machine still negotiates TLS 1.0,
# which github.com refuses outright. Without this the first request fails with
# a bare "connection was closed" and nothing explains why.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

$Repo = "at0m-b0mb/Lares-Windows"
$Headers = @{ "User-Agent" = "lares-installer" }

function Write-Step { param($m) Write-Host "  $m" -ForegroundColor Cyan }
function Write-Ok   { param($m) Write-Host "  $m" -ForegroundColor Green }
function Write-Note { param($m) Write-Host "  $m" -ForegroundColor DarkGray }
function Write-Warn { param($m) Write-Host "  $m" -ForegroundColor Yellow }

function Get-File {
    <#
        curl.exe ships with Windows 10 1803 and later, streams to disk, and is
        markedly faster than Invoke-WebRequest for a file measured in hundreds
        of megabytes. Invoke-WebRequest is the fallback for older builds.
    #>
    param([string]$Url, [string]$OutFile)

    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        & $curl.Source -L --fail --retry 3 --retry-delay 2 -o $OutFile $Url
        if ($LASTEXITCODE -ne 0) { throw "download failed (curl exit $LASTEXITCODE): $Url" }
    } else {
        Invoke-WebRequest $Url -OutFile $OutFile -UseBasicParsing -Headers $Headers
    }
    if (-not (Test-Path $OutFile)) { throw "download produced no file: $Url" }
}

function Test-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $identity).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

Write-Host ""
Write-Host "  Lares" -ForegroundColor White
Write-Host "  An autonomous Windows hardening agent with a local model." -ForegroundColor DarkGray
Write-Host ""

# --------------------------------------------------------------------------
# Which machine is this
# --------------------------------------------------------------------------

# PROCESSOR_ARCHITECTURE describes the *process*. A 32-bit PowerShell on a
# 64-bit machine reports x86, and PROCESSOR_ARCHITEW6432 is what reveals the
# machine underneath. The binary has to match the machine, not the shell.
$rawArch = $env:PROCESSOR_ARCHITEW6432
if (-not $rawArch) { $rawArch = $env:PROCESSOR_ARCHITECTURE }

$arch = switch ($rawArch) {
    "AMD64" { "x64" }
    "ARM64" { "arm64" }
    "x86"   { "x86" }
    default { $rawArch }
}

Write-Step "Architecture: $arch"

if ($arch -eq "x86") {
    throw "Lares has no 32-bit build. This machine needs a 64-bit Windows."
}
if ($arch -ne "x64" -and $arch -ne "arm64") {
    throw "Unrecognised architecture '$rawArch'. Download a binary by hand from https://github.com/$Repo/releases"
}

if ($arch -eq "arm64" -and $Full) {
    Write-Warn "There is no model-embedded build for ARM64."
    Write-Note "llama-cpp-python publishes no ARM64 wheel, so a bundled model could"
    Write-Note "not be loaded. The ARM64 build scans, fixes, verifies and rolls back"
    Write-Note "exactly the same using the built-in planner."
    $Full = $false
}

# --------------------------------------------------------------------------
# Which release
# --------------------------------------------------------------------------

if ($Version -eq "latest") {
    Write-Step "Looking up the latest release"
    try {
        $release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" -Headers $Headers
    } catch {
        throw "could not reach the GitHub API to find the latest release: $($_.Exception.Message)"
    }
    $Version = $release.tag_name
}
if (-not $Version) { throw "no release tag could be determined" }
Write-Ok "Release $Version"

$base = "https://github.com/$Repo/releases/download/$Version"
$exeName = if ($Full) { "lares-full-$arch.exe" } else { "lares-$arch.exe" }

$wanted = @($exeName)
if ($Desktop) { $wanted += "lares-desktop-$arch.exe" }
if ($Freehand) {
    $wanted += if ($Full) { "lares-freehand-full-$arch.exe" } else { "lares-freehand-$arch.exe" }
    if (-not $Full) {
        Write-Warn ("lares-freehand.exe does nothing without a model - it has " +
                    "no catalogue to fall back on. Run 'lares model --download' " +
                    "afterwards, or use -Full to get one inside the file.")
    }
}

if ($WhatIfPreference) {
    Write-Host ""
    Write-Note "Would download from $base :"
    foreach ($n in $wanted) { Write-Note "  $n" }
    Write-Note "Would install into $InstallDir and add it to your user PATH."
    if ($StartWithWindows) { Write-Note "Would register a scheduled task named 'Lares'." }
    Write-Host ""
    return
}

# --------------------------------------------------------------------------
# Download and verify
# --------------------------------------------------------------------------

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$temp = Join-Path $env:TEMP "lares-install-$([Guid]::NewGuid().ToString('N').Substring(0,8))"
New-Item -ItemType Directory -Force -Path $temp | Out-Null

try {
    Write-Step "Downloading the checksums"
    $sumsPath = Join-Path $temp "SHA256SUMS.txt"
    Get-File "$base/SHA256SUMS.txt" $sumsPath

    $expected = @{}
    foreach ($line in Get-Content $sumsPath) {
        if ($line -match '^\s*([0-9a-fA-F]{64})\s+\*?(\S+)\s*$') {
            $expected[$Matches[2]] = $Matches[1].ToLower()
        }
    }
    if ($expected.Count -eq 0) {
        throw "SHA256SUMS.txt for $Version could not be parsed. Nothing was installed."
    }

    foreach ($name in $wanted) {
        if (-not $expected.ContainsKey($name)) {
            throw ("$name is not listed in SHA256SUMS.txt for $Version, so its " +
                   "integrity cannot be established. Refusing to install it.")
        }

        $size = if ($name -like "*full*") { " - about 1.1 GB, this will take a while" } else { "" }
        Write-Step "Downloading $name$size"
        $target = Join-Path $temp $name
        Get-File "$base/$name" $target

        Write-Step "Verifying $name"
        $actual = (Get-FileHash $target -Algorithm SHA256).Hash.ToLower()
        if ($actual -ne $expected[$name]) {
            throw ("$name failed its checksum.`n  expected $($expected[$name])`n" +
                   "  received $actual`nNothing was installed.")
        }
        Write-Ok "$name matches its published hash"

        # Whichever variant of a program was downloaded is installed under that
        # program's plain name, so the command you type does not depend on
        # which build you chose. The freehand test has to come first: its full
        # variant is called lares-freehand-full-x64.exe, which matches the
        # pattern for the ordinary full build as well.
        $installedName = if ($name -like "lares-freehand-*") { "lares-freehand.exe" }
                         elseif ($name -like "lares-desktop-*") { "lares-desktop.exe" }
                         else { "lares.exe" }
        $destination = Join-Path $InstallDir $installedName
        try {
            Copy-Item $target $destination -Force
        } catch {
            throw ("could not write $destination - if Lares is already running, " +
                   "close it and run this again. ($($_.Exception.Message))")
        }
    }
}
finally {
    Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Ok "Installed to $InstallDir"

# --------------------------------------------------------------------------
# PATH
#
# Read the RAW registry value, not [Environment]::GetEnvironmentVariable.
# That API expands %USERPROFILE% and friends before handing the string back,
# and writing the expanded result returns destroys every variable reference in
# the user's PATH - permanently, and silently. Reading the value with
# DoNotExpandEnvironmentNames and writing it back as ExpandString preserves
# them.
# --------------------------------------------------------------------------

$key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Environment", $true)
try {
    $rawPath = $key.GetValue("Path", "",
        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)

    $entries = @($rawPath -split ';' | Where-Object { $_ -ne "" })
    $already = $entries | Where-Object { $_.TrimEnd('\') -ieq $InstallDir.TrimEnd('\') }

    if ($already) {
        Write-Note "Already on your PATH."
    } else {
        Write-Step "Adding it to your PATH"
        $joined = (@($entries) + $InstallDir) -join ';'
        $kind = if ($rawPath -match '%') {
            [Microsoft.Win32.RegistryValueKind]::ExpandString
        } else {
            [Microsoft.Win32.RegistryValueKind]::String
        }
        $key.SetValue("Path", $joined, $kind)

        # Tell the shell the environment changed, so new processes pick it up
        # without a sign-out. Existing windows keep their old copy either way.
        try {
            $signature = @'
[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam,
    string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
'@
            $native = Add-Type -MemberDefinition $signature -Name LaresEnv `
                -Namespace Win32 -PassThru -ErrorAction Stop
            $result = [UIntPtr]::Zero
            # HWND_BROADCAST, WM_SETTINGCHANGE, SMTO_ABORTIFHUNG, 5s
            $null = $native::SendMessageTimeout([IntPtr]0xffff, 0x1A, [UIntPtr]::Zero,
                "Environment", 2, 5000, [ref]$result)
        } catch { }

        $env:Path = "$env:Path;$InstallDir"
        Write-Note "Open a new terminal for 'lares' to be found everywhere."
    }
}
finally {
    if ($key) { $key.Dispose() }
}

# --------------------------------------------------------------------------
# Start with Windows
# --------------------------------------------------------------------------

if ($StartWithWindows) {
    if (-not (Test-Elevated)) {
        Write-Warn "Skipped 'start with Windows': that needs an administrator."
        Write-Note "Re-run this from an elevated prompt, or register it yourself later:"
        Write-Note "  .\install.ps1 -StartWithWindows"
    } else {
        Write-Step "Registering it to run at logon"
        try {
            $exe = Join-Path $InstallDir "lares.exe"
            $action = New-ScheduledTaskAction -Execute $exe -Argument "watch"
            $trigger = New-ScheduledTaskTrigger -AtLogOn
            # Highest available, because remediation needs an elevated token.
            # Without it the agent runs, scans and reports but changes nothing.
            $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" `
                -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
                -DontStopIfGoingOnBatteries -StartWhenAvailable

            Register-ScheduledTask -TaskName "Lares" -Action $action -Trigger $trigger `
                -Principal $principal -Settings $settings -Force | Out-Null
            Write-Ok "Scheduled task 'Lares' created"
            Write-Note "Remove it with: Unregister-ScheduledTask -TaskName Lares -Confirm:`$false"
        } catch {
            Write-Warn "Could not register the scheduled task: $($_.Exception.Message)"
            Write-Note "Everything else installed fine; you can still run 'lares watch' yourself."
        }
    }
}

# --------------------------------------------------------------------------

Write-Host ""
Write-Ok "Done."
Write-Host ""
Write-Note "Can this machine run it?       lares doctor"
Write-Note "What is wrong, change nothing: lares scan"
Write-Note "What would it do, and why:     lares plan"
Write-Note "Let it fix things:             lares run"
Write-Note "Leave it running:              lares watch"
Write-Note "Watch it talk to the model:    lares consult --live"
if ($Freehand) {
    Write-Host ""
    Write-Note "The freehand lane - no catalogue, the model writes every fix:"
    Write-Note "  Read it through first:       lares-freehand --recorded"
    Write-Note "  See what it would do:        lares-freehand --dry-run"
    Write-Note "  Let it act on what it says:  lares-freehand"
}
Write-Host ""
Write-Warn "Start with 'lares scan' and read it before letting it change anything."
if ($Freehand) {
    Write-Warn ("lares-freehand.exe runs PowerShell the model wrote. Nothing in " +
                "it was reviewed in advance, and its undo was written by the " +
                "same model. Take a snapshot before letting it change anything.")
}
Write-Note "Applying fixes needs an elevated prompt. In a VM, take a snapshot first."
Write-Note "Windows will warn that the file is unsigned - these builds are not"
Write-Note "code-signed. Check the SHA-256 against SHA256SUMS.txt if in doubt."
Write-Host ""
