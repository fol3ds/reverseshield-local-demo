# ReverseShield Windows setup (project-local tools only).
# Run through setup.bat. No Administrator rights and no system-wide installs.
param(
    [switch]$SkipCompiler
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$Root = Split-Path -Parent $PSScriptRoot
$Tools = Join-Path $Root "tools"
$WindowsTools = Join-Path $Tools "windows"
New-Item -ItemType Directory -Force -Path $WindowsTools | Out-Null

function Get-RemoteFile {
    param([string]$Uri, [string]$OutFile, [string]$ExpectedSha256)
    Write-Host "Downloading $Uri"
    Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing
    if ($ExpectedSha256) {
        $actual = (Get-FileHash -Algorithm SHA256 -Path $OutFile).Hash
        if ($actual -ne $ExpectedSha256.ToUpperInvariant()) {
            Remove-Item -Force $OutFile
            throw "Checksum mismatch for $OutFile. Expected $ExpectedSha256, got $actual."
        }
        Write-Host "Checksum OK: $($actual.Substring(0,16))..."
    }
}

function Expand-ZipTo {
    param([string]$Zip, [string]$Destination)
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    Expand-Archive -Path $Zip -DestinationPath $Destination -Force
}

# 1) Ghidra (cross-platform Java application).
$GhidraVersion = "ghidra_12.2_PUBLIC"
$GhidraDir = Join-Path $Tools "ghidra\$GhidraVersion"
$GhidraZip = Join-Path $Tools "ghidra_12.2_PUBLIC.zip"
if (-not (Test-Path (Join-Path $GhidraDir "support\analyzeHeadless.bat"))) {
    Get-RemoteFile `
        -Uri "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.2_build/ghidra_12.2_PUBLIC_20261016.zip" `
        -OutFile $GhidraZip `
        -ExpectedSha256 "2C2CD776DB3C1F6A097BA418922378AC3649CADD5E844A6F5F088AE628A7BE67"
    Expand-ZipTo -Zip $GhidraZip -Destination (Join-Path $Tools "ghidra")
    Remove-Item -Force $GhidraZip
} else {
    Write-Host "Ghidra already present."
}

# 2) Windows JDK 25 for Ghidra.
$JdkDir = Join-Path $WindowsTools "jdk25"
$JdkZip = Join-Path $WindowsTools "jdk25.zip"
if (-not (Test-Path (Join-Path $JdkDir "bin\java.exe"))) {
    Get-RemoteFile `
        -Uri "https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.5%2B8/OpenJDK25U-jdk_x64_windows_hotspot_25.0.5_8.zip" `
        -OutFile $JdkZip `
        -ExpectedSha256 "636BDC13DC649DDC7D5921C5C7D23CCA6E44FD19D662B45CC9C02135A6C96C42"
    $TempJdk = Join-Path $WindowsTools "_jdk_tmp"
    Remove-Item -Recurse -Force $TempJdk -ErrorAction SilentlyContinue
    Expand-ZipTo -Zip $JdkZip -Destination $TempJdk
    $Extracted = Get-ChildItem -Path $TempJdk -Directory | Select-Object -First 1
    if (-not $Extracted) { throw "The JDK archive did not contain a folder." }
    Move-Item -Path $Extracted.FullName -Destination $JdkDir
    Remove-Item -Recurse -Force $TempJdk
    Remove-Item -Force $JdkZip
} else {
    Write-Host "Windows JDK already present."
}

# 3) Optional MinGW-w64 (gcc + binutils) for sample builds and binary hygiene.
if (-not $SkipCompiler) {
    $MingwDir = Join-Path $WindowsTools "mingw64"
    if (-not (Test-Path (Join-Path $MingwDir "bin\gcc.exe"))) {
        $MingwName = "winlibs-x86_64-posix-seh-gcc-16.2.0-llvm-23.1.3-mingw-w64ucrt-14.0.0-r3.zip"
        $MingwBase = "https://github.com/brechtsanders/winlibs_mingw/releases/download/16.2.0posix-23.1.3-14.0.0-ucrt-r3"
        $MingwZip = Join-Path $WindowsTools $MingwName
        $MingwShaFile = "$MingwZip.sha256"
        Get-RemoteFile -Uri "$MingwBase/$MingwName" -OutFile $MingwZip
        Invoke-WebRequest -Uri "$MingwBase/$MingwName.sha256" -OutFile $MingwShaFile -UseBasicParsing
        $Expected = ((Get-Content -Raw $MingwShaFile) -split "\s+")[0]
        $Actual = (Get-FileHash -Algorithm SHA256 -Path $MingwZip).Hash
        if ($Expected -and ($Actual -ne $Expected.ToUpperInvariant())) {
            Remove-Item -Force $MingwZip, $MingwShaFile
            throw "MinGW checksum mismatch."
        }
        $TempMingw = Join-Path $WindowsTools "_mingw_tmp"
        Remove-Item -Recurse -Force $TempMingw -ErrorAction SilentlyContinue
        Expand-ZipTo -Zip $MingwZip -Destination $TempMingw
        $Extracted = Get-ChildItem -Path $TempMingw -Directory | Where-Object { $_.Name -eq "mingw64" } | Select-Object -First 1
        if (-not $Extracted) { $Extracted = Get-ChildItem -Path $TempMingw -Directory | Select-Object -First 1 }
        if (-not $Extracted) { throw "The MinGW archive did not contain a folder." }
        Move-Item -Path $Extracted.FullName -Destination $MingwDir
        Remove-Item -Recurse -Force $TempMingw
        Remove-Item -Force $MingwZip, $MingwShaFile
    } else {
        Write-Host "MinGW-w64 already present."
    }
} else {
    Write-Host "Skipping MinGW-w64; analysis uses Ghidra only."
}

# 4) Verify Python. The app itself uses only the standard library.
$pythonCommand = $null
foreach ($candidate in @((Get-Command py -ErrorAction SilentlyContinue),
                         (Get-Command python -ErrorAction SilentlyContinue))) {
    if (-not $candidate) { continue }
    try {
        $versionText = & $candidate.Source --version 2>&1
        if ($LASTEXITCODE -eq 0 -and $versionText -match 'Python\s+(\d+)\.(\d+)') {
            if ([int]$Matches[1] -gt 3 -or ([int]$Matches[1] -eq 3 -and [int]$Matches[2] -ge 11)) {
                $pythonCommand = $candidate.Source
                break
            }
        }
    } catch {
        # A launcher may be present but blocked or stale; try the next candidate.
    }
}
if (-not $pythonCommand) {
    throw "Python 3.11+ was not found. Install it from python.org and enable 'Add python.exe to PATH'."
}
Write-Host "Python: $versionText"

Write-Host ""
Write-Host "Setup complete."
Write-Host "Next: run run.bat; the browser should open http://127.0.0.1:8765/"
Write-Host "Optional test suite: $pythonCommand -m unittest discover -s tests -v"
