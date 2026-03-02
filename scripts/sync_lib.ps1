param(
    [string]$LibRepo = "git@github.com:ELF-Nigel/keyauth-cpp-library-1.3API.git",
    [string]$DestX86 = "x86/lib",
    [string]$DestX64 = "x64/lib"
)

$ErrorActionPreference = "Stop"

$work = Join-Path $env:TEMP "keyauth-lib-sync"
if (Test-Path $work) { Remove-Item -Recurse -Force $work }

git clone --depth 1 $LibRepo $work

# Copy entire lib contents into both arch folders
if (-not (Test-Path $DestX86)) { New-Item -ItemType Directory -Force $DestX86 | Out-Null }
if (-not (Test-Path $DestX64)) { New-Item -ItemType Directory -Force $DestX64 | Out-Null }

Remove-Item -Recurse -Force (Join-Path $DestX86 "*")
Remove-Item -Recurse -Force (Join-Path $DestX64 "*")

Copy-Item -Recurse -Force (Join-Path $work "*") $DestX86
Copy-Item -Recurse -Force (Join-Path $work "*") $DestX64

Write-Host "Synced KeyAuth library into $DestX86 and $DestX64"
