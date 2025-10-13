<#
 Copyright 2025 Nitro Agility S.r.l.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
#>

param(
  [string]$Version
)

$ErrorActionPreference = "Stop"
$Owner   = "permguard"
$Repo    = "permguard"
$Project = "permguard"

Write-Host "[permguard-install] Detecting architecture…" -ForegroundColor Cyan
$archEnv = $env:PROCESSOR_ARCHITECTURE
if ($archEnv -eq "ARM64") { $archPretty = "arm64" }
elseif ($archEnv -eq "AMD64") { $archPretty = "x86_64" }
else { throw "Unsupported architecture: $archEnv" }

if (-not $Version) {
  Write-Host "[permguard-install] Resolving latest release tag…" -ForegroundColor Cyan
  $latest = Invoke-RestMethod "https://api.github.com/repos/$Owner/$Repo/releases/latest"
  $Version = $latest.tag_name
  if (-not $Version) { throw "Cannot determine latest tag" }
}
Write-Host "[permguard-install] Using tag: $Version" -ForegroundColor Cyan

$asset  = "${Project}_cli_Windows_${archPretty}.zip"
$base   = "https://github.com/$Owner/$Repo/releases/download/$Version"
$zipUrl = "$base/$asset"
$sumUrl = "$base/checksums.txt"

$tmp = New-Item -ItemType Directory -Path ([System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "permguard-" + [guid]::NewGuid().ToString())) -Force
$zipFile = Join-Path $tmp.FullName $asset
$sumFile = Join-Path $tmp.FullName "checksums.txt"

Write-Host "[permguard-install] Downloading $asset…" -ForegroundColor Cyan
Invoke-WebRequest -Uri $zipUrl -UseBasicParsing -OutFile $zipFile

Write-Host "[permguard-install] Downloading checksums…" -ForegroundColor Cyan
Invoke-WebRequest -Uri $sumUrl -UseBasicParsing -OutFile $sumFile

Write-Host "[permguard-install] Verifying SHA-256…" -ForegroundColor Cyan
$expected = (Get-Content $sumFile | Where-Object { $_ -match " $asset$" } | Select-Object -First 1)
if (-not $expected) { throw "Checksum entry for $asset not found in checksums.txt" }
$expectedHash = ($expected -split '\s+')[0].ToLowerInvariant()

$actualHash = (Get-FileHash -Algorithm SHA256 -Path $zipFile).Hash.ToLowerInvariant()
if ($actualHash -ne $expectedHash) {
  throw "Checksum mismatch for $asset (expected $expectedHash, got $actualHash)"
}

Write-Host "[permguard-install] Extracting to .\bin..." -ForegroundColor Cyan
$extractDir = ".\bin"
New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
Expand-Archive -Path $zipFile -DestinationPath $extractDir -Force | Out-Null

Write-Host "[permguard-install] Done. Binary available in .\bin\" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host '  Move-Item .\bin\permguard.exe "C:\Program Files\permguard\permguard.exe"'
Write-Host '  setx PATH "$($env:PATH);C:\Program Files\permguard"'
Write-Host ""
Write-Host "Then verify with:" -ForegroundColor Yellow
Write-Host '  permguard --version'
