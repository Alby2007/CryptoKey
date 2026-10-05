# Pull, rebuild, and reinstall CryptoKey so the desktop copy at
# %LOCALAPPDATA%\CryptoKey matches the repo. Run: pwsh ./update.ps1
# (or: powershell -File update.ps1). The running guard hands off to the
# installed copy automatically when it's unlocked.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = $PSScriptRoot

git -C $repo pull --ff-only
if ($LASTEXITCODE -ne 0) { throw "git pull failed — resolve the tree state first" }

$proj = Join-Path $repo 'src\CryptoKey.Win\CryptoKey.Win.csproj'
dotnet build $proj -c Release
if ($LASTEXITCODE -ne 0) { throw "build failed" }

$exe = Join-Path $repo 'src\CryptoKey.Win\bin\Release\net9.0-windows\cryptokey.exe'
& $exe install
if ($LASTEXITCODE -ne 0) { throw "install failed" }

# Report what just landed so the stamp is checkable end-to-end:
# `cryptokey status` should show the same `build=` suffix.
Write-Host "`nHEAD:      $(git -C $repo rev-parse --short HEAD)"
Write-Host "Installed: $((Get-Item $exe).VersionInfo.ProductVersion)"
