<#
  build.ps1 — build RootreX.exe and (optionally) the Windows installer.

  Usage (from the RootreX/ folder):
      .\build.ps1              # build dist\RootreX\RootreX.exe
      .\build.ps1 -Installer   # also build installer\Output\RootreX-Setup.exe (needs Inno Setup 6)

  No admin needed to build. The produced app self-elevates when run.
#>
param([switch]$Installer)
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
Set-Location $root

Write-Host "==> build venv" -ForegroundColor Cyan
python -m venv .build-venv
$py = Join-Path $root ".build-venv\Scripts\python.exe"

Write-Host "==> dependencies" -ForegroundColor Cyan
& $py -m pip install --upgrade pip
& $py -m pip install -r requirements.txt pyinstaller pillow

Write-Host "==> icon" -ForegroundColor Cyan
& $py tools\make_icon.py

Write-Host "==> PyInstaller" -ForegroundColor Cyan
& $py -m PyInstaller --noconfirm rootrex.spec
Write-Host "    built dist\RootreX\RootreX.exe" -ForegroundColor Green

if ($Installer) {
    $iscc = Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"
    if (Test-Path $iscc) {
        Write-Host "==> Inno Setup" -ForegroundColor Cyan
        & $iscc installer\rootrex.iss
        Write-Host "    installer at installer\Output\RootreX-Setup.exe" -ForegroundColor Green
    } else {
        Write-Warning "Inno Setup 6 not found ($iscc)."
        Write-Warning "Install it from https://jrsoftware.org/isdl.php then re-run: .\build.ps1 -Installer"
    }
}
