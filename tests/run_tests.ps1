# DetectIQ Test Runner & Report Generator (PowerShell)
# Usage: .\run_tests.ps1 [unit|system|all]

param(
    [string]$Type = "all"
)

$RootDir = Split-Path -Parent $PSScriptRoot
$PythonExe = Join-Path $RootDir "backend\venv\Scripts\python.exe"
$ReportsDir = Join-Path $RootDir "tests\reports"

if (-not (Test-Path $ReportsDir)) {
    New-Item -ItemType Directory -Path $ReportsDir -Force | Out-Null
}

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "       DetectIQ Test Suite & Report Generator           " -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

# Check if pytest-html is installed; if not, standard pytest will run
$HtmlPlugin = & $PythonExe -m pip list | Select-String "pytest-html"

if ($Type -eq "unit" -or $Type -eq "all") {
    Write-Host "[*] Running Unit Tests (Mocked / Logic Scope)..." -ForegroundColor Yellow
    $UnitReport = Join-Path $ReportsDir "unit_test_report.html"
    
    if ($HtmlPlugin) {
        & $PythonExe -m pytest "$RootDir\tests\unit" -v --html="$UnitReport" --self-contained-html
        Write-Host "[+] Unit test report generated: $UnitReport" -ForegroundColor Green
    } else {
        & $PythonExe -m pytest "$RootDir\tests\unit" -v
    }
}

if ($Type -eq "system" -or $Type -eq "all") {
    Write-Host "`n[*] Running System Tests (Live Pipeline Scope)..." -ForegroundColor Yellow
    Write-Host "    Note: Requires backend server running on http://127.0.0.1:8000" -ForegroundColor DarkGray
    $SystemReport = Join-Path $ReportsDir "system_test_report.html"
    
    if ($HtmlPlugin) {
        & $PythonExe -m pytest "$RootDir\tests\system" -v --html="$SystemReport" --self-contained-html
        Write-Host "[+] System test report generated: $SystemReport" -ForegroundColor Green
    } else {
        & $PythonExe -m pytest "$RootDir\tests\system" -v
    }
}

Write-Host "`n[✓] Testing complete!`n" -ForegroundColor Cyan

