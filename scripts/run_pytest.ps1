param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$PytestArgs
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$pythonExe = Join-Path $repoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $pythonExe)) {
    throw "Project virtual environment not found at $pythonExe"
}

$tempRoot = Join-Path $env:TEMP "ka-facility-os-pytest"
$baseTemp = Join-Path $tempRoot ("run-" + $PID)
New-Item -ItemType Directory -Force -Path $baseTemp | Out-Null

$args = @("-m", "pytest", "--basetemp", $baseTemp, "tests") + $PytestArgs
& $pythonExe @args
exit $LASTEXITCODE
