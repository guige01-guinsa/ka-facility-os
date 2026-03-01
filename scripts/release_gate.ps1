param(
  [string]$BaseUrl = "",
  [string]$AdminToken = "",
  [switch]$SkipTests
)

$ErrorActionPreference = "Stop"

Write-Output "[gate] python compile check"
python -m py_compile app/main.py app/schemas.py app/database.py tests/test_api.py

if (-not $SkipTests) {
  Write-Output "[gate] pytest regression"
  pytest -q tests/test_api.py
}

if ($BaseUrl -ne "") {
  Write-Output "[gate] endpoint smoke"
  $health = Invoke-RestMethod -Method Get -Uri "$BaseUrl/health" -TimeoutSec 20
  if ($health.status -ne "ok") {
    throw "health endpoint failed"
  }

  $modules = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/public/modules" -TimeoutSec 20
  if (-not $modules.title) {
    throw "public modules endpoint failed"
  }

  $serviceInfo = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/service-info" -TimeoutSec 20
  if (-not $serviceInfo.service) {
    throw "service-info endpoint failed"
  }

  if ($AdminToken -ne "") {
    $headers = @{ "X-Admin-Token" = $AdminToken }
    $runbook = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/ops/runbook/checks" -Headers $headers -TimeoutSec 20
    if (-not $runbook.overall_status) {
      throw "runbook checks endpoint failed"
    }
    $posture = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/ops/security/posture" -Headers $headers -TimeoutSec 20
    if (-not $posture.env) {
      throw "security posture endpoint failed"
    }
    $governance = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/ops/governance/gate" -Headers $headers -TimeoutSec 20
    if (-not $governance.decision) {
      throw "governance gate endpoint failed"
    }
    if ($governance.decision -ne "go") {
      throw "governance gate decision is no_go"
    }
  }
}

Write-Output "RELEASE_GATE_OK"
