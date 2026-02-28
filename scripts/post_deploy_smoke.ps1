param(
  [Parameter(Mandatory = $true)]
  [string]$BaseUrl,
  [string]$AdminToken = "",
  [string]$ExpectRateLimitBackend = "",
  [int]$TimeoutSec = 20
)

$ErrorActionPreference = "Stop"

function Invoke-JsonGet {
  param(
    [Parameter(Mandatory = $true)][string]$Uri,
    [hashtable]$Headers = @{}
  )
  return Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers -TimeoutSec $TimeoutSec
}

$health = Invoke-JsonGet -Uri "$BaseUrl/health"
if ($health.status -ne "ok") {
  throw "Health check failed: unexpected body"
}

$meta = Invoke-JsonGet -Uri "$BaseUrl/meta"
if (-not $meta.db) {
  throw "Meta check failed: db field missing"
}

if ($AdminToken -ne "") {
  $headers = @{ "X-Admin-Token" = $AdminToken }
  $me = Invoke-JsonGet -Uri "$BaseUrl/api/auth/me" -Headers $headers
  if (-not $me.role) {
    throw "Auth check failed: role missing"
  }

  $integrity = Invoke-JsonGet -Uri "$BaseUrl/api/admin/audit-integrity" -Headers $headers
  if (-not $integrity.chain.chain_ok) {
    throw "Audit integrity check failed: hash chain mismatch"
  }

  $runbook = Invoke-JsonGet -Uri "$BaseUrl/api/ops/runbook/checks" -Headers $headers
  if ($runbook.overall_status -eq "critical") {
    throw "Runbook check failed: overall_status=critical"
  }

  $posture = Invoke-JsonGet -Uri "$BaseUrl/api/ops/security/posture" -Headers $headers
  if (-not $posture.rate_limit.active_backend) {
    throw "Security posture check failed: missing rate_limit.active_backend"
  }
  if ($ExpectRateLimitBackend -ne "") {
    if ($posture.rate_limit.active_backend -ne $ExpectRateLimitBackend) {
      throw "Security posture check failed: expected rate limit backend '$ExpectRateLimitBackend' but got '$($posture.rate_limit.active_backend)'"
    }
  }
}

Write-Output "SMOKE_OK"
