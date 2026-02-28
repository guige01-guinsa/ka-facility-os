param(
  [Parameter(Mandatory = $true)]
  [string]$BaseUrl,
  [string]$AdminToken = "",
  [string]$ExpectRateLimitBackend = "",
  [switch]$RequireAuditChainOk,
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
  if ($RequireAuditChainOk -and (-not $integrity.chain.chain_ok)) {
    throw "Audit integrity check failed: hash chain mismatch"
  }

  $runbook = Invoke-JsonGet -Uri "$BaseUrl/api/ops/runbook/checks" -Headers $headers
  $criticalChecks = @($runbook.checks | Where-Object { $_.status -eq "critical" })
  if (-not $RequireAuditChainOk) {
    $criticalChecks = @($criticalChecks | Where-Object { $_.id -ne "audit_chain_integrity" })
  }
  if ($criticalChecks.Count -gt 0) {
    $criticalIds = ($criticalChecks | ForEach-Object { $_.id }) -join ","
    throw "Runbook check failed: critical checks=$criticalIds"
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
