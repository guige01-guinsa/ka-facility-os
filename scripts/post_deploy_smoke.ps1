param(
  [Parameter(Mandatory = $true)]
  [string]$BaseUrl,
  [string]$AdminToken = "",
  [string]$ExpectRateLimitBackend = "",
  [switch]$RequireAuditChainOk,
  [int]$TimeoutSec = 20,
  [string]$DeployId = "",
  [string]$ChecklistVersion = "2026.03.v1",
  [bool]$RunRunbookGate = $true,
  [bool]$RecordSmokeRun = $true
)

$ErrorActionPreference = "Stop"
$startedAt = (Get-Date).ToUniversalTime()
$smokeChecks = @()
$overallStatus = "success"
$failureMessage = ""
$runbookGatePassed = $false
$rollbackReady = $true

function Add-SmokeCheck {
  param(
    [Parameter(Mandatory = $true)][string]$Id,
    [Parameter(Mandatory = $true)][string]$Status,
    [Parameter(Mandatory = $true)][string]$Message
  )
  $script:smokeChecks += [ordered]@{
    id = $Id
    status = $Status
    message = $Message
  }
}

function Invoke-JsonGet {
  param(
    [Parameter(Mandatory = $true)][string]$Uri,
    [hashtable]$Headers = @{}
  )
  return Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers -TimeoutSec $TimeoutSec
}

function Record-SmokeRun {
  param(
    [Parameter(Mandatory = $true)][string]$FinalStatus,
    [Parameter(Mandatory = $true)][string]$FinalMessage
  )
  if ($AdminToken -eq "" -or (-not $RecordSmokeRun)) {
    return
  }
  try {
    $recordHeaders = @{
      "X-Admin-Token" = $AdminToken
      "Content-Type" = "application/json"
    }
    $payload = @{
      deploy_id = $DeployId
      environment = "production"
      status = $FinalStatus
      base_url = $BaseUrl
      checklist_version = $ChecklistVersion
      rollback_reference = "docs/W15_MIGRATION_ROLLBACK.md"
      rollback_ready = $rollbackReady
      runbook_gate_passed = $runbookGatePassed
      notes = $FinalMessage
      started_at = $startedAt.ToString("o")
      finished_at = ((Get-Date).ToUniversalTime()).ToString("o")
      checks = $smokeChecks
    } | ConvertTo-Json -Depth 8
    Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/ops/deploy/smoke/record" -Headers $recordHeaders -Body $payload -TimeoutSec $TimeoutSec | Out-Null
  } catch {
    Write-Output "SMOKE_RECORD_WARN $($_.Exception.Message)"
  }
}

try {
  $health = Invoke-JsonGet -Uri "$BaseUrl/health"
  if ($health.status -ne "ok") {
    throw "Health check failed: unexpected body"
  }
  Add-SmokeCheck -Id "health" -Status "ok" -Message "/health response ok"

  $meta = Invoke-JsonGet -Uri "$BaseUrl/meta"
  if (-not $meta.db) {
    throw "Meta check failed: db field missing"
  }
  Add-SmokeCheck -Id "meta" -Status "ok" -Message "/meta response contains db info"

  if ($AdminToken -ne "") {
    $headers = @{ "X-Admin-Token" = $AdminToken }
    $me = Invoke-JsonGet -Uri "$BaseUrl/api/auth/me" -Headers $headers
    if (-not $me.role) {
      throw "Auth check failed: role missing"
    }
    Add-SmokeCheck -Id "auth_me" -Status "ok" -Message "/api/auth/me role resolved"

    $integrity = Invoke-JsonGet -Uri "$BaseUrl/api/admin/audit-integrity" -Headers $headers
    if ($RequireAuditChainOk -and (-not $integrity.chain.chain_ok)) {
      throw "Audit integrity check failed: hash chain mismatch"
    }
    Add-SmokeCheck -Id "audit_integrity" -Status "ok" -Message "Audit integrity endpoint responded"

    $runbook = Invoke-JsonGet -Uri "$BaseUrl/api/ops/runbook/checks" -Headers $headers
    $criticalChecks = @($runbook.checks | Where-Object { $_.status -eq "critical" })
    if (-not $RequireAuditChainOk) {
      $criticalChecks = @($criticalChecks | Where-Object { $_.id -ne "audit_chain_integrity" })
    }
    if ($criticalChecks.Count -gt 0) {
      $criticalIds = ($criticalChecks | ForEach-Object { $_.id }) -join ","
      throw "Runbook check failed: critical checks=$criticalIds"
    }
    Add-SmokeCheck -Id "runbook_checks" -Status "ok" -Message "Runbook checks have no blocking critical issue"

    $posture = Invoke-JsonGet -Uri "$BaseUrl/api/ops/security/posture" -Headers $headers
    if (-not $posture.rate_limit.active_backend) {
      throw "Security posture check failed: missing rate_limit.active_backend"
    }
    if ($ExpectRateLimitBackend -ne "") {
      if ($posture.rate_limit.active_backend -ne $ExpectRateLimitBackend) {
        throw "Security posture check failed: expected rate limit backend '$ExpectRateLimitBackend' but got '$($posture.rate_limit.active_backend)'"
      }
    }
    Add-SmokeCheck -Id "security_posture" -Status "ok" -Message "Security posture endpoint validated"

    if ($RunRunbookGate) {
      $runbookRun = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/ops/runbook/checks/run" -Headers $headers -TimeoutSec $TimeoutSec
      $criticalCount = 0
      try {
        $criticalCount = [int]$runbookRun.critical_count
      } catch {
        $criticalCount = 0
      }
      $runbookGatePassed = ($runbookRun.overall_status -ne "critical" -and $criticalCount -le 0)
      if (-not $runbookGatePassed) {
        throw "Runbook gate failed: overall=$($runbookRun.overall_status), critical_count=$criticalCount"
      }
      Add-SmokeCheck -Id "runbook_gate" -Status "ok" -Message "Runbook gate passed"
    } else {
      $runbookGatePassed = $true
      Add-SmokeCheck -Id "runbook_gate" -Status "skipped" -Message "Runbook gate disabled by parameter"
    }
  } else {
    Add-SmokeCheck -Id "admin_checks" -Status "skipped" -Message "Admin token not provided; auth/runbook/security checks skipped"
    if ($RunRunbookGate) {
      $runbookGatePassed = $false
    } else {
      $runbookGatePassed = $true
    }
  }
} catch {
  $overallStatus = "critical"
  $failureMessage = $_.Exception.Message
  Add-SmokeCheck -Id "fatal" -Status "critical" -Message $failureMessage
  Record-SmokeRun -FinalStatus $overallStatus -FinalMessage $failureMessage
  throw
}

Record-SmokeRun -FinalStatus $overallStatus -FinalMessage "smoke_ok"
Write-Output "SMOKE_OK"
