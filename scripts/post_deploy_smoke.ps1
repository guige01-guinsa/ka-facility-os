param(
  [Parameter(Mandatory = $true)]
  [string]$BaseUrl,
  [string]$AdminToken = "",
  [string]$ServiceId = "",
  [string]$RenderApiKey = "",
  [string]$AdminTokenEnvKey = "ADMIN_TOKEN",
  [string]$ExpectRateLimitBackend = "",
  [switch]$RequireAuditChainOk,
  [int]$TimeoutSec = 20,
  [string]$DeployId = "",
  [string]$ChecklistVersion = "",
  [bool]$RunA1Lite = $true,
  [bool]$RunA2Lite = $false,
  [bool]$RunRunbookGate = $true,
  [bool]$RecordSmokeRun = $true
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot/render_env_utils.ps1"
$ServiceId = Resolve-RenderServiceId -ServiceId $ServiceId
$AdminToken = Resolve-RenderAdminToken -AdminToken $AdminToken -ServiceId $ServiceId -RenderApiKey $RenderApiKey -EnvKey $AdminTokenEnvKey
$startedAt = (Get-Date).ToUniversalTime()
$smokeChecks = @()
$overallStatus = "success"
$failureMessage = ""
$runbookGatePassed = $false
$rollbackReady = $true
$rollbackReference = "docs/W15_MIGRATION_ROLLBACK.md"
$rollbackReferenceSha = ""

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

function Invoke-JsonPost {
  param(
    [Parameter(Mandatory = $true)][string]$Uri,
    [hashtable]$Headers = @{},
    [Parameter(Mandatory = $true)][object]$Body
  )
  $requestHeaders = @{}
  foreach ($key in $Headers.Keys) {
    $requestHeaders[$key] = $Headers[$key]
  }
  if (-not $requestHeaders.ContainsKey("Content-Type")) {
    $requestHeaders["Content-Type"] = "application/json"
  }
  $payload = $Body | ConvertTo-Json -Depth 10
  return Invoke-RestMethod -Method Post -Uri $Uri -Headers $requestHeaders -Body $payload -TimeoutSec $TimeoutSec
}

function Invoke-JsonPatch {
  param(
    [Parameter(Mandatory = $true)][string]$Uri,
    [hashtable]$Headers = @{},
    [Parameter(Mandatory = $true)][object]$Body
  )
  $requestHeaders = @{}
  foreach ($key in $Headers.Keys) {
    $requestHeaders[$key] = $Headers[$key]
  }
  if (-not $requestHeaders.ContainsKey("Content-Type")) {
    $requestHeaders["Content-Type"] = "application/json"
  }
  $payload = $Body | ConvertTo-Json -Depth 10
  return Invoke-RestMethod -Method Patch -Uri $Uri -Headers $requestHeaders -Body $payload -TimeoutSec $TimeoutSec
}

function Invoke-MultipartFormPost {
  param(
    [Parameter(Mandatory = $true)][string]$Uri,
    [hashtable]$Headers = @{},
    [Parameter(Mandatory = $true)][byte[]]$FileBytes,
    [Parameter(Mandatory = $true)][string]$FileName,
    [string]$ContentType = "application/octet-stream",
    [string]$FileFieldName = "file",
    [hashtable]$FormFields = @{}
  )
  $client = [System.Net.Http.HttpClient]::new()
  try {
    $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)
    $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, $Uri)
    try {
      foreach ($key in $Headers.Keys) {
        [void]$request.Headers.TryAddWithoutValidation($key, [string]$Headers[$key])
      }
      $multipart = [System.Net.Http.MultipartFormDataContent]::new()
      foreach ($key in $FormFields.Keys) {
        $fieldContent = [System.Net.Http.StringContent]::new([string]$FormFields[$key], [System.Text.Encoding]::UTF8)
        $multipart.Add($fieldContent, $key)
      }
      $fileContent = [System.Net.Http.ByteArrayContent]::new($FileBytes)
      $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse($ContentType)
      $multipart.Add($fileContent, $FileFieldName, $FileName)
      $request.Content = $multipart
      $response = $client.SendAsync($request).GetAwaiter().GetResult()
      $raw = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
      if (-not $response.IsSuccessStatusCode) {
        throw "Multipart POST failed: $([int]$response.StatusCode) $raw"
      }
      if ([string]::IsNullOrWhiteSpace($raw)) {
        return $null
      }
      return $raw | ConvertFrom-Json
    } finally {
      if ($request -ne $null) {
        $request.Dispose()
      }
    }
  } finally {
    $client.Dispose()
  }
}

function Invoke-HtmlGet {
  param(
    [Parameter(Mandatory = $true)][string]$Uri
  )
  return Invoke-WebRequest -Method Get -Uri $Uri -Headers @{ "Accept" = "text/html" } -TimeoutSec $TimeoutSec -UseBasicParsing
}

function Invoke-HttpGet {
  param(
    [Parameter(Mandatory = $true)][string]$Uri,
    [hashtable]$Headers = @{}
  )
  return Invoke-WebRequest -Method Get -Uri $Uri -Headers $Headers -TimeoutSec $TimeoutSec -UseBasicParsing
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
      rollback_reference = $rollbackReference
      rollback_reference_sha256 = $rollbackReferenceSha
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

function Get-NumericProperty {
  param(
    [object]$Object,
    [Parameter(Mandatory = $true)][string]$PropertyName
  )
  if ($null -eq $Object) {
    return 0
  }
  if ($Object -is [hashtable]) {
    if ($Object.ContainsKey($PropertyName)) {
      try {
        return [int]$Object[$PropertyName]
      } catch {
        return 0
      }
    }
    return 0
  }
  if ($Object.PSObject.Properties.Name -contains $PropertyName) {
    try {
      return [int]$Object.$PropertyName
    } catch {
      return 0
    }
  }
  return 0
}

function Invoke-A1LiteSmoke {
  param(
    [Parameter(Mandatory = $true)][hashtable]$Headers
  )
  if (-not $RunA1Lite) {
    Add-SmokeCheck -Id "a1_lite_ops_flow" -Status "skipped" -Message "A1-lite smoke disabled by parameter"
    return
  }

  $site = "SMOKE-A1"
  $location = "B1 electrical room"
  $monthLabel = (Get-Date).ToUniversalTime().ToString("yyyy-MM")
  $runLabel = if ([string]::IsNullOrWhiteSpace($DeployId)) {
    (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
  } else {
    $DeployId
  }
  $encodedSite = [uri]::EscapeDataString($site)
  $encodedMonth = [uri]::EscapeDataString($monthLabel)
  $integratedUri = "$BaseUrl/api/reports/monthly/integrated?site=$encodedSite&month=$encodedMonth"
  $beforeIntegrated = Invoke-JsonGet -Uri $integratedUri -Headers $Headers
  $beforeInspectionTotal = Get-NumericProperty -Object $beforeIntegrated.inspections -PropertyName "total"
  $beforeWorkOrderTotal = Get-NumericProperty -Object $beforeIntegrated.work_orders -PropertyName "total"
  $beforeCompletedTotal = Get-NumericProperty -Object $beforeIntegrated.work_orders.status_counts -PropertyName "completed"

  $metaJson = '{"task_type":"\uc804\uae30\uc810\uac80","equipment":"Transformer","equipment_location":"B1 electrical room","qr_id":"QR-002","checklist_set_id":"electrical_60","checklist_data_version":"smoke-script","summary":{"total":3,"normal":0,"abnormal":3,"na":0},"abnormal_action":"Retorque terminal and re-check heat rise"}'
  $checklistJson = '[{"group":"Transformer","item":"\ubcc0\uc555\uae30 \uc678\uad00 \uc810\uac80","result":"abnormal","action":""},{"group":"Transformer","item":"\ubcc0\uc555\uae30 \uc628\ub3c4 \uc0c1\uc2b9 \uc5ec\ubd80 \ud655\uc778","result":"abnormal","action":""},{"group":"Transformer","item":"\ubcc0\uc555\uae30 \uc774\uc0c1 \uc18c\uc74c \ud655\uc778","result":"abnormal","action":""}]'
  $inspectionNotes = "[OPS_CHECKLIST_V1]`nmeta=$metaJson`nchecklist=$checklistJson"

  $inspection = Invoke-JsonPost -Uri "$BaseUrl/api/inspections" -Headers $Headers -Body @{
    site = $site
    location = $location
    cycle = "monthly"
    inspector = "deploy_smoke"
    inspected_at = ((Get-Date).ToUniversalTime()).ToString("o")
    notes = $inspectionNotes
  }
  $inspectionId = Get-NumericProperty -Object $inspection -PropertyName "id"
  if ($inspectionId -le 0) {
    throw "A1-lite smoke failed: inspection id missing"
  }

  $workOrder = Invoke-JsonPost -Uri "$BaseUrl/api/work-orders" -Headers $Headers -Body @{
    title = "A1-lite smoke remediation $runLabel"
    description = "Deploy smoke legal inspection follow-up"
    site = $site
    location = $location
    priority = "low"
    inspection_id = $inspectionId
  }
  $workOrderId = Get-NumericProperty -Object $workOrder -PropertyName "id"
  if ($workOrderId -le 0) {
    throw "A1-lite smoke failed: work order id missing"
  }
  if ("$($workOrder.priority)" -ne "critical") {
    throw "A1-lite smoke failed: work order priority was not upgraded to critical"
  }
  if ([string]::IsNullOrWhiteSpace("$($workOrder.due_at)")) {
    throw "A1-lite smoke failed: work order due_at missing"
  }

  $events = @(Invoke-JsonGet -Uri "$BaseUrl/api/work-orders/$workOrderId/events" -Headers $Headers)
  if ($events.Count -lt 1) {
    throw "A1-lite smoke failed: work order event log missing"
  }
  $createdEvent = $events[0]
  if ("$($createdEvent.event_type)" -ne "created") {
    throw "A1-lite smoke failed: first work order event was not 'created'"
  }
  if (-not $createdEvent.detail.priority_upgraded) {
    throw "A1-lite smoke failed: priority_upgraded flag missing from work order event"
  }
  if (-not $createdEvent.detail.auto_due_applied) {
    throw "A1-lite smoke failed: auto_due_applied flag missing from work order event"
  }

  $acked = Invoke-JsonPatch -Uri "$BaseUrl/api/work-orders/$workOrderId/ack" -Headers $Headers -Body @{
    assignee = "Deploy Smoke Bot"
  }
  if ("$($acked.status)" -ne "acked") {
    throw "A1-lite smoke failed: work order ack did not transition to acked"
  }

  $completed = Invoke-JsonPatch -Uri "$BaseUrl/api/work-orders/$workOrderId/complete" -Headers $Headers -Body @{
    resolution_notes = "Deploy smoke path verified"
  }
  if ("$($completed.status)" -ne "completed") {
    throw "A1-lite smoke failed: work order complete did not transition to completed"
  }

  $afterIntegrated = Invoke-JsonGet -Uri $integratedUri -Headers $Headers
  $afterInspectionTotal = Get-NumericProperty -Object $afterIntegrated.inspections -PropertyName "total"
  $afterWorkOrderTotal = Get-NumericProperty -Object $afterIntegrated.work_orders -PropertyName "total"
  $afterCompletedTotal = Get-NumericProperty -Object $afterIntegrated.work_orders.status_counts -PropertyName "completed"
  if ("$($afterIntegrated.site)" -ne $site) {
    throw "A1-lite smoke failed: integrated report site mismatch"
  }
  if ($afterInspectionTotal -lt ($beforeInspectionTotal + 1)) {
    throw "A1-lite smoke failed: integrated report inspection total did not increase"
  }
  if ($afterWorkOrderTotal -lt ($beforeWorkOrderTotal + 1)) {
    throw "A1-lite smoke failed: integrated report work order total did not increase"
  }
  if ($afterCompletedTotal -lt ($beforeCompletedTotal + 1)) {
    throw "A1-lite smoke failed: integrated report completed work order total did not increase"
  }

  Add-SmokeCheck `
    -Id "a1_lite_ops_flow" `
    -Status "ok" `
    -Message "A1-lite flow ok (inspection_id=$inspectionId, work_order_id=$workOrderId, month=$monthLabel)"
}

function Invoke-A2LiteSmoke {
  param(
    [Parameter(Mandatory = $true)][hashtable]$Headers
  )
  if (-not $RunA2Lite) {
    Add-SmokeCheck -Id "a2_lite_document_flow" -Status "skipped" -Message "A2-lite smoke disabled by parameter"
    return
  }

  $site = "SMOKE-A2"
  $monthLabel = (Get-Date).ToUniversalTime().ToString("yyyy-MM")
  $encodedSite = [uri]::EscapeDataString($site)
  $encodedMonth = [uri]::EscapeDataString($monthLabel)
  $reportUri = "$BaseUrl/api/reports/official-documents/monthly?site=$encodedSite&month=$encodedMonth"
  $beforeReport = Invoke-JsonGet -Uri $reportUri -Headers $Headers
  $beforeTotal = Get-NumericProperty -Object $beforeReport -PropertyName "total_documents"
  $beforeLinked = Get-NumericProperty -Object $beforeReport -PropertyName "linked_work_order_documents"

  $document = Invoke-JsonPost -Uri "$BaseUrl/api/official-documents" -Headers $Headers -Body @{
    site = $site
    organization = "KEPCO"
    organization_code = "KEPCO"
    document_number = "SMOKE-A2-001"
    title = "A2-lite overdue document"
    document_type = "electricity"
    priority = "critical"
    received_at = ((Get-Date).ToUniversalTime()).ToString("o")
    due_at = ((Get-Date).ToUniversalTime().AddDays(-2)).ToString("o")
    required_action = "Create follow-up work order"
    summary = "A2-lite smoke candidate"
  }
  $documentId = Get-NumericProperty -Object $document -PropertyName "id"
  if ($documentId -le 0) {
    throw "A2-lite smoke failed: official document id missing"
  }

  $attachment = Invoke-MultipartFormPost `
    -Uri "$BaseUrl/api/official-documents/$documentId/attachments" `
    -Headers $Headers `
    -FileBytes ([System.Text.Encoding]::ASCII.GetBytes("%PDF-1.4 A2 lite smoke")) `
    -FileName "official-smoke.pdf" `
    -ContentType "application/pdf" `
    -FormFields @{ note = "A2-lite original" }
  $attachmentId = Get-NumericProperty -Object $attachment -PropertyName "id"
  if ($attachmentId -le 0) {
    throw "A2-lite smoke failed: attachment id missing"
  }

  $download = Invoke-HttpGet -Uri "$BaseUrl/api/official-documents/attachments/$attachmentId/download" -Headers $Headers
  $attachmentSha = ""
  if ($download.Headers -and $download.Headers["X-Attachment-SHA256"]) {
    $attachmentSha = "$($download.Headers["X-Attachment-SHA256"])".Trim()
  }
  if ($download.StatusCode -ne 200) {
    throw "A2-lite smoke failed: attachment download failed"
  }
  if ($attachmentSha.Length -ne 64) {
    throw "A2-lite smoke failed: attachment sha header missing"
  }

  $overdue = Invoke-JsonPost -Uri "$BaseUrl/api/official-documents/overdue/run?site=$encodedSite&limit=20" -Headers $Headers -Body @{}
  $candidateCount = Get-NumericProperty -Object $overdue -PropertyName "candidate_count"
  $workOrderCreatedCount = Get-NumericProperty -Object $overdue -PropertyName "work_order_created_count"
  $linkedExistingCount = Get-NumericProperty -Object $overdue -PropertyName "linked_existing_work_order_count"
  if ($candidateCount -lt 1) {
    throw "A2-lite smoke failed: overdue sync candidate count did not increase"
  }
  if (($workOrderCreatedCount + $linkedExistingCount) -lt 1) {
    throw "A2-lite smoke failed: overdue sync did not link or create a work order"
  }

  $loaded = Invoke-JsonGet -Uri "$BaseUrl/api/official-documents/$documentId" -Headers $Headers
  $linkedWorkOrderId = Get-NumericProperty -Object $loaded -PropertyName "linked_work_order_id"
  if ($linkedWorkOrderId -le 0) {
    throw "A2-lite smoke failed: linked work order id missing after overdue sync"
  }

  $afterReport = Invoke-JsonGet -Uri $reportUri -Headers $Headers
  $afterTotal = Get-NumericProperty -Object $afterReport -PropertyName "total_documents"
  $afterLinked = Get-NumericProperty -Object $afterReport -PropertyName "linked_work_order_documents"
  $entries = @($afterReport.entries)
  $matchingEntry = $null
  foreach ($entry in $entries) {
    if ((Get-NumericProperty -Object $entry -PropertyName "id") -eq $documentId) {
      $matchingEntry = $entry
      break
    }
  }
  if ($afterTotal -lt ($beforeTotal + 1)) {
    throw "A2-lite smoke failed: monthly report total did not increase"
  }
  if ($afterLinked -lt ($beforeLinked + 1)) {
    throw "A2-lite smoke failed: monthly report linked work order count did not increase"
  }
  if ($null -eq $matchingEntry) {
    throw "A2-lite smoke failed: monthly report entry missing"
  }
  if ((Get-NumericProperty -Object $matchingEntry -PropertyName "attachment_count") -lt 1) {
    throw "A2-lite smoke failed: monthly report attachment count missing"
  }

  Add-SmokeCheck `
    -Id "a2_lite_document_flow" `
    -Status "ok" `
    -Message "A2-lite flow ok (document_id=$documentId, attachment_id=$attachmentId, work_order_id=$linkedWorkOrderId, month=$monthLabel)"
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

  $mainShell = Invoke-HtmlGet -Uri "$BaseUrl/?tab=iam"
  $mainShellText = "$($mainShell.Content)"
  foreach ($marker in @("openLoginModalBtn", "panelIam", "panelInspection")) {
    if (-not $mainShellText.Contains($marker)) {
      throw "UI core path check failed: missing marker '$marker'"
    }
  }
  Add-SmokeCheck -Id "ui_main_shell" -Status "ok" -Message "Main HTML shell exposes auth/IAM/inspection entry points"

  if ($AdminToken -ne "") {
    $headers = @{ "X-Admin-Token" = $AdminToken }
    $deployChecklist = Invoke-JsonGet -Uri "$BaseUrl/api/ops/deploy/checklist" -Headers $headers
    if (-not $deployChecklist.policy.rollback_guide_exists) {
      throw "Deploy checklist validation failed: rollback guide file missing"
    }
    if ($deployChecklist.policy.rollback_guide_path) {
      $rollbackReference = "$($deployChecklist.policy.rollback_guide_path)"
    }
    if (-not $rollbackReference) {
      $rollbackReference = "docs/W15_MIGRATION_ROLLBACK.md"
    }
    $rollbackReferenceSha = "$($deployChecklist.policy.rollback_guide_sha256)"
    if (-not $deployChecklist.policy.rollback_guide_sha256) {
      throw "Deploy checklist validation failed: rollback guide checksum missing"
    }
    if (-not $ChecklistVersion) {
      $ChecklistVersion = "$($deployChecklist.version)"
    }
    Add-SmokeCheck -Id "rollback_guide" -Status "ok" -Message "Rollback guide presence/checksum validated ($rollbackReference)"

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
    # Ignore previous smoke status while evaluating the current smoke run.
    $criticalChecks = @($criticalChecks | Where-Object { $_.id -ne "deploy_smoke_checklist" })
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

    Invoke-A1LiteSmoke -Headers $headers
    Invoke-A2LiteSmoke -Headers $headers

    if ($RunRunbookGate) {
      $runbookRun = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/ops/runbook/checks/run" -Headers $headers -TimeoutSec $TimeoutSec
      $runbookRunCritical = @()
      if ($runbookRun.checks) {
        $runbookRunCritical = @($runbookRun.checks | Where-Object { $_.status -eq "critical" })
      }
      if (-not $RequireAuditChainOk) {
        $runbookRunCritical = @($runbookRunCritical | Where-Object { $_.id -ne "audit_chain_integrity" })
      }
      $runbookRunCritical = @($runbookRunCritical | Where-Object { $_.id -ne "deploy_smoke_checklist" })
      $criticalCount = $runbookRunCritical.Count
      $runbookGatePassed = ($criticalCount -le 0)
      if (-not $runbookGatePassed) {
        $criticalIds = ($runbookRunCritical | ForEach-Object { $_.id }) -join ","
        throw "Runbook gate failed: critical checks=$criticalIds"
      }
      Add-SmokeCheck -Id "runbook_gate" -Status "ok" -Message "Runbook gate passed"
    } else {
      $runbookGatePassed = $true
      Add-SmokeCheck -Id "runbook_gate" -Status "skipped" -Message "Runbook gate disabled by parameter"
    }
  } else {
    $skipMessage = "Admin token not provided or could not be resolved; auth/runbook/security checks skipped"
    Add-SmokeCheck -Id "admin_checks" -Status "skipped" -Message $skipMessage
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
