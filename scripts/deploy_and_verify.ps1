param(
  [Parameter(Mandatory = $true)]
  [string]$DeployHookUrl,
  [Parameter(Mandatory = $true)]
  [string]$ServiceId,
  [Parameter(Mandatory = $true)]
  [string]$BaseUrl,
  [string]$AdminToken = "",
  [string]$RenderApiKey = "",
  [int]$PollSeconds = 5,
  [int]$MaxWaitSeconds = 900,
  [switch]$RollbackOnFailure,
  [string]$ExpectRateLimitBackend = "",
  [bool]$RunRunbookGate = $true,
  [string]$ChecklistVersion = "2026.03.v1"
)

$ErrorActionPreference = "Stop"

if ($RenderApiKey -eq "") {
  $RenderApiKey = $env:RENDER_API_KEY
}
if ($RenderApiKey -eq "") {
  throw "Render API key is required (param -RenderApiKey or env RENDER_API_KEY)."
}

$apiBase = "https://api.render.com/v1"
$headers = @{ Authorization = "Bearer $RenderApiKey" }

function Get-Deploys {
  param([int]$Limit = 10)
  return Invoke-RestMethod -Method Get -Uri "$apiBase/services/$ServiceId/deploys?limit=$Limit" -Headers $headers
}

function Try-Rollback {
  param([string]$DeployId)
  try {
    Invoke-RestMethod -Method Post -Uri "$apiBase/services/$ServiceId/deploys/$DeployId/rollback" -Headers $headers | Out-Null
    Write-Output "ROLLBACK_TRIGGERED $DeployId"
    return $true
  } catch {
    Write-Output "ROLLBACK_API_FAILED"
    return $false
  }
}

$before = Get-Deploys -Limit 20
$lastLive = ($before | ForEach-Object { $_.deploy } | Where-Object { $_.status -eq "live" } | Select-Object -First 1)
$lastLiveId = if ($lastLive) { $lastLive.id } else { "" }

Invoke-WebRequest -Method Post -Uri $DeployHookUrl -UseBasicParsing | Out-Null

$deadline = (Get-Date).AddSeconds($MaxWaitSeconds)
$targetDeploy = $null

while ((Get-Date) -lt $deadline) {
  $list = Get-Deploys -Limit 10
  $targetDeploy = $list[0].deploy
  if ($targetDeploy.status -in @("live", "build_failed", "update_failed", "canceled")) {
    break
  }
  Start-Sleep -Seconds $PollSeconds
}

if ($null -eq $targetDeploy) {
  throw "No deploy information returned."
}

if ($targetDeploy.status -ne "live") {
  Write-Output "DEPLOY_FAILED status=$($targetDeploy.status) deploy=$($targetDeploy.id)"
  if ($RollbackOnFailure -and $lastLiveId -ne "") {
    $rollbackTriggered = Try-Rollback -DeployId $lastLiveId
    if (-not $rollbackTriggered) {
      Write-Output "Manual rollback required via Render dashboard."
    }
  }
  exit 1
}

& "$PSScriptRoot/post_deploy_smoke.ps1" `
  -BaseUrl $BaseUrl `
  -AdminToken $AdminToken `
  -ExpectRateLimitBackend $ExpectRateLimitBackend `
  -DeployId $targetDeploy.id `
  -ChecklistVersion $ChecklistVersion `
  -RunRunbookGate $RunRunbookGate `
  -RecordSmokeRun $true
$smokeSucceeded = $?
if (-not $smokeSucceeded) {
  Write-Output "SMOKE_FAILED deploy=$($targetDeploy.id)"
  if ($RollbackOnFailure -and $lastLiveId -ne "") {
    $rollbackTriggered = Try-Rollback -DeployId $lastLiveId
    if (-not $rollbackTriggered) {
      Write-Output "Manual rollback required via Render dashboard."
    }
  }
  exit 1
}

Write-Output "DEPLOY_AND_SMOKE_OK deploy=$($targetDeploy.id)"
