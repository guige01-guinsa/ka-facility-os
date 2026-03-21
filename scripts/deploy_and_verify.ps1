param(
  [string]$DeployHookUrl = "",
  [string]$ServiceId = "",
  [Parameter(Mandatory = $true)]
  [string]$BaseUrl,
  [string]$ExpectedServiceName = "ka-facility-os",
  [string]$ExpectedRepoFragment = "guige01-guinsa/ka-facility-os",
  [string]$AdminToken = "",
  [string]$RenderApiKey = "",
  [int]$PollSeconds = 5,
  [int]$MaxWaitSeconds = 900,
  [switch]$RollbackOnFailure,
  [string]$ExpectRateLimitBackend = "",
  [bool]$RunA1Lite = $true,
  [bool]$RunA2Lite = $false,
  [bool]$RunRunbookGate = $true,
  [string]$ChecklistVersion = "",
  [switch]$SkipPreDeploySmokeTests,
  [string]$PythonCommand = "python",
  [string]$ExpectedCommit = "",
  [int]$MaxDeployAttempts = 3
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot/render_env_utils.ps1"
$UserRenderServiceId = [Environment]::GetEnvironmentVariable("RENDER_SERVICE_ID", "User")
$ProcessRenderServiceId = $env:RENDER_SERVICE_ID
$ExplicitServiceIdProvided = -not [string]::IsNullOrWhiteSpace($ServiceId)
$ServiceId = Resolve-RenderServiceId -ServiceId $ServiceId
if ($ServiceId -eq "") {
  throw "Render service id is required (param -ServiceId or env RENDER_SERVICE_ID)."
}

if ($RenderApiKey -eq "") {
  $RenderApiKey = $env:RENDER_API_KEY
}
if ($RenderApiKey -eq "") {
  throw "Render API key is required (param -RenderApiKey or env RENDER_API_KEY)."
}

$apiBase = "https://api.render.com/v1"
$headers = @{ Authorization = "Bearer $RenderApiKey" }
$projectRoot = Split-Path -Parent $PSScriptRoot

function Get-Deploys {
  param(
    [int]$Limit = 10,
    [string]$TargetServiceId = $ServiceId
  )
  return Invoke-RestMethod -Method Get -Uri "$apiBase/services/$TargetServiceId/deploys?limit=$Limit" -Headers $headers
}

function Get-ServiceInfo {
  param([string]$TargetServiceId = $ServiceId)
  return Invoke-RestMethod -Method Get -Uri "$apiBase/services/$TargetServiceId" -Headers $headers
}

function Start-Deploy {
  param([string]$TargetServiceId = $ServiceId)
  if (-not [string]::IsNullOrWhiteSpace($DeployHookUrl)) {
    Invoke-WebRequest -Method Post -Uri $DeployHookUrl -UseBasicParsing | Out-Null
    return
  }
  Invoke-RestMethod -Method Post -Uri "$apiBase/services/$TargetServiceId/deploys" -Headers $headers -Body "{}" | Out-Null
}

function Invoke-PreDeploySmokeTests {
  if ($SkipPreDeploySmokeTests) {
    Write-Output "PRE_DEPLOY_SMOKE_SKIPPED"
    return
  }
  Push-Location $projectRoot
  try {
    & $PythonCommand -m pytest -q -m smoke
    $exitCode = $LASTEXITCODE
  } finally {
    Pop-Location
  }
  if ($exitCode -ne 0) {
    throw "Pre-deploy smoke tests failed (python -m pytest -q -m smoke)."
  }
  Write-Output "PRE_DEPLOY_SMOKE_OK"
}

function Resolve-ExpectedCommit {
  if (-not [string]::IsNullOrWhiteSpace($ExpectedCommit)) {
    return $ExpectedCommit.Trim()
  }

  Push-Location $projectRoot
  try {
    $commit = (& git rev-parse HEAD 2>$null)
    $exitCode = $LASTEXITCODE
  } finally {
    Pop-Location
  }
  if ($exitCode -ne 0) {
    return ""
  }
  $resolved = "$commit".Trim()
  if ([string]::IsNullOrWhiteSpace($resolved)) {
    return ""
  }
  return $resolved
}

function Get-DeployCommitId {
  param([object]$Deploy)

  if ($null -eq $Deploy) {
    return ""
  }
  if ($Deploy.PSObject.Properties.Name -notcontains "commit") {
    return ""
  }
  $commit = $Deploy.commit
  if ($null -eq $commit) {
    return ""
  }
  if ($commit.PSObject.Properties.Name -notcontains "id") {
    return ""
  }
  return "$($commit.id)"
}

function Test-ServiceInfoMatches {
  param([object]$Info)

  $candidateName = "$($Info.name)"
  $candidateRepo = "$($Info.repo)"
  if ($ExpectedServiceName -ne "" -and $candidateName -ne $ExpectedServiceName) {
    return $false
  }
  if ($ExpectedRepoFragment -ne "" -and (-not $candidateRepo.Contains($ExpectedRepoFragment))) {
    return $false
  }
  return $true
}

function Try-Rollback {
  param(
    [string]$DeployId,
    [string]$TargetServiceId = $ServiceId
  )
  try {
    Invoke-RestMethod -Method Post -Uri "$apiBase/services/$TargetServiceId/deploys/$DeployId/rollback" -Headers $headers | Out-Null
    Write-Output "ROLLBACK_TRIGGERED $DeployId"
    return $true
  } catch {
    Write-Output "ROLLBACK_API_FAILED"
    return $false
  }
}

$serviceInfo = Get-ServiceInfo
if (-not (Test-ServiceInfoMatches -Info $serviceInfo)) {
  if (
    (-not $ExplicitServiceIdProvided) `
    -and (-not [string]::IsNullOrWhiteSpace($UserRenderServiceId)) `
    -and $UserRenderServiceId -ne $ServiceId
  ) {
    $fallbackServiceInfo = Get-ServiceInfo -TargetServiceId $UserRenderServiceId
    if (Test-ServiceInfoMatches -Info $fallbackServiceInfo) {
      Write-Output "TARGET_SERVICE_FALLBACK processEnv=$ProcessRenderServiceId userEnv=$UserRenderServiceId"
      $ServiceId = $UserRenderServiceId
      $serviceInfo = $fallbackServiceInfo
    }
  }
}

$serviceName = "$($serviceInfo.name)"
$serviceRepo = "$($serviceInfo.repo)"
$serviceUrl = ""
if ($serviceInfo.serviceDetails) {
  $serviceUrl = "$($serviceInfo.serviceDetails.url)"
}
Write-Output "TARGET_SERVICE id=$ServiceId name=$serviceName repo=$serviceRepo url=$serviceUrl"
if (-not (Test-ServiceInfoMatches -Info $serviceInfo)) {
  throw "Service validation failed: expected name '$ExpectedServiceName' and repo containing '$ExpectedRepoFragment', got name '$serviceName' repo '$serviceRepo' (serviceId=$ServiceId)"
}

$before = Get-Deploys -Limit 20
$lastLive = ($before | ForEach-Object { $_.deploy } | Where-Object { $_.status -eq "live" } | Select-Object -First 1)
$lastLiveId = if ($lastLive) { $lastLive.id } else { "" }
$resolvedExpectedCommit = Resolve-ExpectedCommit
if ($resolvedExpectedCommit -ne "") {
  Write-Output "EXPECTED_COMMIT $resolvedExpectedCommit"
}

Invoke-PreDeploySmokeTests
$targetDeploy = $null
for ($attempt = 1; $attempt -le [Math]::Max(1, $MaxDeployAttempts); $attempt++) {
  $attemptBeforeIds = @(
    Get-Deploys -Limit 20 |
      ForEach-Object { $_.deploy } |
      Where-Object { $null -ne $_ } |
      ForEach-Object { "$($_.id)" }
  )

  Write-Output "DEPLOY_TRIGGER attempt=$attempt service=$ServiceId"
  Start-Deploy -TargetServiceId $ServiceId

  $deadline = (Get-Date).AddSeconds($MaxWaitSeconds)
  $targetDeploy = $null
  while ((Get-Date) -lt $deadline) {
    $list = Get-Deploys -Limit 20 -TargetServiceId $ServiceId
    $targetDeploy = $list |
      ForEach-Object { $_.deploy } |
      Where-Object { $null -ne $_ -and $attemptBeforeIds -notcontains "$($_.id)" } |
      Select-Object -First 1
    if ($null -eq $targetDeploy) {
      Start-Sleep -Seconds $PollSeconds
      continue
    }
    if ($targetDeploy.status -in @("live", "build_failed", "update_failed", "canceled")) {
      break
    }
    Start-Sleep -Seconds $PollSeconds
  }

  if ($null -eq $targetDeploy) {
    throw "No new deploy information returned for attempt $attempt."
  }

  if ($targetDeploy.status -ne "live") {
    Write-Output "DEPLOY_FAILED status=$($targetDeploy.status) deploy=$($targetDeploy.id)"
    if ($RollbackOnFailure -and $lastLiveId -ne "") {
      $rollbackTriggered = Try-Rollback -DeployId $lastLiveId -TargetServiceId $ServiceId
      if (-not $rollbackTriggered) {
        Write-Output "Manual rollback required via Render dashboard."
      }
    }
    exit 1
  }

  $actualCommit = Get-DeployCommitId -Deploy $targetDeploy
  if ($resolvedExpectedCommit -ne "" -and $actualCommit -ne "" -and $actualCommit -ne $resolvedExpectedCommit) {
    Write-Output "DEPLOY_COMMIT_MISMATCH attempt=$attempt expected=$resolvedExpectedCommit actual=$actualCommit deploy=$($targetDeploy.id)"
    if ($attempt -lt [Math]::Max(1, $MaxDeployAttempts)) {
      Start-Sleep -Seconds ([Math]::Max($PollSeconds, 5))
      continue
    }
    throw "Deploy commit mismatch after $attempt attempts: expected '$resolvedExpectedCommit' but got '$actualCommit'."
  }
  if ($resolvedExpectedCommit -ne "" -and $actualCommit -ne "") {
    Write-Output "DEPLOY_COMMIT_MATCH expected=$resolvedExpectedCommit actual=$actualCommit deploy=$($targetDeploy.id)"
  } elseif ($resolvedExpectedCommit -ne "") {
    Write-Output "DEPLOY_COMMIT_UNKNOWN expected=$resolvedExpectedCommit deploy=$($targetDeploy.id)"
  }
  break
}

& "$PSScriptRoot/post_deploy_smoke.ps1" `
  -BaseUrl $BaseUrl `
  -AdminToken $AdminToken `
  -ServiceId $ServiceId `
  -RenderApiKey $RenderApiKey `
  -ExpectRateLimitBackend $ExpectRateLimitBackend `
  -DeployId $targetDeploy.id `
  -ChecklistVersion $ChecklistVersion `
  -RunA1Lite $RunA1Lite `
  -RunA2Lite $RunA2Lite `
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
