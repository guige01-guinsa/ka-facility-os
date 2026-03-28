param(
  [string]$RenderApiKey = "",
  [int]$PollSeconds = 10,
  [int]$MaxWaitSecondsPerService = 1200
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($RenderApiKey)) {
  $RenderApiKey = $env:RENDER_API_KEY
}
if ([string]::IsNullOrWhiteSpace($RenderApiKey)) {
  throw "Render API key is required (param -RenderApiKey or env RENDER_API_KEY)."
}

$headers = @{ Authorization = "Bearer $RenderApiKey" }
$apiBase = "https://api.render.com/v1"

$orderedNames = @(
  "ka-facility-os-alert-guard-recover",
  "ka-facility-os-alert-retention",
  "ka-facility-os-alert-retry",
  "ka-facility-os",
  "ka-platform-admin"
)

function Get-AllServices {
  return Invoke-RestMethod -Method Get -Uri "$apiBase/services?limit=100" -Headers $headers
}

function Resolve-Service {
  param([string]$Name)
  $service = Get-AllServices | Where-Object { $_.service.name -eq $Name } | Select-Object -First 1
  if ($null -eq $service) {
    throw "Render service not found: $Name"
  }
  return $service.service
}

function Get-Deploys {
  param([string]$ServiceId, [int]$Limit = 10)
  return Invoke-RestMethod -Method Get -Uri "$apiBase/services/$ServiceId/deploys?limit=$Limit" -Headers $headers
}

function Start-ServiceDeploy {
  param([string]$ServiceId)
  return Invoke-RestMethod -Method Post -Uri "$apiBase/services/$ServiceId/deploys" -Headers $headers -Body "{}"
}

function Get-TerminalStatus {
  param([string]$ServiceId, [string[]]$ExistingDeployIds)
  $deadline = (Get-Date).AddSeconds($MaxWaitSecondsPerService)
  while ((Get-Date) -lt $deadline) {
    $deploys = Get-Deploys -ServiceId $ServiceId -Limit 10
    $newDeploy = $deploys |
      ForEach-Object { $_.deploy } |
      Where-Object { $null -ne $_ -and $ExistingDeployIds -notcontains "$($_.id)" } |
      Select-Object -First 1

    if ($null -eq $newDeploy) {
      Start-Sleep -Seconds $PollSeconds
      continue
    }

    $status = "$($newDeploy.status)"
    if ($status -in @("live", "build_failed", "update_failed", "canceled")) {
      return $newDeploy
    }
    Start-Sleep -Seconds $PollSeconds
  }

  throw "Timed out waiting for deploy terminal status for serviceId=$ServiceId"
}

foreach ($name in $orderedNames) {
  $service = Resolve-Service -Name $name
  $deploysBefore = Get-Deploys -ServiceId $service.id -Limit 10
  $existingIds = @(
    $deploysBefore |
      ForEach-Object { $_.deploy } |
      Where-Object { $null -ne $_ } |
      ForEach-Object { "$($_.id)" }
  )

  Write-Output "DEPLOY_START name=$name id=$($service.id)"
  try {
    Start-ServiceDeploy -ServiceId $service.id | Out-Null
  } catch {
    Write-Output "DEPLOY_TRIGGER_FAILED name=$name message=$($_.Exception.Message)"
    throw
  }

  $finalDeploy = Get-TerminalStatus -ServiceId $service.id -ExistingDeployIds $existingIds
  $commitId = ""
  if ($finalDeploy.commit -and $finalDeploy.commit.id) {
    $commitId = "$($finalDeploy.commit.id)"
  }

  Write-Output "DEPLOY_RESULT name=$name status=$($finalDeploy.status) deploy=$($finalDeploy.id) commit=$commitId"

  if ("$($finalDeploy.status)" -ne "live") {
    throw "Deployment failed for $name with status $($finalDeploy.status)"
  }
}

Write-Output "RECOVERY_DEPLOY_SEQUENCE_OK"
