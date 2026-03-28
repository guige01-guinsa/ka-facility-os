param(
  [string]$PrimaryServiceId = "",
  [string]$PrimaryServiceName = "ka-facility-os",
  [string]$CoreMirrorServiceName = "ka-facility-core",
  [string]$AdminServiceName = "ka-platform-admin",
  [string]$RenderApiKey = "",
  [int]$PollSeconds = 10,
  [int]$MaxWaitSeconds = 1800,
  [switch]$SkipFullSmoke
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot/render_env_utils.ps1"

if ([string]::IsNullOrWhiteSpace($RenderApiKey)) {
  $RenderApiKey = $env:RENDER_API_KEY
}
if ([string]::IsNullOrWhiteSpace($RenderApiKey)) {
  $RenderApiKey = [Environment]::GetEnvironmentVariable("RENDER_API_KEY", "User")
}
if ([string]::IsNullOrWhiteSpace($RenderApiKey)) {
  throw "Render API key is required (param -RenderApiKey or env RENDER_API_KEY)."
}

$PrimaryServiceId = Resolve-RenderServiceId -ServiceId $PrimaryServiceId
if ([string]::IsNullOrWhiteSpace($PrimaryServiceId)) {
  throw "Primary Render service id is required (param -PrimaryServiceId or env RENDER_SERVICE_ID)."
}

$apiBase = "https://api.render.com/v1"
$headers = @{
  Authorization = "Bearer $RenderApiKey"
  "Content-Type" = "application/json"
}

function Get-RenderService {
  param([Parameter(Mandatory = $true)][string]$ServiceId)
  return Invoke-RestMethod -Method Get -Uri "$apiBase/services/$ServiceId" -Headers $headers
}

function Get-RenderServicesByOwner {
  param([Parameter(Mandatory = $true)][string]$OwnerId)

  $all = @()
  $cursor = $null
  do {
    $uri = "$apiBase/services?ownerId=$OwnerId&limit=100"
    if ($cursor) {
      $uri += "&cursor=$cursor"
    }
    $items = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    if (-not $items) {
      break
    }
    $all += @($items)
    if ($items.Count -lt 100) {
      break
    }
    $cursor = "$($items[-1].cursor)"
  } while ($cursor)
  return $all
}

function Find-RenderServiceByName {
  param(
    [Parameter(Mandatory = $true)][string]$OwnerId,
    [Parameter(Mandatory = $true)][string]$Name
  )

  $items = Get-RenderServicesByOwner -OwnerId $OwnerId
  foreach ($item in $items) {
    if ($null -eq $item.service) {
      continue
    }
    if ("$($item.service.name)" -eq $Name) {
      return $item.service
    }
  }
  return $null
}

function Get-AllEnvVars {
  param([Parameter(Mandatory = $true)][string]$ServiceId)

  $all = @()
  $cursor = $null
  do {
    $uri = "$apiBase/services/$ServiceId/env-vars?limit=100"
    if ($cursor) {
      $uri += "&cursor=$cursor"
    }
    $items = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    if (-not $items) {
      break
    }
    foreach ($item in $items) {
      if ($null -eq $item.envVar) {
        continue
      }
      $all += @{
        key = "$($item.envVar.key)"
        value = "$($item.envVar.value)"
      }
    }
    if ($items.Count -lt 100) {
      break
    }
    $cursor = "$($items[-1].cursor)"
  } while ($cursor)
  return $all
}

function Set-AllEnvVars {
  param(
    [Parameter(Mandatory = $true)][string]$ServiceId,
    [Parameter(Mandatory = $true)][array]$EnvVars
  )

  Invoke-RestMethod -Method Put -Uri "$apiBase/services/$ServiceId/env-vars" -Headers $headers -Body ($EnvVars | ConvertTo-Json -Depth 8) | Out-Null
}

function Get-LatestDeploy {
  param([Parameter(Mandatory = $true)][string]$ServiceId)

  $deploys = Invoke-RestMethod -Method Get -Uri "$apiBase/services/$ServiceId/deploys?limit=5" -Headers $headers
  return $deploys | ForEach-Object { $_.deploy } | Where-Object { $null -ne $_ } | Select-Object -First 1
}

function Start-RenderDeploy {
  param([Parameter(Mandatory = $true)][string]$ServiceId)
  Invoke-RestMethod -Method Post -Uri "$apiBase/services/$ServiceId/deploys" -Headers $headers -Body "{}" | Out-Null
}

function Wait-ServiceLive {
  param(
    [Parameter(Mandatory = $true)][string]$ServiceId,
    [string]$PreviousDeployId = ""
  )

  $deadline = (Get-Date).AddSeconds($MaxWaitSeconds)
  while ((Get-Date) -lt $deadline) {
    $latest = Get-LatestDeploy -ServiceId $ServiceId
    if ($null -eq $latest) {
      Start-Sleep -Seconds $PollSeconds
      continue
    }
    $deployId = "$($latest.id)"
    if (-not [string]::IsNullOrWhiteSpace($PreviousDeployId) -and $deployId -eq $PreviousDeployId) {
      Start-Sleep -Seconds $PollSeconds
      continue
    }
    if ("$($latest.status)" -eq "live") {
      return $deployId
    }
    if ("$($latest.status)" -in @("build_failed", "update_failed", "canceled")) {
      throw "Deploy failed for service $ServiceId (deploy=$deployId status=$($latest.status))."
    }
    Start-Sleep -Seconds $PollSeconds
  }
  throw "Timed out waiting for service $ServiceId to become live."
}

function Set-OrAddEnvVar {
  param(
    [Parameter(Mandatory = $true)][array]$EnvVars,
    [Parameter(Mandatory = $true)][string]$Key,
    [Parameter(Mandatory = $true)][string]$Value
  )

  $updated = @()
  $matched = $false
  foreach ($envVar in $EnvVars) {
    if ("$($envVar.key)" -eq $Key) {
      $updated += @{
        key = $Key
        value = $Value
      }
      $matched = $true
    } else {
      $updated += @{
        key = "$($envVar.key)"
        value = "$($envVar.value)"
      }
    }
  }
  if (-not $matched) {
    $updated += @{
      key = $Key
      value = $Value
    }
  }
  return ,$updated
}

function Rewrite-WebhookTargets {
  param(
    [string]$RawValue,
    [string[]]$LegacyTargets,
    [string]$ReplacementTarget
  )

  if ([string]::IsNullOrWhiteSpace($RawValue)) {
    return ""
  }

  $parts = @($RawValue -split "[,;`n]")
  $rewritten = @()
  foreach ($part in $parts) {
    $candidate = $part.Trim()
    if ([string]::IsNullOrWhiteSpace($candidate)) {
      continue
    }
    if ($LegacyTargets -contains $candidate) {
      $candidate = $ReplacementTarget
    }
    if ($rewritten -notcontains $candidate) {
      $rewritten += $candidate
    }
  }
  return ($rewritten -join ",")
}

function Update-WebServiceStartCommand {
  param(
    [Parameter(Mandatory = $true)][object]$Service,
    [Parameter(Mandatory = $true)][string]$StartCommand
  )

  $payload = @{
    repo = "$($Service.repo)"
    branch = "$($Service.branch)"
    rootDir = "$($Service.rootDir)"
    autoDeploy = "$($Service.autoDeploy)"
    serviceDetails = @{
      runtime = "python"
      plan = "$($Service.serviceDetails.plan)"
      region = "$($Service.serviceDetails.region)"
      healthCheckPath = "/health"
      pullRequestPreviewsEnabled = "$($Service.serviceDetails.pullRequestPreviewsEnabled)"
      previews = $Service.serviceDetails.previews
      envSpecificDetails = @{
        buildCommand = "$($Service.serviceDetails.envSpecificDetails.buildCommand)"
        startCommand = $StartCommand
      }
    }
  }
  Invoke-RestMethod -Method Patch -Uri "$apiBase/services/$($Service.id)" -Headers $headers -Body ($payload | ConvertTo-Json -Depth 8) | Out-Null
}

$primaryService = Get-RenderService -ServiceId $PrimaryServiceId
if ("$($primaryService.type)" -ne "web_service") {
  throw "Primary service must be a web service."
}
if ("$($primaryService.name)" -ne $PrimaryServiceName) {
  Write-Output "PRIMARY_SERVICE_WARN expectedName=$PrimaryServiceName actualName=$($primaryService.name)"
}

$ownerId = "$($primaryService.ownerId)"
$adminService = Find-RenderServiceByName -OwnerId $ownerId -Name $AdminServiceName
if ($null -eq $adminService) {
  throw "Could not find admin service '$AdminServiceName'."
}
$coreMirrorService = Find-RenderServiceByName -OwnerId $ownerId -Name $CoreMirrorServiceName

$adminBaseUrl = "$($adminService.serviceDetails.url)"
$primaryBaseUrl = "$($primaryService.serviceDetails.url)"
$coreMirrorBaseUrl = if ($null -ne $coreMirrorService) { "$($coreMirrorService.serviceDetails.url)" } else { "" }
$adminWebhookUrl = "$adminBaseUrl/api/ops/alerts/webhook/internal"

$legacyWebhookTargets = @(
  "$primaryBaseUrl/api/ops/alerts/webhook/internal"
)
if (-not [string]::IsNullOrWhiteSpace($coreMirrorBaseUrl)) {
  $legacyWebhookTargets += "$coreMirrorBaseUrl/api/ops/alerts/webhook/internal"
}
$legacyWebhookTargets = @($legacyWebhookTargets | Select-Object -Unique)

$allServices = Get-RenderServicesByOwner -OwnerId $ownerId | ForEach-Object { $_.service } | Where-Object { $null -ne $_ }
$updatedEnvServices = @()
foreach ($service in $allServices) {
  $envVars = Get-AllEnvVars -ServiceId $service.id
  if (-not $envVars -or $envVars.Count -eq 0) {
    continue
  }

  $hasWebhookUrl = @($envVars | Where-Object { "$($_.key)" -eq "ALERT_WEBHOOK_URL" }).Count -gt 0
  $hasWebhookUrls = @($envVars | Where-Object { "$($_.key)" -eq "ALERT_WEBHOOK_URLS" }).Count -gt 0
  if (-not $hasWebhookUrl -and -not $hasWebhookUrls -and "$($service.id)" -ne "$($primaryService.id)" -and "$($service.id)" -ne "$($adminService.id)") {
    continue
  }

  $newEnvVars = @()
  foreach ($envVar in $envVars) {
    $key = "$($envVar.key)"
    $value = "$($envVar.value)"
    if ($key -eq "ALERT_WEBHOOK_URL") {
      $value = $adminWebhookUrl
    } elseif ($key -eq "ALERT_WEBHOOK_URLS") {
      $value = Rewrite-WebhookTargets -RawValue $value -LegacyTargets $legacyWebhookTargets -ReplacementTarget $adminWebhookUrl
    }
    $newEnvVars += @{
      key = $key
      value = $value
    }
  }

  if ("$($service.id)" -eq "$($primaryService.id)") {
    $newEnvVars = Set-OrAddEnvVar -EnvVars $newEnvVars -Key "ALERT_WEBHOOK_URL" -Value $adminWebhookUrl
    $newEnvVars = Set-OrAddEnvVar -EnvVars $newEnvVars -Key "SPLIT_APP_RUN_BACKGROUND_AUTOMATION" -Value "true"
  } elseif ($null -ne $coreMirrorService -and "$($service.id)" -eq "$($coreMirrorService.id)") {
    $newEnvVars = Set-OrAddEnvVar -EnvVars $newEnvVars -Key "SPLIT_APP_RUN_BACKGROUND_AUTOMATION" -Value "false"
  } elseif ("$($service.id)" -eq "$($adminService.id)") {
    $newEnvVars = Set-OrAddEnvVar -EnvVars $newEnvVars -Key "ALERT_WEBHOOK_URL" -Value $adminWebhookUrl
  }

  Set-AllEnvVars -ServiceId $service.id -EnvVars $newEnvVars
  $updatedEnvServices += "$($service.name)"
}

$primaryPreviousDeploy = Get-LatestDeploy -ServiceId $primaryService.id
$adminPreviousDeploy = Get-LatestDeploy -ServiceId $adminService.id
$corePreviousDeploy = if ($null -ne $coreMirrorService) { Get-LatestDeploy -ServiceId $coreMirrorService.id } else { $null }
$primaryPreviousDeployId = if ($null -ne $primaryPreviousDeploy) { "$($primaryPreviousDeploy.id)" } else { "" }
$adminPreviousDeployId = if ($null -ne $adminPreviousDeploy) { "$($adminPreviousDeploy.id)" } else { "" }
$corePreviousDeployId = if ($null -ne $corePreviousDeploy) { "$($corePreviousDeploy.id)" } else { "" }

Update-WebServiceStartCommand -Service $primaryService -StartCommand "uvicorn app.entrypoints.facility_core:app --host 0.0.0.0 --port `$PORT"
if ($null -ne $coreMirrorService) {
  Update-WebServiceStartCommand -Service $coreMirrorService -StartCommand "uvicorn app.entrypoints.facility_core:app --host 0.0.0.0 --port `$PORT"
}
Update-WebServiceStartCommand -Service $adminService -StartCommand "uvicorn app.entrypoints.platform_admin:app --host 0.0.0.0 --port `$PORT"

Start-RenderDeploy -ServiceId $adminService.id
Start-RenderDeploy -ServiceId $primaryService.id
if ($null -ne $coreMirrorService) {
  Start-RenderDeploy -ServiceId $coreMirrorService.id
}

$adminDeployId = Wait-ServiceLive -ServiceId $adminService.id -PreviousDeployId $adminPreviousDeployId
$primaryDeployId = Wait-ServiceLive -ServiceId $primaryService.id -PreviousDeployId $primaryPreviousDeployId
$coreDeployId = ""
if ($null -ne $coreMirrorService) {
  $coreDeployId = Wait-ServiceLive -ServiceId $coreMirrorService.id -PreviousDeployId $corePreviousDeployId
}

$resolvedAdminToken = Resolve-RenderAdminToken -ServiceId $adminService.id -RenderApiKey $RenderApiKey
if ([string]::IsNullOrWhiteSpace($resolvedAdminToken)) {
  throw "Could not resolve ADMIN_TOKEN from admin service."
}

$primaryInfo = Invoke-RestMethod -Method Get -Uri "$primaryBaseUrl/api/service-info" -TimeoutSec 30
if ("$($primaryInfo.service)" -ne "ka-facility-core") {
  throw "Primary service info mismatch after cutover. Expected ka-facility-core, got $($primaryInfo.service)"
}

$primaryComplaints = Invoke-WebRequest -Method Get -Uri "$primaryBaseUrl/web/complaints" -UseBasicParsing -TimeoutSec 30
if ($primaryComplaints.StatusCode -ne 200) {
  throw "Primary complaints page failed after cutover."
}

try {
  Invoke-RestMethod -Method Get -Uri "$primaryBaseUrl/api/public/adoption-plan" -TimeoutSec 30 | Out-Null
  throw "Primary service still exposes adoption plan after cutover."
} catch {
  $statusCode = $null
  if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
    $statusCode = $_.Exception.Response.StatusCode.value__
  }
  if ($statusCode -ne 404) {
    throw
  }
}

$adminInfo = Invoke-RestMethod -Method Get -Uri "$adminBaseUrl/api/service-info" -TimeoutSec 30
if ("$($adminInfo.service)" -ne "ka-platform-admin") {
  throw "Admin service info mismatch after cutover. Expected ka-platform-admin, got $($adminInfo.service)"
}

$checklistHeaders = @{ "X-Admin-Token" = $resolvedAdminToken }
$deployChecklist = Invoke-RestMethod -Method Get -Uri "$adminBaseUrl/api/ops/deploy/checklist" -Headers $checklistHeaders -TimeoutSec 30
if (-not $deployChecklist.policy.rollback_guide_exists) {
  throw "Admin governance deploy checklist is missing rollback guide after cutover."
}

if (-not $SkipFullSmoke) {
  & "$PSScriptRoot/post_deploy_smoke.ps1" `
    -BaseUrl $primaryBaseUrl `
    -GovernanceBaseUrl $adminBaseUrl `
    -AdminToken $resolvedAdminToken `
    -ServiceId $adminService.id `
    -RenderApiKey $RenderApiKey `
    -RecordSmokeRun $true
}

Write-Output "CUTOVER_OK primary=$primaryBaseUrl admin=$adminBaseUrl updated_env_services=$($updatedEnvServices -join ',') primary_deploy=$primaryDeployId admin_deploy=$adminDeployId core_deploy=$coreDeployId"
