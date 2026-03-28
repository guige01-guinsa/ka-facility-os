param(
  [string]$SourceServiceId = "",
  [string]$RenderApiKey = "",
  [string]$CoreServiceName = "",
  [string]$AdminServiceName = "ka-platform-admin",
  [int]$PollSeconds = 10,
  [int]$MaxWaitSeconds = 1800
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

$SourceServiceId = Resolve-RenderServiceId -ServiceId $SourceServiceId
if ([string]::IsNullOrWhiteSpace($SourceServiceId)) {
  throw "Source Render service id is required (param -SourceServiceId or env RENDER_SERVICE_ID)."
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

function New-WebServicePayload {
  param(
    [Parameter(Mandatory = $true)][object]$SourceService,
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][string]$StartCommand,
    [Parameter(Mandatory = $true)][array]$EnvVars
  )

  return @{
    type = "web_service"
    name = $Name
    ownerId = "$($SourceService.ownerId)"
    repo = "$($SourceService.repo)"
    branch = "$($SourceService.branch)"
    rootDir = "$($SourceService.rootDir)"
    autoDeploy = "$($SourceService.autoDeploy)"
    envVars = $EnvVars
    serviceDetails = @{
      runtime = "python"
      plan = "$($SourceService.serviceDetails.plan)"
      region = "$($SourceService.serviceDetails.region)"
      healthCheckPath = "/health"
      pullRequestPreviewsEnabled = "$($SourceService.serviceDetails.pullRequestPreviewsEnabled)"
      previews = $SourceService.serviceDetails.previews
      envSpecificDetails = @{
        buildCommand = "$($SourceService.serviceDetails.envSpecificDetails.buildCommand)"
        startCommand = $StartCommand
      }
    }
  }
}

function Update-WebService {
  param(
    [Parameter(Mandatory = $true)][string]$ServiceId,
    [Parameter(Mandatory = $true)][object]$SourceService,
    [Parameter(Mandatory = $true)][string]$StartCommand,
    [Parameter(Mandatory = $true)][array]$EnvVars
  )

  $patchPayload = @{
    repo = "$($SourceService.repo)"
    branch = "$($SourceService.branch)"
    rootDir = "$($SourceService.rootDir)"
    autoDeploy = "$($SourceService.autoDeploy)"
    serviceDetails = @{
      runtime = "python"
      plan = "$($SourceService.serviceDetails.plan)"
      region = "$($SourceService.serviceDetails.region)"
      healthCheckPath = "/health"
      pullRequestPreviewsEnabled = "$($SourceService.serviceDetails.pullRequestPreviewsEnabled)"
      previews = $SourceService.serviceDetails.previews
      envSpecificDetails = @{
        buildCommand = "$($SourceService.serviceDetails.envSpecificDetails.buildCommand)"
        startCommand = $StartCommand
      }
    }
  }
  Invoke-RestMethod -Method Patch -Uri "$apiBase/services/$ServiceId" -Headers $headers -Body ($patchPayload | ConvertTo-Json -Depth 8) | Out-Null
  Invoke-RestMethod -Method Put -Uri "$apiBase/services/$ServiceId/env-vars" -Headers $headers -Body ($EnvVars | ConvertTo-Json -Depth 6) | Out-Null
  Invoke-RestMethod -Method Post -Uri "$apiBase/services/$ServiceId/deploys" -Headers $headers -Body "{}" | Out-Null
}

function Get-LatestDeploy {
  param([Parameter(Mandatory = $true)][string]$ServiceId)

  $deploys = Invoke-RestMethod -Method Get -Uri "$apiBase/services/$ServiceId/deploys?limit=5" -Headers $headers
  return $deploys | ForEach-Object { $_.deploy } | Where-Object { $null -ne $_ } | Select-Object -First 1
}

function Wait-ServiceLive {
  param(
    [Parameter(Mandatory = $true)][string]$ServiceId,
    [string]$PreviousDeployId = ""
  )

  $deadline = (Get-Date).AddSeconds($MaxWaitSeconds)
  $deployId = ""
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

function Invoke-SplitSmoke {
  param(
    [Parameter(Mandatory = $true)][string]$BaseUrl,
    [Parameter(Mandatory = $true)][string]$ExpectedServiceName,
    [Parameter(Mandatory = $true)][string]$HtmlNeedle
  )

  $health = Invoke-RestMethod -Method Get -Uri "$BaseUrl/health" -TimeoutSec 30
  if ("$($health.status)" -ne "ok") {
    throw "Health check failed for $BaseUrl"
  }

  $info = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/service-info" -TimeoutSec 30
  if ("$($info.service)" -ne $ExpectedServiceName) {
    throw "Service info mismatch for $BaseUrl. Expected $ExpectedServiceName, got $($info.service)"
  }

  $html = Invoke-WebRequest -Method Get -Uri $BaseUrl -Headers @{ Accept = "text/html" } -UseBasicParsing -TimeoutSec 30
  if ($html.StatusCode -ne 200 -or -not $html.Content.Contains($HtmlNeedle)) {
    throw "HTML smoke failed for $BaseUrl"
  }
}

$sourceService = Get-RenderService -ServiceId $SourceServiceId
$sourceEnvVars = Get-AllEnvVars -ServiceId $SourceServiceId
if (-not $sourceEnvVars -or $sourceEnvVars.Count -eq 0) {
  throw "No environment variables could be read from source service $SourceServiceId."
}

$ownerId = "$($sourceService.ownerId)"
$targets = @()
if (-not [string]::IsNullOrWhiteSpace($CoreServiceName)) {
  $targets += @{
    Name = $CoreServiceName
    StartCommand = "uvicorn app.entrypoints.facility_core:app --host 0.0.0.0 --port `$PORT"
    HtmlNeedle = "시설 운영 코어"
    ExpectedServiceName = "ka-facility-core"
  }
}
if (-not [string]::IsNullOrWhiteSpace($AdminServiceName)) {
  $targets += @{
    Name = $AdminServiceName
    StartCommand = "uvicorn app.entrypoints.platform_admin:app --host 0.0.0.0 --port `$PORT"
    HtmlNeedle = "플랫폼 관리 허브"
    ExpectedServiceName = "ka-platform-admin"
  }
}

if ($targets.Count -lt 1) {
  throw "At least one split target service name must be provided."
}

foreach ($target in $targets) {
  $existing = Find-RenderServiceByName -OwnerId $ownerId -Name $target.Name
  $previousDeployId = ""
  if ($null -eq $existing) {
    $payload = New-WebServicePayload -SourceService $sourceService -Name $target.Name -StartCommand $target.StartCommand -EnvVars $sourceEnvVars
    $created = Invoke-RestMethod -Method Post -Uri "$apiBase/services" -Headers $headers -Body ($payload | ConvertTo-Json -Depth 8)
    $service = $created.service
    if ($null -eq $service) {
      throw "Create service response for $($target.Name) did not include service metadata."
    }
    Write-Output "SPLIT_SERVICE_CREATED name=$($target.Name) id=$($service.id)"
  } else {
    $previous = Get-LatestDeploy -ServiceId "$($existing.id)"
    if ($null -ne $previous) {
      $previousDeployId = "$($previous.id)"
    }
    Update-WebService -ServiceId "$($existing.id)" -SourceService $sourceService -StartCommand $target.StartCommand -EnvVars $sourceEnvVars
    $service = Get-RenderService -ServiceId "$($existing.id)"
    Write-Output "SPLIT_SERVICE_UPDATED name=$($target.Name) id=$($service.id)"
  }

  $deployId = Wait-ServiceLive -ServiceId "$($service.id)" -PreviousDeployId $previousDeployId
  $serviceInfo = Get-RenderService -ServiceId "$($service.id)"
  $baseUrl = "$($serviceInfo.serviceDetails.url)"
  Invoke-SplitSmoke -BaseUrl $baseUrl -ExpectedServiceName $target.ExpectedServiceName -HtmlNeedle $target.HtmlNeedle
  Write-Output "SPLIT_SERVICE_READY name=$($target.Name) id=$($service.id) deploy=$deployId url=$baseUrl"
}
