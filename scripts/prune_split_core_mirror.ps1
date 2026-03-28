param(
  [string]$PrimaryServiceId = "",
  [string]$MirrorServiceName = "ka-facility-core",
  [string]$RenderApiKey = ""
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

$primaryService = Get-RenderService -ServiceId $PrimaryServiceId
$ownerId = "$($primaryService.ownerId)"
$services = Get-RenderServicesByOwner -OwnerId $ownerId | ForEach-Object { $_.service } | Where-Object { $null -ne $_ }
$mirrorService = $services | Where-Object { "$($_.name)" -eq $MirrorServiceName } | Select-Object -First 1

if ($null -eq $mirrorService) {
  Write-Output "MIRROR_NOT_FOUND name=$MirrorServiceName"
  exit 0
}

if ("$($mirrorService.id)" -eq "$PrimaryServiceId") {
  throw "Mirror service id matches the primary service id. Refusing to delete."
}
if ("$($mirrorService.type)" -ne "web_service") {
  throw "Mirror target '$MirrorServiceName' is not a web service."
}

Invoke-RestMethod -Method Delete -Uri "$apiBase/services/$($mirrorService.id)" -Headers $headers | Out-Null
Write-Output "MIRROR_DELETED name=$($mirrorService.name) id=$($mirrorService.id)"
