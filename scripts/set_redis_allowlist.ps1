param(
  [Parameter(Mandatory = $true)]
  [string]$RedisId,
  [Parameter(Mandatory = $true)]
  [string[]]$Cidrs,
  [string]$DescriptionPrefix = "allow",
  [string]$RenderApiKey = ""
)

$ErrorActionPreference = "Stop"

if ($RenderApiKey -eq "") {
  $RenderApiKey = $env:RENDER_API_KEY
}
if ($RenderApiKey -eq "") {
  throw "Render API key is required (param -RenderApiKey or env RENDER_API_KEY)."
}

$validCidrs = @()
foreach ($cidr in $Cidrs) {
  $trimmed = ($cidr | Out-String).Trim()
  if ($trimmed -ne "") {
    $validCidrs += $trimmed
  }
}
if ($validCidrs.Count -eq 0) {
  throw "At least one CIDR is required."
}

$allowList = @()
for ($i = 0; $i -lt $validCidrs.Count; $i++) {
  $allowList += @{
    cidrBlock = $validCidrs[$i]
    description = "$DescriptionPrefix-$($i + 1)"
  }
}

$apiBase = "https://api.render.com/v1"
$headers = @{
  Authorization = "Bearer $RenderApiKey"
  "Content-Type" = "application/json"
}

$payload = @{
  ipAllowList = $allowList
} | ConvertTo-Json -Depth 6 -Compress

Invoke-RestMethod -Method Patch -Uri "$apiBase/redis/$RedisId" -Headers $headers -Body $payload | Out-Null

$updated = Invoke-RestMethod -Method Get -Uri "$apiBase/redis/$RedisId" -Headers @{ Authorization = "Bearer $RenderApiKey" }
$cidrText = (($updated.ipAllowList | ForEach-Object { $_.cidrBlock }) -join ",")
Write-Output "REDIS_ALLOWLIST_UPDATED $RedisId $cidrText"

