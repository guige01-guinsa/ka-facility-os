param(
  [Parameter(Mandatory = $true)]
  [string]$BaseUrl,
  [string]$AdminToken = "",
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
}

Write-Output "SMOKE_OK"
