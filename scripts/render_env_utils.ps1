function Resolve-RenderServiceId {
  param([string]$ServiceId = "")

  if (-not [string]::IsNullOrWhiteSpace($ServiceId)) {
    return $ServiceId
  }
  if (-not [string]::IsNullOrWhiteSpace($env:RENDER_SERVICE_ID)) {
    return $env:RENDER_SERVICE_ID
  }
  $userValue = [Environment]::GetEnvironmentVariable("RENDER_SERVICE_ID", "User")
  if (-not [string]::IsNullOrWhiteSpace($userValue)) {
    return $userValue
  }
  return ""
}

function Get-RenderEnvVarValue {
  param(
    [Parameter(Mandatory = $true)][string]$ServiceId,
    [Parameter(Mandatory = $true)][string]$Key,
    [string]$RenderApiKey = "",
    [int]$PageSize = 20,
    [int]$MaxPages = 50
  )

  if ([string]::IsNullOrWhiteSpace($RenderApiKey)) {
    $RenderApiKey = $env:RENDER_API_KEY
  }
  if ([string]::IsNullOrWhiteSpace($RenderApiKey)) {
    return ""
  }

  $normalizedPageSize = [Math]::Max(1, [Math]::Min($PageSize, 100))
  $headers = @{ Authorization = "Bearer $RenderApiKey" }
  $cursor = $null

  for ($page = 0; $page -lt $MaxPages; $page++) {
    $uri = "https://api.render.com/v1/services/$ServiceId/env-vars?limit=$normalizedPageSize"
    if ($cursor) {
      $uri += "&cursor=$cursor"
    }

    try {
      $items = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    } catch {
      return ""
    }
    if (-not $items) {
      break
    }

    $nextCursor = $null
    foreach ($item in $items) {
      $envVar = $item.envVar
      if ($null -eq $envVar) {
        continue
      }
      $candidateKey = ""
      if ($envVar.PSObject.Properties.Name -contains "key") {
        $candidateKey = "$($envVar.key)"
      } elseif ($envVar.PSObject.Properties.Name -contains "name") {
        $candidateKey = "$($envVar.name)"
      }
      if ($candidateKey -eq $Key) {
        return "$($envVar.value)"
      }
      $nextCursor = "$($item.cursor)"
    }

    if ($items.Count -lt $normalizedPageSize) {
      break
    }
    if (-not $nextCursor) {
      break
    }
    $cursor = $nextCursor
  }

  return ""
}

function Resolve-RenderAdminToken {
  param(
    [string]$AdminToken = "",
    [string]$ServiceId = "",
    [string]$RenderApiKey = "",
    [string]$EnvKey = "ADMIN_TOKEN"
  )

  if (-not [string]::IsNullOrWhiteSpace($AdminToken)) {
    return $AdminToken
  }
  if (-not [string]::IsNullOrWhiteSpace($env:ADMIN_TOKEN)) {
    return $env:ADMIN_TOKEN
  }
  $userToken = [Environment]::GetEnvironmentVariable("ADMIN_TOKEN", "User")
  if (-not [string]::IsNullOrWhiteSpace($userToken)) {
    return $userToken
  }

  $resolvedServiceId = Resolve-RenderServiceId -ServiceId $ServiceId
  if ([string]::IsNullOrWhiteSpace($resolvedServiceId)) {
    return ""
  }

  $resolvedToken = Get-RenderEnvVarValue -ServiceId $resolvedServiceId -Key $EnvKey -RenderApiKey $RenderApiKey
  return $resolvedToken
}
