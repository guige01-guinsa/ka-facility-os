param(
  [string]$DatabaseUrl = $env:DATABASE_URL,
  [string]$BackupDir = "data/backups",
  [int]$KeepCount = 10
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($DatabaseUrl)) {
  throw "DATABASE_URL is required."
}

New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")

if ($DatabaseUrl.StartsWith("sqlite:///")) {
  $sqlitePath = $DatabaseUrl.Substring("sqlite:///".Length)
  if (-not [System.IO.Path]::IsPathRooted($sqlitePath)) {
    $sqlitePath = Join-Path (Get-Location) $sqlitePath
  }
  if (-not (Test-Path $sqlitePath)) {
    throw "SQLite DB not found: $sqlitePath"
  }

  $backupFile = Join-Path $BackupDir "sqlite-backup-$timestamp.db"
  Copy-Item -Path $sqlitePath -Destination $backupFile -Force

  $rehydrateFile = Join-Path $BackupDir "sqlite-restore-check-$timestamp.db"
  Copy-Item -Path $backupFile -Destination $rehydrateFile -Force

  $hashOriginal = (Get-FileHash -Algorithm SHA256 -Path $sqlitePath).Hash
  $hashRestored = (Get-FileHash -Algorithm SHA256 -Path $rehydrateFile).Hash
  if ($hashOriginal -ne $hashRestored) {
    throw "Restore rehearsal failed: hash mismatch"
  }
  Remove-Item -Path $rehydrateFile -Force

  Get-ChildItem -Path $BackupDir -Filter "sqlite-backup-*.db" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -Skip $KeepCount |
    Remove-Item -Force

  Write-Output "BACKUP_RESTORE_REHEARSAL_OK sqlite $backupFile"
  exit 0
}

if ($DatabaseUrl.StartsWith("postgres://") -or $DatabaseUrl.StartsWith("postgresql://") -or $DatabaseUrl.StartsWith("postgresql+psycopg://")) {
  $pgDump = Get-Command pg_dump -ErrorAction SilentlyContinue
  $pgRestore = Get-Command pg_restore -ErrorAction SilentlyContinue
  if ($null -eq $pgDump -or $null -eq $pgRestore) {
    throw "pg_dump and pg_restore are required for PostgreSQL rehearsal."
  }

  $pgUrl = $DatabaseUrl.Replace("postgresql+psycopg://", "postgresql://")
  $backupFile = Join-Path $BackupDir "postgres-backup-$timestamp.dump"

  & $pgDump.Source --format=custom --file $backupFile $pgUrl
  if ($LASTEXITCODE -ne 0) {
    throw "pg_dump failed"
  }
  & $pgRestore.Source --list $backupFile | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "pg_restore --list failed"
  }

  Get-ChildItem -Path $BackupDir -Filter "postgres-backup-*.dump" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -Skip $KeepCount |
    Remove-Item -Force

  Write-Output "BACKUP_RESTORE_REHEARSAL_OK postgres $backupFile"
  exit 0
}

throw "Unsupported DATABASE_URL scheme: $DatabaseUrl"

