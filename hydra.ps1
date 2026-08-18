<#
.SYNOPSIS
  Drive the local HydraDB node for the blast-radius project.

.DESCRIPTION
  The node runs as container `hydradb` against the named volume `hydradb-data`.
  A named volume rather than a bind mount is deliberate: the image runs as UID
  10001, and a Windows bind mount cannot express that ownership, so a bind
  mount fails on the first storage write. The volume is seeded once by a
  throwaway container that creates the store/cache directories and the auth
  token, then chowns them to 10001.

  Run this from PowerShell, never Git Bash. Git Bash rewrites container-side
  absolute paths -- `/data/store` arrives as `C:/Program Files/Git/data/store`
  and the node dies with a bare PermissionDenied that names no path.

.EXAMPLE
  .\hydra.ps1 up
  .\hydra.ps1 q "MATCH (s:Service) RETURN s.name AS name"
  .\hydra.ps1 status
#>
[CmdletBinding()]
param(
  [Parameter(Position = 0)]
  [ValidateSet('up', 'down', 'restart', 'status', 'logs', 'q', 'raw', 'reset', 'wipe')]
  [string]$Command = 'status',

  [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
  [string[]]$Args,

  [string]$Params,
  [string]$File,
  [ValidateSet('causal', 'strong')]
  [string]$Consistency = 'causal'
)

$ErrorActionPreference = 'Stop'

$Image     = 'ghcr.io/hydra-db/hydradb:latest'
$Container = 'hydradb'
$Volume    = 'hydradb-data'
$Token     = 'local-development-token-32-bytes'
$HttpAddr  = 'http://127.0.0.1:8443'
$AdminAddr = 'http://127.0.0.1:9090'
$Graph     = 'default'
$Cell      = 'cell-0'

$Labels = @('Service', 'PackageVersion', 'File', 'Function', 'ExternalImport', 'Route', 'PersistenceArtifact')

function Test-Daemon {
  docker version --format '{{.Server.Version}}' 2>$null | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "Docker daemon is not reachable. Start Docker Desktop and try again."
  }
}

function Initialize-Volume {
  $existing = docker volume ls --quiet --filter "name=^$Volume$"
  if (-not $existing) {
    Write-Host "creating volume $Volume" -ForegroundColor Cyan
    docker volume create $Volume | Out-Null
  }
  # Seed the store, cache and token, owned by the image's UID. Idempotent.
  docker run --rm -v "${Volume}:/data" --entrypoint /bin/sh $Image -c `
    "mkdir -p /data/store /data/cache && printf '%s\n' '$Token' > /data/auth-token && chown -R 10001:10001 /data" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "failed to seed volume $Volume" }
}

function Start-Node {
  Test-Daemon
  $running = docker ps --quiet --filter "name=^$Container$"
  if ($running) { Write-Host "$Container already running" -ForegroundColor Green; return }

  docker rm -f $Container 2>$null | Out-Null
  Initialize-Volume

  Write-Host "starting $Container" -ForegroundColor Cyan
  docker run -d --name $Container `
    -p 7687:7687 -p 8443:8443 -p 9090:9090 `
    -v "${Volume}:/data" `
    -e CLOUD_PROVIDER=local `
    -e LOCAL_PATH=/data/store `
    -e GRAPH_NAMESPACE=default `
    -e GRAPH_ID=default `
    -e GRAPH_CELL_ID=cell-0 `
    -e GRAPH_CELLS=cell-0 `
    -e GRAPH_NODE_ID=node-0 `
    -e GRAPH_BOLT_NODE_ADDRESSES=node-0=127.0.0.1:7687 `
    -e GRAPH_ADVERTISED_BOLT_ADDR=127.0.0.1:7687 `
    -e GRAPH_DATA_CACHE_DIR=/data/cache `
    -e GRAPH_AUTH_TOKEN_FILE=/data/auth-token `
    -e GRAPH_ALLOW_PLAINTEXT=true `
    -e RUST_MIN_STACK=33554432 `
    $Image | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "docker run failed" }

  Write-Host -NoNewline "waiting for readiness"
  foreach ($attempt in 1..60) {
    Start-Sleep -Milliseconds 1000
    try {
      $r = Invoke-WebRequest -Uri "$AdminAddr/readyz" -TimeoutSec 2 -UseBasicParsing
      if ($r.StatusCode -eq 200) { Write-Host " ready" -ForegroundColor Green; return }
    } catch { Write-Host -NoNewline "." }
  }
  Write-Host ""
  docker logs --tail 40 $Container
  throw "node did not become ready in 60s (logs above)"
}

function Invoke-Hydra {
  param([string]$Statement, [string]$JsonParams, [switch]$Raw)

  $body = @{ cell_id = $Cell; query = $Statement; timeout_ms = 60000 }
  if ($JsonParams) { $body.parameters = ($JsonParams | ConvertFrom-Json) }
  if ($Consistency -ne 'causal') { $body.consistency = $Consistency }

  $headers = @{
    Authorization        = "Bearer $Token"
    'X-Graph-Namespace'  = 'default'
  }
  $response = Invoke-RestMethod -Uri "$HttpAddr/v1/graphs/$Graph/query" -Method Post `
    -Headers $headers -ContentType 'application/json' `
    -Body ($body | ConvertTo-Json -Depth 20 -Compress)

  if ($Raw) { return ($response | ConvertTo-Json -Depth 20) }

  # Flatten typed cells ({type,value}) into a plain table.
  $columns = $response.columns
  $rows = foreach ($row in $response.rows) {
    $out = [ordered]@{}
    for ($i = 0; $i -lt $columns.Count; $i++) {
      $cell = $row[$i]
      $out[$columns[$i]] = if ($null -ne $cell -and $cell.PSObject.Properties.Name -contains 'value') { $cell.value } else { $cell }
    }
    [pscustomobject]$out
  }
  return $rows
}

switch ($Command) {
  'up' { Start-Node }

  'down' {
    Test-Daemon
    docker rm -f $Container 2>$null | Out-Null
    Write-Host "$Container stopped (volume $Volume kept)" -ForegroundColor Yellow
  }

  'restart' {
    Test-Daemon
    docker rm -f $Container 2>$null | Out-Null
    Start-Node
  }

  'logs' { Test-Daemon; docker logs -f $Container }

  'status' {
    Test-Daemon
    $state = docker ps -a --filter "name=^$Container$" --format '{{.Status}}'
    if (-not $state) { Write-Host "$Container does not exist. Run: .\hydra.ps1 up" -ForegroundColor Yellow; break }
    Write-Host "container: $state"
    try {
      $ready = Invoke-WebRequest -Uri "$AdminAddr/readyz" -TimeoutSec 3 -UseBasicParsing
      Write-Host "readyz:    $($ready.StatusCode)" -ForegroundColor Green
    } catch { Write-Host "readyz:    unreachable" -ForegroundColor Red; break }

    Write-Host "`nnode counts:"
    foreach ($label in $Labels) {
      $n = (Invoke-Hydra -Statement "MATCH (n:$label) RETURN count(*) AS n").n
      '{0,-22} {1,8}' -f $label, $n | Write-Host
    }
  }

  'q' {
    $statement = if ($File) { Get-Content -Raw $File } else { $Args -join ' ' }
    if (-not $statement) { throw "no statement. Usage: .\hydra.ps1 q ""MATCH (n:Service) RETURN n.name AS name""" }
    Invoke-Hydra -Statement $statement -JsonParams $Params | Format-Table -AutoSize
  }

  'raw' {
    $statement = if ($File) { Get-Content -Raw $File } else { $Args -join ' ' }
    Invoke-Hydra -Statement $statement -JsonParams $Params -Raw
  }

  'reset' {
    # Delete every node this project creates. Relationships go with them via
    # DETACH DELETE, so the edge blocks need no separate pass.
    foreach ($label in $Labels) {
      Invoke-Hydra -Statement "MATCH (n:$label) DETACH DELETE n" | Out-Null
      Write-Host "cleared $label"
    }
    Write-Host "`nGraph cleared. Delete data\ids.sqlite too, or re-ingest will" -ForegroundColor Yellow
    Write-Host "reuse the old ids against an empty graph." -ForegroundColor Yellow
  }

  'wipe' {
    Test-Daemon
    docker rm -f $Container 2>$null | Out-Null
    docker volume rm $Volume 2>$null | Out-Null
    if (Test-Path 'data\ids.sqlite') { Remove-Item 'data\ids.sqlite*' -Force }
    Write-Host "container, volume and id map destroyed" -ForegroundColor Red
  }
}
