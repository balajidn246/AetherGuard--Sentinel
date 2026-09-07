# AetherGuard--Sentinel real telemetry -> ingestion -> API/live-log verification
# Run on the SAME Windows machine that runs the backend and ClickHouse.

$ErrorActionPreference = 'Continue'
$ApiBase = 'http://127.0.0.1:8000'
$Frontend = 'http://127.0.0.1:5173'
$ClickHouse = 'http://127.0.0.1:8123'
$Username = 'admin'
$Password = 'aetherguard2024'
$Marker = "AG-E2E-$([guid]::NewGuid().ToString('N').Substring(0,12))"

function Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Pass($msg) { Write-Host "PASS: $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "FAIL: $msg" -ForegroundColor Red }
function Warn($msg) { Write-Host "WARN: $msg" -ForegroundColor Yellow }

Step '1. Backend health'
try {
  $h = Invoke-RestMethod -Uri "$ApiBase/api/health" -Method Get -TimeoutSec 10
  $h | ConvertTo-Json -Depth 8
  Pass 'Backend health endpoint responded.'
} catch {
  Fail "Backend health failed: $($_.Exception.Message)"
  exit 1
}

Step '2. Login / obtain bearer token'
$token = $null
$loginUris = @("$ApiBase/api/auth/login", "$ApiBase/api/auth/token")
foreach ($uri in $loginUris) {
  if ($token) { break }
  try {
    $body = @{ username = $Username; password = $Password } | ConvertTo-Json
    $r = Invoke-RestMethod -Uri $uri -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 10
    $token = $r.access_token
    if ($token) { Pass "Authenticated through $uri" }
  } catch { }
}
if (-not $token) {
  Warn 'Could not obtain a bearer token. The test will continue and report whether the log API is public or uses another auth mechanism.'
}
$headers = @{}
if ($token) { $headers['Authorization'] = "Bearer $token" }

Step '3. Capture current live logs'
$before = @()
try {
  $before = @(Invoke-RestMethod -Uri "$ApiBase/api/logs/live?limit=50" -Headers $headers -Method Get -TimeoutSec 10)
  Pass "Live log endpoint responded with $($before.Count) records."
} catch {
  Fail "GET /api/logs/live failed: $($_.Exception.Message)"
}

Step '4. Send a unique REAL syslog event to TCP :5514'
$tcpMessage = "<134>$(Get-Date -Format 'MMM dd HH:mm:ss') aetherguard-e2e AetherGuardTest[4242]: $Marker source=aetherguard-e2e event_type=authentication action=login result=failure username=e2e-test src_ip=198.51.100.42"
$tcpSent = $false
try {
  $client = [System.Net.Sockets.TcpClient]::new()
  $client.ReceiveTimeout = 3000
  $client.SendTimeout = 3000
  $client.Connect('127.0.0.1', 5514)
  $stream = $client.GetStream()
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($tcpMessage + "`n")
  $stream.Write($bytes, 0, $bytes.Length)
  $stream.Flush()
  $stream.Dispose(); $client.Dispose()
  $tcpSent = $true
  Pass 'TCP syslog message sent to 127.0.0.1:5514.'
} catch { Warn "TCP :5514 send failed: $($_.Exception.Message)" }

Step '5. Send a unique REAL syslog event to UDP :5514'
$udpMessage = "<134>$(Get-Date -Format 'MMM dd HH:mm:ss') aetherguard-e2e AetherGuardTest[4243]: $Marker source=aetherguard-e2e event_type=authentication action=login result=failure username=e2e-test src_ip=198.51.100.43"
$udpSent = $false
try {
  $udp = [System.Net.Sockets.UdpClient]::new()
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($udpMessage)
  [void]$udp.Send($bytes, $bytes.Length, '127.0.0.1', 5514)
  $udp.Dispose()
  $udpSent = $true
  Pass 'UDP syslog message sent to 127.0.0.1:5514.'
} catch { Warn "UDP :5514 send failed: $($_.Exception.Message)" }

if (-not $tcpSent -and -not $udpSent) {
  Fail 'Could not send either TCP or UDP test event. Verify which protocol the :5514 listener uses.'
  exit 1
}

Step '6. Poll AetherGuard live logs for the unique marker'
$found = $false
$foundRecord = $null
for ($i=1; $i -le 30; $i++) {
  try {
    $rows = @(Invoke-RestMethod -Uri "$ApiBase/api/logs/search?q=$Marker&limit=20" -Headers $headers -Method Get -TimeoutSec 10)
    $candidate = $rows
    if ($rows.logs) { $candidate = @($rows.logs) }
    foreach ($row in $candidate) {
      $json = $row | ConvertTo-Json -Compress -Depth 10
      if ($json -like "*$Marker*") { $found = $true; $foundRecord = $row; break }
    }
    if ($found) { break }
  } catch {
    # Some builds may not expose /search; fall back to /live.
    try {
      $rows = @(Invoke-RestMethod -Uri "$ApiBase/api/logs/live?limit=200" -Headers $headers -Method Get -TimeoutSec 10)
      foreach ($row in $rows) {
        $json = $row | ConvertTo-Json -Compress -Depth 10
        if ($json -like "*$Marker*") { $found = $true; $foundRecord = $row; break }
      }
      if ($found) { break }
    } catch { }
  }
  Write-Host "poll $i/30 - marker not visible yet"
  Start-Sleep -Seconds 1
}
if ($found) {
  Pass "AetherGuard API returned the real event containing marker $Marker"
  $foundRecord | ConvertTo-Json -Depth 12
} else {
  Fail "Marker $Marker was not returned by the live/search API after 30 seconds."
  Warn 'This means the break is somewhere between listener -> ingestion -> normalization -> ClickHouse -> log API, OR the endpoint uses a different storage/query path.'
}

Step '7. Check ClickHouse HTTP service'
try {
  $ping = Invoke-WebRequest -Uri "$ClickHouse/ping" -Method Get -TimeoutSec 5
  if ($ping.StatusCode -eq 200) { Pass 'ClickHouse HTTP endpoint is reachable on :8123.' }
} catch { Warn "ClickHouse :8123 not reachable from Windows: $($_.Exception.Message)" }

Step '8. Inspect likely ClickHouse event tables'
try {
  $sql = "SELECT name FROM system.tables WHERE database NOT IN ('system','INFORMATION_SCHEMA','information_schema') AND (lower(name) LIKE '%log%' OR lower(name) LIKE '%event%' OR lower(name) LIKE '%signal%') ORDER BY database, name FORMAT JSONEachRow"
  $resp = Invoke-RestMethod -Uri $ClickHouse -Method Post -Body $sql -ContentType 'text/plain' -TimeoutSec 10
  if ($resp) { $resp }
  else { Warn 'No candidate log/event/signal tables were returned.' }
} catch { Warn "Could not inspect ClickHouse tables: $($_.Exception.Message)" }

Step '9. Result'
if ($found) {
  Pass 'REAL TELEMETRY -> :5514 -> AetherGuard ingestion/query path is working for the test event.'
  Write-Host "Open $Frontend and go to Log Explorer. Search for: $Marker" -ForegroundColor White
} else {
  Fail 'REAL-TELEMETRY PATH IS NOT YET PROVEN END-TO-END.'
  Write-Host "Keep this marker: $Marker" -ForegroundColor White
  Write-Host 'Send the complete output of this script back so the exact failing stage can be fixed.' -ForegroundColor White
}
