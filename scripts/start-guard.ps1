$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$configPath = Join-Path $repoRoot "config\settings.json"
$pythonw = (Get-Command pythonw.exe).Source

if (-not (Test-Path $configPath)) {
    python -m prevent_visit.cli init-config --config $configPath | Out-Null
}

$config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
$proxyHost = [string]$config.proxy_host
$proxyPort = [int]$config.proxy_port
$listenPattern = "^\s*TCP\s+{0}\s+\S+\s+LISTENING\s+\d+\s*$" -f [regex]::Escape("$proxyHost`:$proxyPort")
$alreadyListening = @(netstat -ano -p TCP | Where-Object { $_ -match $listenPattern }).Count -gt 0

if ($alreadyListening) {
    Write-Host "Prevent Visit guard already appears to be listening on ${proxyHost}:$proxyPort. Skipping start."
    return
}

Start-Process -WindowStyle Hidden -FilePath $pythonw -ArgumentList "`"$repoRoot\run_guard.py`""
Write-Host "Prevent Visit guard started."
