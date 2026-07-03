$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$configPath = Join-Path $repoRoot "config\settings.json"

if (-not (Test-Path $configPath)) {
    Write-Host "Prevent Visit config was not found. Nothing to stop."
    return
}

$config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
$proxyHost = [string]$config.proxy_host
$proxyPort = [int]$config.proxy_port
$listenPattern = "^\s*TCP\s+{0}\s+\S+\s+LISTENING\s+(\d+)\s*$" -f [regex]::Escape("$proxyHost`:$proxyPort")
$listenerPids = @(
    netstat -ano -p TCP |
        ForEach-Object {
            if ($_ -match $listenPattern) {
                [int]$matches[1]
            }
        } |
        Select-Object -Unique
)

foreach ($listenerPid in $listenerPids) {
    Stop-Process -Id $listenerPid -Force -ErrorAction SilentlyContinue
}

if ($listenerPids.Count -eq 0) {
    Write-Host "Prevent Visit guard was not listening."
} else {
    Write-Host "Prevent Visit guard stopped."
}
