$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$configPath = Join-Path $repoRoot "config\settings.json"
$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$generatedHosts = Join-Path $repoRoot "build\hosts.generated"
$pacFile = Join-Path $repoRoot "build\prevent-visit.pac"
$policyScript = Join-Path $repoRoot "build\apply-policies.ps1"
$firewallScript = Join-Path $repoRoot "build\apply-firewall-rules.ps1"
$taskScript = Join-Path $repoRoot "build\register-task.ps1"
$rootCertPath = Join-Path $repoRoot "config\certs\root_ca_cert.cer"

function Test-LocalTcpPort {
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName,
        [Parameter(Mandatory = $true)]
        [int]$Port
    )

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(1500, $false)) {
            return $false
        }
        $client.EndConnect($async) | Out-Null
        return $true
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this installer in an elevated PowerShell window."
}

python -m prevent_visit.cli init-config --config $configPath
python -m prevent_visit.cli generate-ca --config $configPath
python -m prevent_visit.cli build-hosts --config $configPath --output $generatedHosts
python -m prevent_visit.cli build-pac --config $configPath --output $pacFile
python -m prevent_visit.cli build-registry-script --config $configPath --output $policyScript
python -m prevent_visit.cli build-firewall-script --config $configPath --output $firewallScript
python -m prevent_visit.cli build-startup-task --repo-root $repoRoot --output $taskScript

. (Join-Path $repoRoot "scripts\start-guard.ps1")
$config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
if (-not (Test-LocalTcpPort -HostName ([string]$config.proxy_host) -Port ([int]$config.proxy_port))) {
    throw "Prevent Visit guard did not start cleanly on $($config.proxy_host):$($config.proxy_port). Browser proxy settings were not applied."
}

. $policyScript
. $firewallScript
. $taskScript
if (-not (Test-Path $rootCertPath)) {
    throw "Root certificate file not found at $rootCertPath"
}
Import-Certificate -FilePath $rootCertPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null

$managedText = Get-Content -LiteralPath $generatedHosts -Raw
$existingHosts = if (Test-Path $hostsFile) { [string](Get-Content -LiteralPath $hostsFile -Raw) } else { "" }
if ($null -eq $existingHosts) {
    $existingHosts = ""
}
$startMarker = "# >>> prevent-visit managed block start >>>"
$endMarker = "# <<< prevent-visit managed block end <<<"
$pattern = [regex]::Escape($startMarker) + ".*?" + [regex]::Escape($endMarker)
$cleanedHosts = [regex]::Replace($existingHosts, $pattern, "", [System.Text.RegularExpressions.RegexOptions]::Singleline).TrimEnd()
$finalHosts = ($cleanedHosts, "", $managedText.Trim()) -join "`r`n"
[System.IO.File]::WriteAllText(
    $hostsFile,
    $finalHosts,
    [System.Text.Encoding]::ASCII
)

ipconfig /flushdns | Out-Null
Write-Host "Prevent Visit has been installed."
Write-Host "The blocker service was started and will auto-start at login."
