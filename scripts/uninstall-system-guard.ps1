$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$configPath = Join-Path $repoRoot "config\settings.json"
$policyScript = Join-Path $repoRoot "build\remove-policies.ps1"
$rootCertPath = Join-Path $repoRoot "config\certs\root_ca_cert.cer"
$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$startMarker = "# >>> prevent-visit managed block start >>>"
$endMarker = "# <<< prevent-visit managed block end <<<"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this uninstaller in an elevated PowerShell window."
}

python -m prevent_visit.cli build-uninstall-script --config $configPath --output $policyScript
. $policyScript

if (Test-Path $rootCertPath) {
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($rootCertPath)
    Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $cert.Thumbprint } | Remove-Item
}

Get-NetFirewallRule -DisplayName "PreventVisit Browser * Block 80-443" -ErrorAction SilentlyContinue | Remove-NetFirewallRule

if (Test-Path $hostsFile) {
    $existingHosts = Get-Content -LiteralPath $hostsFile -Raw
    $pattern = [regex]::Escape($startMarker) + ".*?" + [regex]::Escape($endMarker)
    $cleanedHosts = [regex]::Replace($existingHosts, $pattern, "", [System.Text.RegularExpressions.RegexOptions]::Singleline).Trim()
    [System.IO.File]::WriteAllText(
        $hostsFile,
        $cleanedHosts,
        [System.Text.Encoding]::ASCII
    )
}

Unregister-ScheduledTask -TaskName "PreventVisitGuard" -Confirm:$false -ErrorAction SilentlyContinue
ipconfig /flushdns | Out-Null
Write-Host "Prevent Visit has been removed."
