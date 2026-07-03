$ErrorActionPreference = 'Stop'
Get-NetFirewallRule -DisplayName 'PreventVisit Browser * Block 80-443' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
