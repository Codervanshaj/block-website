$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$configPath = Join-Path $repoRoot "config\settings.json"

python -m prevent_visit.cli check-status --config $configPath
