[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('INITIALIZE_BITWARDEN_MACHINE_TOKEN')]
    [string]$Confirm
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ai-gateway-secrets.ps1')

$credentialHelper = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.codex\bin\bws_credential.py'
$launcher = Get-BwsCodexLauncher
if (-not (Test-Path -LiteralPath $credentialHelper -PathType Leaf)) {
    throw "The global Codex Bitwarden credential helper was not found: $credentialHelper"
}
$python = Get-Command python -ErrorAction Stop
& $python.Source $credentialHelper set-from-clipboard
if ($LASTEXITCODE -ne 0) {
    throw 'The Bitwarden machine-account token was not stored in Windows Credential Manager.'
}
& $python.Source $launcher project list --output none --color no
if ($LASTEXITCODE -ne 0) {
    throw 'Bitwarden rejected the stored machine-account token or the account cannot list its assigned projects.'
}
Write-Output 'PASS: scoped Bitwarden machine-account token verified in Windows Credential Manager; clipboard cleared.'
