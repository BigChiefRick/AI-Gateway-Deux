$ErrorActionPreference = 'Stop'
$helper = Join-Path $PSScriptRoot 'ai-gateway-secrets.ps1'
. $helper

$expectedInstall = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.local\bin\bws.exe'
if ((Test-Path -LiteralPath $expectedInstall) -and (Resolve-BwsExecutable) -ne $expectedInstall) {
    throw 'Resolve-BwsExecutable did not select the installed user-scoped CLI.'
}

$missingReference = $false
try {
    Get-AiGatewaySecretValue -Prompt 'test secret' | Out-Null
}
catch {
    $missingReference = $_.Exception.Message -like 'No Bitwarden secret ID was supplied*'
}
if (-not $missingReference) {
    throw 'Get-AiGatewaySecretValue did not fail closed without a secret ID or prompt authorization.'
}

Write-Output 'AI_GATEWAY_BITWARDEN_HELPER_TEST_OK'
