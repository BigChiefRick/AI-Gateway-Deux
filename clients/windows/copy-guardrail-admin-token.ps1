[CmdletBinding()]
param(
    [string]$GatewayAddress = '192.0.2.10',
    [string]$SshUser = 'ubuntu',
    [string]$IdentityFile = (Join-Path ([Environment]::GetFolderPath('UserProfile')) '.ssh\id_ed25519')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $IdentityFile -PathType Leaf)) {
    throw "SSH identity file was not found: $IdentityFile"
}

$remoteCommand = "sudo sed -n 's/^DLP_ADMIN_API_KEY=//p' /opt/ai-gateway/archestra/.env | head -n 1"
$sshArguments = @(
    '-i', $IdentityFile,
    '-o', 'BatchMode=yes',
    '-o', 'ConnectTimeout=10',
    "$SshUser@$GatewayAddress",
    $remoteCommand
)

$tokenLines = & ssh @sshArguments
if ($LASTEXITCODE -ne 0) {
    throw "SSH failed with exit code $LASTEXITCODE. The clipboard was not changed."
}

$token = (($tokenLines | ForEach-Object { [string]$_ }) -join '').Trim()
if ([string]::IsNullOrWhiteSpace($token)) {
    throw 'The gateway returned an empty guardrail administrator token. The clipboard was not changed.'
}

Set-Clipboard -Value $token
$token = $null
$tokenLines = $null

Write-Host 'Guardrail administrator token copied to the Windows clipboard.'
Write-Host "Paste it into http://${GatewayAddress}:4200/admin, select Use recovery token, then clear the clipboard."
