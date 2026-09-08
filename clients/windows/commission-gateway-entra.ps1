[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$TenantId,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9.-]+$')]
    [string]$Domain,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$ClientId,
    [string]$Confirmation = '',
    [ValidatePattern('^[A-Za-z0-9.-]+$')]
    [string]$GatewayAddress = '192.0.2.10',
    [ValidatePattern('^[A-Za-z_][A-Za-z0-9_-]{0,31}$')]
    [string]$SshUser = 'ubuntu',
    [string]$IdentityFile = (Join-Path ([Environment]::GetFolderPath('UserProfile')) '.ssh\id_ed25519'),
    [string]$AdminPasswordSecretId = $env:AI_GATEWAY_ADMIN_PASSWORD_SECRET_ID,
    [string]$EntraClientSecretSecretId = $env:AI_GATEWAY_ENTRA_CLIENT_SECRET_ID,
    [string]$BwsPath = '',
    [switch]$PromptForAdminPassword,
    [switch]$PromptForEntraClientSecret
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ai-gateway-secrets.ps1')
if ($Confirmation -ne 'CONFIGURE_GATEWAY_ENTRA') {
    throw 'Commissioning requires -Confirmation CONFIGURE_GATEWAY_ENTRA.'
}
if (-not (Test-Path -LiteralPath $IdentityFile -PathType Leaf)) {
    throw "SSH identity file was not found: $IdentityFile"
}

$adminPassword = $null
$clientSecret = $null
$payload = $null
$process = $null
try {
    $adminPassword = Get-AiGatewaySecretValue -SecretId $AdminPasswordSecretId `
        -Prompt 'Rotated AI Gateway administrator password' `
        -AllowPrompt:$PromptForAdminPassword -BwsPath $BwsPath
    $clientSecret = Get-AiGatewaySecretValue -SecretId $EntraClientSecretSecretId `
        -Prompt 'gateway Entra OIDC client secret' `
        -AllowPrompt:$PromptForEntraClientSecret -BwsPath $BwsPath
    $payload = @{
        admin_password = $adminPassword
        client_secret = $clientSecret
    } | ConvertTo-Json -Compress
    $target = "$SshUser@$GatewayAddress"
    $quotedIdentity = '"' + $IdentityFile.Replace('"', '\"') + '"'
    $remote = "cd /opt/ai-gateway/archestra && sudo python3 ./configure-gateway-entra.py --tenant-id $TenantId --domain $Domain --client-id $ClientId --confirmation CONFIGURE_GATEWAY_ENTRA"
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = 'ssh'
    $startInfo.Arguments = "-i $quotedIdentity -o BatchMode=yes -o ConnectTimeout=10 $target `"$remote`""
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.CreateNoWindow = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    [void]$process.Start()
    $process.StandardInput.Write($payload)
    $process.StandardInput.Close()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw "Entra SSO commissioning failed: $stderr"
    }
    Write-Output $stdout.Trim()
}
finally {
    $adminPassword = $null
    $clientSecret = $null
    $payload = $null
    if ($process) {
        $process.Dispose()
    }
}
