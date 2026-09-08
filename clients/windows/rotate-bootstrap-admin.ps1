[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('ROTATE_BOOTSTRAP_ADMIN')]
    [string]$Confirm,
    [ValidatePattern('^[A-Za-z0-9.-]+$')]
    [string]$GatewayAddress = '192.0.2.10',
    [ValidatePattern('^[A-Za-z_][A-Za-z0-9_-]{0,31}$')]
    [string]$SshUser = 'ubuntu',
    [string]$IdentityFile = (Join-Path ([Environment]::GetFolderPath('UserProfile')) '.ssh\id_ed25519'),
    [string]$CurrentAdminPasswordSecretId = $env:AI_GATEWAY_ADMIN_PASSWORD_SECRET_ID,
    [string]$ReplacementAdminPasswordSecretId = $env:AI_GATEWAY_REPLACEMENT_ADMIN_PASSWORD_SECRET_ID,
    [string]$BwsPath = '',
    [switch]$PromptForCurrentPassword,
    [switch]$PromptForReplacementPassword
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ai-gateway-secrets.ps1')

if (-not (Test-Path -LiteralPath $IdentityFile -PathType Leaf)) {
    throw "SSH identity file was not found: $IdentityFile"
}

function Invoke-GatewaySshInput {
    param(
        [Parameter(Mandatory = $true)][string]$RemoteCommand,
        [Parameter(Mandatory = $true)][string]$InputText
    )

    $target = "$SshUser@$GatewayAddress"
    $quotedIdentity = '"' + $IdentityFile.Replace('"', '\"') + '"'
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = 'ssh'
    $startInfo.Arguments = "-i $quotedIdentity -o BatchMode=yes -o ConnectTimeout=10 $target `"$RemoteCommand`""
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.CreateNoWindow = $true
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        [void]$process.Start()
        $process.StandardInput.Write($InputText)
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            throw "Gateway credential command failed: $stderr"
        }
        return $stdout.Trim()
    }
    finally {
        $InputText = $null
        $process.Dispose()
    }
}

$currentPassword = $null
$newPassword = $null
$payload = $null
try {
    $currentPassword = Get-AiGatewaySecretValue `
        -SecretId $CurrentAdminPasswordSecretId `
        -Prompt 'Current AI Gateway administrator password' `
        -AllowPrompt:$PromptForCurrentPassword `
        -BwsPath $BwsPath
    $newPassword = Get-AiGatewaySecretValue `
        -SecretId $ReplacementAdminPasswordSecretId `
        -Prompt 'Replacement AI Gateway administrator password' `
        -AllowPrompt:$PromptForReplacementPassword `
        -BwsPath $BwsPath
    if ($currentPassword -ceq $newPassword) {
        throw 'The replacement administrator password must differ from the current password.'
    }

    $preflightCommand = 'cd /opt/ai-gateway/archestra && sudo python3 ./rotate-bootstrap-admin.py --preflight-only'
    Write-Output (Invoke-GatewaySshInput -RemoteCommand $preflightCommand -InputText $currentPassword)

    $payload = @{
        current_password = $currentPassword
        new_password = $newPassword
    } | ConvertTo-Json -Compress
    $remoteCommand = 'cd /opt/ai-gateway/archestra && sudo python3 ./rotate-bootstrap-admin.py --confirm ROTATE_BOOTSTRAP_ADMIN'
    Write-Output (Invoke-GatewaySshInput -RemoteCommand $remoteCommand -InputText $payload)
    Write-Host 'Administrator rotation completed. Promote the replacement Bitwarden secret ID to AI_GATEWAY_ADMIN_PASSWORD_SECRET_ID only after verification.'
}
finally {
    $payload = $null
    $newPassword = $null
    $currentPassword = $null
}
