[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('RECOVER_GATEWAY_ADMIN')]
    [string]$Confirm,
    [ValidatePattern('^[A-Za-z0-9.-]+$')]
    [string]$GatewayAddress = '192.0.2.10',
    [ValidatePattern('^[A-Za-z_][A-Za-z0-9_-]{0,31}$')]
    [string]$SshUser = 'ubuntu',
    [string]$IdentityFile = (Join-Path ([Environment]::GetFolderPath('UserProfile')) '.ssh\id_ed25519'),
    [string]$AdminPasswordSecretId = $env:AI_GATEWAY_ADMIN_PASSWORD_SECRET_ID,
    [string]$BwsPath = '',
    [switch]$PromptForAdminPassword
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ai-gateway-secrets.ps1')

if (-not (Test-Path -LiteralPath $IdentityFile -PathType Leaf)) {
    throw "SSH identity file was not found: $IdentityFile"
}

$password = $null
$process = $null
try {
    $password = Get-AiGatewaySecretValue `
        -SecretId $AdminPasswordSecretId `
        -Prompt 'Trusted AI Gateway administrator recovery password' `
        -AllowPrompt:$PromptForAdminPassword `
        -BwsPath $BwsPath

    $target = "$SshUser@$GatewayAddress"
    $quotedIdentity = '"' + $IdentityFile.Replace('"', '\"') + '"'
    $remote = 'cd /opt/ai-gateway/archestra && sudo python3 ./recover-admin-password.py --confirm RECOVER_GATEWAY_ADMIN'
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
    $process.StandardInput.Write($password)
    $process.StandardInput.Close()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw "Gateway administrator recovery failed: $stderr"
    }
    Write-Output $stdout.Trim()
}
finally {
    $password = $null
    if ($process) {
        $process.Dispose()
    }
}
