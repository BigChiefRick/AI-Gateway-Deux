[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$')]
    [string]$Model,
    [string]$GatewayAddress = '192.0.2.10',
    [string]$SshUser = 'ubuntu',
    [string]$IdentityFile = (Join-Path ([Environment]::GetFolderPath('UserProfile')) '.ssh\id_ed25519')
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $IdentityFile -PathType Leaf)) {
    throw "SSH identity file was not found: $IdentityFile"
}

$apiKey = Get-Clipboard -Raw
if ([string]::IsNullOrWhiteSpace($apiKey)) {
    throw 'The Windows clipboard is empty.'
}
$apiKey = $apiKey.Trim()
if ($apiKey -notmatch '^sk-[A-Za-z0-9_-]{20,}$') {
    $apiKey = $null
    throw 'Clipboard text is not a validly shaped OpenAI API key.'
}

$target = "$SshUser@$GatewayAddress"
$quotedIdentity = '"' + $IdentityFile.Replace('"', '\"') + '"'
$remoteCommand = "cd /opt/ai-gateway/archestra && sudo python3 ./stage-company-openai.py --model $Model"
$startInfo = [System.Diagnostics.ProcessStartInfo]::new()
$startInfo.FileName = 'ssh'
$startInfo.Arguments = "-i $quotedIdentity -o BatchMode=yes -o ConnectTimeout=10 $target `"$remoteCommand`""
$startInfo.UseShellExecute = $false
$startInfo.RedirectStandardInput = $true
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError = $true
$startInfo.CreateNoWindow = $true

$process = [System.Diagnostics.Process]::new()
$process.StartInfo = $startInfo
try {
    [void]$process.Start()
    $process.StandardInput.Write($apiKey)
    $process.StandardInput.Close()
    $apiKey = $null
    Set-Clipboard -Value ''

    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw "Guarded OpenAI staging failed: $stderr"
    }
    Write-Output $stdout.Trim()
    Write-Host 'The clipboard was cleared. The guarded route is staged but not published to users.'
}
finally {
    $apiKey = $null
    if ($null -ne $process) {
        $process.Dispose()
    }
}
