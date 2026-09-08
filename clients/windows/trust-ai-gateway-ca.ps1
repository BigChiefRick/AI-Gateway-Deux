[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9.-]+$')]
    [string]$GatewayAddress = '192.0.2.10',
    [ValidatePattern('^[A-Za-z_][A-Za-z0-9_-]{0,31}$')]
    [string]$SshUser = 'ubuntu',
    [string]$IdentityFile = (Join-Path ([Environment]::GetFolderPath('UserProfile')) '.ssh\id_ed25519')
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $IdentityFile -PathType Leaf)) {
    throw "SSH identity file was not found: $IdentityFile"
}

$temporary = Join-Path ([IO.Path]::GetTempPath()) ("ai-gateway-ca-{0}.crt" -f [guid]::NewGuid().ToString('N'))
$target = "$SshUser@$GatewayAddress"
$quotedIdentity = '"' + $IdentityFile.Replace('"', '\"') + '"'
$startInfo = [System.Diagnostics.ProcessStartInfo]::new()
$startInfo.FileName = 'ssh'
$startInfo.Arguments = "-i $quotedIdentity -o BatchMode=yes -o ConnectTimeout=10 $target `"sudo docker exec ai-gateway-https cat /data/caddy/pki/authorities/local/root.crt`""
$startInfo.UseShellExecute = $false
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError = $true
$startInfo.CreateNoWindow = $true
$process = [System.Diagnostics.Process]::new()
$process.StartInfo = $startInfo
try {
    [void]$process.Start()
    $certificate = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw "Unable to retrieve the AI Gateway public CA certificate: $stderr"
    }
    if ($certificate -notmatch '-----BEGIN CERTIFICATE-----') {
        throw 'The gateway returned an invalid CA certificate.'
    }
    [IO.File]::WriteAllText($temporary, $certificate, [Text.UTF8Encoding]::new($false))
    Import-Certificate -FilePath $temporary -CertStoreLocation 'Cert:\CurrentUser\Root' | Out-Null
    $response = Invoke-WebRequest -UseBasicParsing -Uri "https://$GatewayAddress/health" -TimeoutSec 20
    if ($response.StatusCode -ne 200) {
        throw "HTTPS verification returned HTTP $($response.StatusCode)."
    }
    Write-Output "Trusted the AI Gateway CA for the current Windows user and verified https://$GatewayAddress."
}
finally {
    $process.Dispose()
    Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
}
