[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$')]
    [string]$Model,
    [Parameter(Mandatory = $true)]
    [ValidateRange(0.01, 1000000)]
    [decimal]$MonthlyExternalBudgetDollars,
    [Parameter(Mandatory = $true)]
    [ValidateRange(0.000001, 1000000)]
    [decimal]$InputPricePerMillionDollars,
    [Parameter(Mandatory = $true)]
    [ValidateRange(0.000001, 1000000)]
    [decimal]$OutputPricePerMillionDollars,
    [Parameter(Mandatory = $true)]
    [ValidateSet('COMMISSION_COMPANY_OPENAI')]
    [string]$Confirm,
    [ValidatePattern('^[A-Za-z0-9.-]+$')]
    [string]$GatewayAddress = '192.0.2.10',
    [ValidatePattern('^[A-Za-z_][A-Za-z0-9_-]{0,31}$')]
    [string]$SshUser = 'ubuntu',
    [string]$IdentityFile = (Join-Path ([Environment]::GetFolderPath('UserProfile')) '.ssh\id_ed25519'),
    [string]$AdminPasswordSecretId = $env:AI_GATEWAY_ADMIN_PASSWORD_SECRET_ID,
    [string]$OpenAiApiKeySecretId = $env:AI_GATEWAY_OPENAI_API_KEY_SECRET_ID,
    [string]$BwsPath = '',
    [switch]$PromptForAdminPassword,
    [switch]$UseClipboardForOpenAiKey
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
            throw "Gateway commissioning command failed: $stderr"
        }
        return $stdout.Trim()
    }
    finally {
        $InputText = $null
        $process.Dispose()
    }
}

$adminPassword = $null
$apiKey = $null
$payload = $null
try {
    $adminPassword = Get-AiGatewaySecretValue `
        -SecretId $AdminPasswordSecretId `
        -Prompt 'Rotated AI Gateway administrator password' `
        -AllowPrompt:$PromptForAdminPassword `
        -BwsPath $BwsPath
    $preflightCommand = 'cd /opt/ai-gateway/archestra && sudo python3 ./commission-company-openai.py --preflight-only'
    $preflight = Invoke-GatewaySshInput -RemoteCommand $preflightCommand -InputText $adminPassword
    Write-Output $preflight

    if (-not [string]::IsNullOrWhiteSpace($OpenAiApiKeySecretId)) {
        $apiKey = Read-BwsSecretValue -SecretId $OpenAiApiKeySecretId -BwsPath $BwsPath
    }
    elseif ($UseClipboardForOpenAiKey) {
        $clipboardText = Get-Clipboard -Raw
        if ([string]::IsNullOrWhiteSpace($clipboardText)) {
            throw 'The Windows clipboard is empty.'
        }
        $apiKey = $clipboardText.Trim()
        $clipboardText = $null
    }
    else {
        throw 'Set AI_GATEWAY_OPENAI_API_KEY_SECRET_ID to a Bitwarden secret ID or explicitly use -UseClipboardForOpenAiKey.'
    }
    if ($apiKey -notmatch '^sk-[A-Za-z0-9_-]{20,}$') {
        throw 'The selected OpenAI credential is not a validly shaped API key.'
    }
    $payload = @{
        openai_api_key = $apiKey
        archestra_admin_password = $adminPassword
    } | ConvertTo-Json -Compress

    $budget = $MonthlyExternalBudgetDollars.ToString([Globalization.CultureInfo]::InvariantCulture)
    $inputPrice = $InputPricePerMillionDollars.ToString([Globalization.CultureInfo]::InvariantCulture)
    $outputPrice = $OutputPricePerMillionDollars.ToString([Globalization.CultureInfo]::InvariantCulture)
    $remoteCommand = "cd /opt/ai-gateway/archestra && sudo python3 ./commission-company-openai.py --model $Model --monthly-budget $budget --input-price-per-million $inputPrice --output-price-per-million $outputPrice --confirm COMMISSION_COMPANY_OPENAI"
    $result = Invoke-GatewaySshInput -RemoteCommand $remoteCommand -InputText $payload
    Write-Output $result
    Write-Host 'Company OpenAI commissioning completed. The existing gateway route is local-first with managed escalation.'
}
finally {
    if ($UseClipboardForOpenAiKey -and $null -ne $apiKey) {
        Set-Clipboard -Value ''
    }
    $payload = $null
    $apiKey = $null
    $adminPassword = $null
}
