Set-StrictMode -Version Latest

function Test-AiGatewayWindowsPlatform {
    [CmdletBinding()]
    param()

    return $env:OS -eq 'Windows_NT'
}

function Resolve-BwsExecutable {
    [CmdletBinding()]
    param([string]$BwsPath = '')

    if (-not [string]::IsNullOrWhiteSpace($BwsPath)) {
        if (-not (Test-Path -LiteralPath $BwsPath -PathType Leaf)) {
            throw "Bitwarden Secrets Manager CLI was not found: $BwsPath"
        }
        return (Resolve-Path -LiteralPath $BwsPath).Path
    }

    $command = Get-Command bws -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $userInstall = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.local\bin\bws.exe'
    if (Test-Path -LiteralPath $userInstall -PathType Leaf) {
        return $userInstall
    }

    $legacyInstall = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.codex\bin\bws.exe'
    if (Test-Path -LiteralPath $legacyInstall -PathType Leaf) {
        return $legacyInstall
    }

    throw 'Bitwarden Secrets Manager CLI (bws) is required. Install it from the official Bitwarden SDK release.'
}

function Get-BwsCodexLauncher {
    [CmdletBinding()]
    param()

    return (Join-Path ([Environment]::GetFolderPath('UserProfile')) '.codex\bin\bws_codex.py')
}

function Read-BwsSecretValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-fA-F-]{36}$')]
        [string]$SecretId,
        [string]$BwsPath = ''
    )

    $savedAccessToken = $env:BWS_ACCESS_TOKEN
    $accessToken = $savedAccessToken
    $launcher = Get-BwsCodexLauncher
    $previousPreference = $ErrorActionPreference
    $exitCode = -1
    $raw = $null
    try {
        $ErrorActionPreference = 'SilentlyContinue'
        if (-not [string]::IsNullOrWhiteSpace($accessToken)) {
            $executable = Resolve-BwsExecutable -BwsPath $BwsPath
            $raw = & $executable secret get $SecretId --output json --color no 2>$null
        }
        elseif (Test-Path -LiteralPath $launcher -PathType Leaf) {
            $python = Get-Command python -ErrorAction Stop
            $raw = & $python.Source $launcher secret get $SecretId --output json --color no 2>$null
        }
        else {
            throw 'No Bitwarden machine-account token is available. Initialize the global Codex Windows Credential Manager entry or set BWS_ACCESS_TOKEN for this shell.'
        }
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousPreference
        $env:BWS_ACCESS_TOKEN = $savedAccessToken
        $accessToken = $null
    }
    if ($exitCode -ne 0) {
        throw "Bitwarden could not retrieve secret ID $SecretId with the current machine account."
    }

    try {
        $secret = (($raw | Out-String).Trim()) | ConvertFrom-Json
    }
    catch {
        throw "Bitwarden returned malformed JSON for secret ID $SecretId."
    }
    if (-not $secret -or [string]::IsNullOrWhiteSpace([string]$secret.value)) {
        throw "Bitwarden returned an empty value for secret ID $SecretId."
    }
    return [string]$secret.value
}

function Read-SecurePromptValue {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Prompt)

    $secureValue = Read-Host $Prompt -AsSecureString
    $pointer = [IntPtr]::Zero
    try {
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureValue)
        $value = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
        if ([string]::IsNullOrWhiteSpace($value)) {
            throw "$Prompt cannot be empty."
        }
        return $value
    }
    finally {
        $secureValue = $null
        if ($pointer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
        }
    }
}

function Get-AiGatewaySecretValue {
    [CmdletBinding()]
    param(
        [string]$SecretId = '',
        [Parameter(Mandatory = $true)][string]$Prompt,
        [switch]$AllowPrompt,
        [string]$BwsPath = ''
    )

    if (-not [string]::IsNullOrWhiteSpace($SecretId)) {
        return Read-BwsSecretValue -SecretId $SecretId -BwsPath $BwsPath
    }
    if ($AllowPrompt) {
        return Read-SecurePromptValue -Prompt $Prompt
    }
    throw "No Bitwarden secret ID was supplied for '$Prompt'. Set the documented secret-ID environment variable or use the explicit secure-prompt switch."
}
