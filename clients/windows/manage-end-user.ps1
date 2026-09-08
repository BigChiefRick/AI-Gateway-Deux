[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('status', 'grant', 'revoke')]
    [string]$Action,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$')]
    [string]$Email,
    [string]$Confirm = '',
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$TenantId,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$GroupId
)

$ErrorActionPreference = 'Stop'
$ExpectedGroupName = 'AI Gateway Users'

if ($Action -eq 'grant' -and $Confirm -ne 'GRANT_AI_GATEWAY_USER') {
    throw 'Grant requires -Confirm GRANT_AI_GATEWAY_USER.'
}
if ($Action -eq 'revoke' -and $Confirm -ne 'REVOKE_AI_GATEWAY_USER') {
    throw 'Revoke requires -Confirm REVOKE_AI_GATEWAY_USER.'
}
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI (az) is required.'
}

function Invoke-Graph {
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Path,
        [object]$Body = $null
    )

    $headers = @{ Authorization = "Bearer $script:GraphToken" }
    $parameters = @{
        Method      = $Method
        Uri         = "https://graph.microsoft.com/v1.0/$Path"
        Headers     = $headers
        ErrorAction = 'Stop'
    }
    if ($null -ne $Body) {
        $parameters.ContentType = 'application/json'
        $parameters.Body = ($Body | ConvertTo-Json -Depth 5 -Compress)
    }
    Invoke-RestMethod @parameters
}

function Test-ManagedMembership {
    param([Parameter(Mandatory = $true)][string]$UserId)

    $result = Invoke-Graph -Method POST -Path "users/$UserId/checkMemberGroups" -Body @{
        groupIds = @($GroupId)
    }
    return @($result.value) -contains $GroupId
}

$script:GraphToken = $null
try {
    $activeTenant = (& az account show --query tenantId --output tsv 2>$null).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($activeTenant)) {
        throw "Azure CLI is not signed in. Run: az login --tenant $TenantId"
    }
    if ($activeTenant -ne $TenantId) {
        throw "Azure CLI is signed into tenant $activeTenant, expected $TenantId. Run: az login --tenant $TenantId"
    }

    $script:GraphToken = (& az account get-access-token --resource-type ms-graph --query accessToken --output tsv 2>$null).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($script:GraphToken)) {
        throw 'Unable to obtain a Microsoft Graph token from the current Azure CLI session.'
    }

    $group = Invoke-Graph -Method GET -Path "groups/$GroupId`?`$select=id,displayName,securityEnabled"
    if ($group.displayName -ne $ExpectedGroupName -or $group.securityEnabled -ne $true) {
        throw "Group $GroupId is not the expected security group '$ExpectedGroupName'."
    }

    $escapedEmail = [Uri]::EscapeDataString($Email)
    try {
        $user = Invoke-Graph -Method GET -Path "users/$escapedEmail`?`$select=id,displayName,userPrincipalName,accountEnabled"
    }
    catch {
        throw "Entra user '$Email' was not found in tenant $TenantId."
    }
    if ($user.accountEnabled -ne $true) {
        throw "Entra user '$Email' is disabled."
    }

    $before = Test-ManagedMembership -UserId $user.id
    if ($Action -eq 'grant' -and -not $before) {
        Invoke-Graph -Method POST -Path "groups/$GroupId/members/`$ref" -Body @{
            '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($user.id)"
        } | Out-Null
    }
    elseif ($Action -eq 'revoke' -and $before) {
        Invoke-Graph -Method DELETE -Path "groups/$GroupId/members/$($user.id)/`$ref" | Out-Null
    }

    $after = Test-ManagedMembership -UserId $user.id
    if ($Action -eq 'grant' -and -not $after) {
        throw 'Graph accepted the grant request but membership verification failed.'
    }
    if ($Action -eq 'revoke' -and $after) {
        throw 'Graph accepted the revoke request but membership verification failed.'
    }

    [pscustomobject]@{
        Status            = 'PASS'
        Action            = $Action
        User              = $user.userPrincipalName
        DisplayName       = $user.displayName
        EntraGroup        = $ExpectedGroupName
        MemberBefore      = $before
        MemberAfter       = $after
        GatewayNextStep   = if ($Action -eq 'status') { 'none' } else { 'sign out and sign back in to refresh the Entra groups claim' }
    } | ConvertTo-Json -Compress
}
finally {
    $script:GraphToken = $null
}
