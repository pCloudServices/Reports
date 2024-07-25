<#
.SYNOPSIS
    Privilege Cloud Discovered accounts export
.DESCRIPTION
    This PowerShell script retrieves and exports discovered accounts from a Privilege Cloud environment. It may also be used to clear discovered accounts after export.
.PARAMETER PortalURL
    Specifies the URL of the Privilege Cloud tenant.
    Example: https://<subdomain>.cyberark.cloud
.PARAMETER ClearDiscoveredAccounts
    Clear Discovered accounts after retrieval.
    Default: false
.PARAMETER Force
    Do not prompt for confirmation before clearing Discovered accounts.
    Default: false
.EXAMPLE
    .\Get-CPCDiscoveredAccounts.ps1 -PortalURL "https://<subdomain>.cyberark.cloud"
    Retrieves discovered accounts from Privilege Cloud. The results will be exported to a CSV file.
#>
param(
    [Parameter(Mandatory = $true, HelpMessage = "Specify the URL of the Privilege Cloud tenant (e.g., https://<subdomain>.cyberark.cloud)")]
    [string]$PortalURL,
    [Parameter(Mandatory = $false, HelpMessage = "Clear discovered accounts after exporting")]
    [switch]$ClearDiscoveredAccounts,
    [Parameter(Mandatory = $false, HelpMessage = "Do not prompt for confirmation before clearing discovered accounts")]
    [switch]$Force,
    [Parameter(Mandatory = $true, HelpMessage = "User credential")]
    [PSCredential]$Credentials
)

# Modules
$mainModule = "Import_AllModules.psm1"

$modulePaths = @(
    "..\\PS-Modules\\$mainModule",
    "..\\..\\PS-Modules\\$mainModule",
    ".\\PS-Modules\\$mainModule", 
    ".\\$mainModule"
    "..\\$mainModule"
    ".\\..\\$mainModule"
    "..\\..\\$mainModule"
)

foreach ($modulePath in $modulePaths) {

    if (Test-Path $modulePath) {
        try {
            Import-Module $modulePath -ErrorAction Stop -DisableNameChecking -Force
        }
        catch {
            Write-Host "Failed to import module from $modulePath. Error: $_"
            Write-Host "check that you copied the PS-Modules folder correctly."
            Pause
            Exit
        }
    }
}

$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
$global:LOG_FILE_PATH = "$ScriptLocation\_Get-CPCDiscoveredAccounts.log"

[int]$scriptVersion = 1

# PS Window title
$Host.UI.RawUI.WindowTitle = "Privilege Cloud Discovered Accounts Report"

## Force Output to be UTF8 (for OS with different languages)
$OutputEncoding = [Console]::InputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding

function Get-DiscoveredAccounts {
    param (
        [string]$URLAPI,
        [HashTable]$logonheader
    )

    $uri = $URLAPI + "/DiscoveredAccounts/?limit=200"
    $RetrievedSoFar = @()

    do {
        try {
            Write-LogMessage -type Info -MSG "Retrieving $uri..."
            $response = Invoke-RestMethod -Uri $uri -Headers $logonheader -Method GET -UseBasicParsing
        }
        catch {
            Write-Error "Error: $($_.Exception.Message) $($_.ErrorDetails.Message) $($_.Exception.Status)"
            return $false
        }
        $uri = $URLAPI + ($response.nextLink -replace "^api", "")
        $RetrievedSoFar += $response.value
    }
    until ($null -eq $response.nextLink)
        
    return $RetrievedSoFar
}

function Clear-DiscoveredAccounts {
    param (
        [string]$URLAPI,
        [HashTable]$logonheader
    )

    $uri = "$URLAPI/DiscoveredAccounts/"
    try {
        $response = Invoke-RestMethod -Uri $uri -Headers $logonheader -Method DELETE -UseBasicParsing
    }
    catch {
        Write-Error "Error: $($_.Exception.Message) $($_.ErrorDetails.Message) $($_.Exception.Status)"
        return $false
    }

    return $response
}


# Main
write-Host "Script Version: $scriptVersion" -ForegroundColor Gray

# Build PVWA Urls
$platformURLs = DetermineTenantTypeURLs -PortalURL $PortalURL
$pvwaAPI = $platformURLs.PVWA_API_URLs.PVWAAPI
$global:AlreadyAnswered = $false


# Login
try {
    $logonheader = Authenticate-Platform -platformURLs $platformURLs -creds $Credentials
    if (-not($logonheader.Authorization)) {
        throw
    }
}
catch {
    Write-Host "Failed to get Token, exiting..."
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Error Details: $($_.ErrorDetails.Message)" -ForegroundColor Red
    Exit
}
try {
    $DiscoveredAccounts = Get-DiscoveredAccounts -URLAPI $pvwaAPI -logonHeader $logonheader
    If ($false -eq $DiscoveredAccounts) {
        throw
    }
}
catch {
    Write-Host "Failed to retrieve Discovered accounts, exiting..."
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Error Details: $($_.ErrorDetails.Message)" -ForegroundColor Red
    Exit
}

$ConvertedDiscoveredAccounts = @()

foreach ($Acc in $DiscoveredAccounts) {
    If ($Acc.discoveryDateTime) { $Acc.discoveryDateTime = (([System.DateTimeOffset]::FromUnixTimeSeconds($Acc.discoveryDateTime)).DateTime).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") } else { $Acc.discoveryDateTime = $null }
    If ($Acc.lastLogonDateTime) { $Acc.lastLogonDateTime = (([System.DateTimeOffset]::FromUnixTimeSeconds($Acc.lastLogonDateTime)).DateTime).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") } else { $Acc.lastLogonDateTime = $null }
    If ($Acc.lastPasswordSetDateTime) { $Acc.lastPasswordSetDateTime = (([System.DateTimeOffset]::FromUnixTimeSeconds($Acc.lastPasswordSetDateTime)).DateTime).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") } else { $Acc.lastPasswordSetDateTime = $null }
    $ConvertedDiscoveredAccounts += $Acc
}
If ($ConvertedDiscoveredAccounts.Length -gt 0) {
    Write-LogMessage -type Success -MSG ("Retrieved {0} Discovered accounts" -f $ConvertedDiscoveredAccounts.Length)
    $DateStamp = Get-Date -Format yyyy-MM-dd_HH-mm-ss
    try {
        $ConvertedDiscoveredAccounts | Export-Csv -NoTypeInformation -Path ".\DiscoveredAccounts-$DateStamp.csv"
        Write-LogMessage -type Info -MSG "Discovered accounts exported to DiscoveredAccounts-$DateStamp.csv"
    }
    catch {
        Write-LogMessage -type Error -MSG "Error occurred exporting accounts to DiscoveredAccounts-$DateStamp.csv"
        Write-LogMessage -type Error -MSG "Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-LogMessage -type Error -MSG "Error Details: $($_.ErrorDetails.Message)" -ForegroundColor Red
    }
    $ConvertedDiscoveredAccounts | ConvertTo-Json -Depth 5 | Out-File -FilePath ".\DiscoveredAccounts-$DateStamp.json"
    If ($ClearDiscoveredAccounts) {
        $DoClearDiscoveredAccounts = $false
        If ($true -eq $Force) {
            $DoClearDiscoveredAccounts = $true
        }
        else {
            Write-LogMessage -Type Verbose -MSG "Confirming request to clear Discovered accounts"
            $DiscoveredAccountsPromptInfo = ""
            $DiscoveredAccountsPromptInfo += ("Are you sure you want to clear Discovered accounts?`n")
        
            $PromptOptions = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
            $PromptOptions.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList "&Yes", "Clear Discovered accounts"))
            $PromptOptions.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList "&No", "Do not clear Discovered accounts"))
        
            $PromptSelection = $Host.UI.PromptForChoice("", $DiscoveredAccountsPromptInfo, $PromptOptions, 1)
            If ($PromptSelection -eq 0) {
                Write-LogMessage -Type Info "Discovered accounts will be cleared"
                $DoClearDiscoveredAccounts = $true
            }
            Else {
                Write-LogMessage -Type Error -MSG "Discovered accounts will NOT be cleared."
            }
        }

        If ($DoClearDiscoveredAccounts) {
            Write-LogMessage -type Info -MSG ("Clearing {0} Discovered accounts" -f $ConvertedDiscoveredAccounts.Length)
            $null = Clear-DiscoveredAccounts -URLAPI $pvwaAPI -logonHeader $logonheader
        }
    }
}
else {
    Write-LogMessage -type Info -MSG ("No Discovered accounts found")
}
# logoff
$Credentials = $null
Try { Invoke-RestMethod -Uri $($platformURLs.PVWA_API_URLs.Logoff) -Method Post -Headers $logonHeader | Out-Null } Catch {}
