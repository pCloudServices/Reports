param (
    [ValidateScript({
        if (!([string]::IsNullOrEmpty($_))) {
            $isValid = ($_ -like "*.privilegecloud.cyberark.com*") -or ($_ -like "*.cyberark.cloud*")
            if (-not $isValid) {
                throw "Invalid URL format. Please specify a valid Privilege Cloud tenant URL (e.g., https://<subdomain>.cyberark.cloud)."
            }
            $true
        } else {
            $true
        }
    })]
    [Parameter(Mandatory = $true, HelpMessage = "Specify the URL of the Privilege Cloud tenant (e.g., https://<subdomain>.cyberark.cloud)")]
    [string]$PortalURL,
    [Parameter(Mandatory = $true, HelpMessage = "Specify a User that has permissions in both Identity User Management and Vault Audit User. (e.g., mike@cyberark.cloud.1022")]
    [PSCredential]$Credentials,
    [Parameter(Mandatory = $false, HelpMessage = "Specify from which direction to sync the users 'sourceIdentity' or 'sourceVault' (Default: sourceIdentity).")]
    [ValidateSet("sourceIdentity", "sourceVault")]
    [string]$sourceOfTruth = "sourceVault",
    # skipReloadRights flag (only relevant if sourceOfTruth is sourceVault) will use cached results for faster run, but less accurate.
    [switch]$skipReloadRights
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
        } catch {
            Write-Host "Failed to import module from $modulePath. Error: $_"
            Write-Host "check that you copied the PS-Modules folder correctly."
            Pause
            Exit
        }
     }
}

$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
$global:LOG_FILE_PATH = "$ScriptLocation\_SyncIdentityRolesWithVaultUsers.log"
[int]$scriptVersion = 7

# PS Window title
$Host.UI.RawUI.WindowTitle = "Privilege Cloud Sync Identity Roles with Vault Users Script"
## Force Output to be UTF8 (for OS with different languages)
$OutputEncoding = [Console]::InputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding

# Build URLs
$platformURLs = DetermineTenantTypeURLs -PortalURL $PortalURL
$IdentityAPIURL = $platformURLs.IdentityURL
$pvwaAPI = $platformURLs.PVWA_API_URLs.PVWAAPI

# Privilege Cloud API
$script:PVWA_GetallUsers = "$pvwaAPI/Users"
$script:PVWA_GetUser = "$pvwaAPI/Users/{0}/"

# Output
$global:ExportDir = "$ScriptLocation\$(Get-Date -Format 'yyyyMMdd_HH-mm')"
if (!(Test-Path -Path $global:ExportDir)) {
    New-Item -ItemType Directory -Path $global:ExportDir | Out-Null
}


# Looking for all roles starting with "Privilege Cloud" in identity
Function Get-PrivCloudRoles(){

    Try{
        $body  = @{script = "Select Role.Name, ID from  Role ORDER BY Role COLLATE NOCASE"} | ConvertTo-Json -Compress
        $response = Invoke-RestMethod -Method Post -Uri "$IdentityAPIURL/Redrock/Query" -ContentType "application/json" -Headers $logonheader -Body $body -ErrorVariable identityErr
        $PrivCloudROles = $response.Result.Results| where {$_.Row.Name -like "Privilege Cloud*"}
        }
    Catch{
        $identityErr.message + $_.exception.status + $_.exception.Response.ResponseUri.AbsoluteUri
    }

    If ($response.success -eq $false){
    Write-LogMessage -type Error -MSG "Couldn't retrieve Roles, see response received:"
    $response
    Write-LogMessage -type Error -MSG "Aborting script..."
    Pause
    Exit
    }
    Else
    {
        return $PrivCloudROles
    }
}


#Cleanup log file if it gets too big
if (Test-Path $LOG_FILE_PATH)
{
    if (Get-ChildItem $LOG_FILE_PATH -File | Where-Object { $_.Length -gt 5000KB })
    {
        Write-LogMessage -type Info -MSG "Log file is getting too big, deleting it."
        Remove-Item $LOG_FILE_PATH -Force
    }

}


# Login
Refresh-Token -PlatformURLs $platformURLs -creds $Credentials -ForceAuthType $ForceAuthType

# Identity minimal permissions
Write-LogMessage -type Info -MSG "Checking if we have sufficient permissions to perform the query in Identity..." -Early
$IdentityPermission=$(Get-IdentityPermissions -URLAPI $IdentityAPIURL -logonheader $logonheader)
if (($IdentityPermission -eq "User Management") -or ($IdentityPermission -eq "All Rights")){
    Write-LogMessage -type Success -MSG "Passed minimal permissions requirement to perform query in Identity"
}
Else{
    Write-LogMessage -type Error -MSG "User doesn't have sufficient permissions in Identity, make sure user is part of any role that has `"User Management`" administrative permission."
    Write-Host "Displaying Current permissions:" -ForegroundColor Yellow
    $IdentityPermission
    Pause
    Exit
}

Write-LogMessage -type Info -MSG "Checking if we have sufficient permissions to peform the query in Privilege Cloud..." -Early
$PrivilegeCloudPermission=$(Get-VaultPermissions -URLAPI $pvwaAPI -logonheader $logonheader -pvwaUser $Credentials.UserName)
if ($PrivilegeCloudPermission -match "AuditUsers"){
     Write-LogMessage -type Success -MSG "Passed minimal permissions requirement to perform query in Privilege Cloud"
}
Else{
    Write-LogMessage -type Error -MSG "User doesn't have sufficient permissions in Privilege Cloud, make sure user has Vault Authorization `"AuditUsers`" permission."
    Write-Host "Displaying Current permissions:" -ForegroundColor Yellow
    $PrivilegeCloudPermission
    Pause
    Exit
}

# if sourceOfTruth flag was not called
if([string]::IsNullOrEmpty($sourceOfTruth)){
    $selection = Get-Choice -Title "Choose Source of Truth" -Options "Identity","Vault" -DefaultChoice 1
    if($selection -like "*Identity*"){
        $script:sourceOfTruth = "sourceIdentity"
    }Else{
        $script:sourceOfTruth = "sourceVault"
    }
}


$sourceOfTruth = "sourceVault" # forcing this to Vault atm until we can overcome external timeouts from AD.


Switch ($sourceOfTruth)
{
    "sourceIdentity"
    {
        Write-LogMessage -type Info -MSG "Start retreieving Users under `"Privilege Cloud*`" Roles in identity"
        $allIdentityUsers = @()
        foreach ($role in $(Get-PrivCloudRoles).Row.ID) {
            Try {
                Write-LogMessage -type Info -MSG "Checking Role: $role" -Early
        
                $startIndex = 0
                $limit = 100000
                $totalFetched = 0
        
                do {
                    # Handle token timeouts
                    Refresh-Token -PlatformURLs $platformURLs -creds $Credentials -ForceAuthType $ForceAuthType
        
                    # Retrieve Role Members
                    $uri = "$IdentityAPIURL/PCloud/GetRoleMembers?roles=$role&startIndex=$startIndex&limit=$limit"
                    $resp = Invoke-RestMethod -Method POST -Uri $uri -ContentType "application/json" -Headers $logonheader -ErrorVariable identityErr
                    $resp
                    if ($resp.success -and $resp.Result.count -gt 0) {
                        Write-LogMessage -type Info -MSG "Fetching users from index $startIndex" -Early
                        #$resp.Result.users.UserName
                        $resp
                        $resp.Result.users.UserName | out-file "$ExportDir\Identityusers_$($role)_$($totalFetched).txt" -force
                        $allIdentityUsers += $resp.Result.users.UserName
        
                        # Update the total number of fetched users
                        $totalFetched += $resp.Result.users.UserName.Count
                    }
        
                    # Increment startIndex for the next batch
                    $startIndex += $limit
        
                    # Check if we have fetched all available users
                } while ($totalFetched -lt $resp.Result.count)
        
            } Catch {
                throw $identityErr.message + $_.exception.status + $_.exception.Response.ResponseUri.AbsoluteUri
            }
        }
        
        #Remove built-in user(s)
        Write-LogMessage -type Info -MSG "Removed InstallerUser from the list..." -Early
        $allIdentityUsers = $allIdentityUsers | Where-Object { $_ -notlike "installeruser*" } | Sort-Object -Unique
        Write-LogMessage -type Info -MSG "Retrieved ($($allIdentityUsers.Count)) Users from Identity"
        
        
        Try{
            Refresh-Token -PlatformURLs $platformURLs -creds $Credentials -ForceAuthType $ForceAuthType
            #Get Users from Vault
            $VaultUsersTypesTOCheck = @("EPVUser", "EPVUserLite", "BasicUser", "ExtUser", "BizUser")
            $VaultUsersAll = @()
            foreach ($userTYpe in $VaultUsersTypesTOCheck){
                Write-LogMessage -type Info -MSG "Retrieving Users under UserTYpe: $userTYpe" -Early
        	Try{
        	   $respUsers = @()
                   $respUsers = Invoke-RestMethod -Uri ("$($PVWA_GetallUsers)?UserType=$($userTYpe)") -Method Get -Headers $logonheader -ErrorVariable pvwaERR
                   Write-LogMessage -type Info -MSG "$userTYpe $($respUsers.total)" -Early
                   $respUsers.Users.username | out-file "$ExportDir\VaultUsers_$($userTYpe).txt" -force
                   if($respUsers.total -gt 0){
                       $VaultUsersAll += $respUsers.Users.username
                   }
        	   }
            	   Catch
        	   {
            	    Write-LogMessage -type Info -MSG "Couldn't find type $($userType) likely no license for it, skipping..." -Early
        	   }
                
            }
            
            
            Write-LogMessage -type Info -MSG "Start comparing users..." -Early
            $VaultUsersAll | out-file "$ExportDir\VaultUsers_ALL.txt" -force
            $allIdentityUsers | out-file "$ExportDir\Identityusers_ALL.txt" -force
            # TODO this fails.
            $diff = Compare-Object -ReferenceObject @($VaultUsersAll | Select-Object) -DifferenceObject @($allIdentityUsers | Select-Object)
        
            <#
            $identityDiff = $diff | Where-Object { $_.SideIndicator -eq '=>' }
            if ($identityDiff){
                Write-Host "Users that exist in Identity but not in vault:" -ForegroundColor Yellow
                $identityDiff.inputObject
                $identityDiff.inputObject | Out-File "$ExportDir\IdentityUsersToDelete.txt" -Force
                Write-Host "Exported to IdentityUsersToDelete.csv" -ForegroundColor Green
            }
            #>
            
            $vaultDiff = $diff | Where-Object { $_.SideIndicator -eq '<=' }
            if ($vaultDiff){
                Write-Host "Below Users exist in the Vault but do NOT exist in Identity: (recommend to analyze the list and delete these users as they are consuming vault license.)" -ForegroundColor Yellow
                Start-Sleep 5
                $vaultDiff.inputObject
                $vaultDiff.inputObject | Out-File "$ExportDir\VaultUsersToDelete.txt" -Force
                Write-Host "Exported to VaultUsersToDelete.csv" -ForegroundColor Green
            }
            
            if (($identityDiff -eq $null) -and ($vaultDiff -eq $null)){
                Write-LogMessage -type Success -MSG "No discrepancies found between Identity and Privilege Cloud Vault!"
            }
        }Catch{
            Write-LogMessage -Type Error -Msg "Error: $(Collect-ExceptionMessage $_.exception.message $($_.ErrorDetails.Message) $($_.exception.status) $($_.exception.Response.ResponseUri.AbsoluteUri) $pvwaERR)"
        }    
    }
    
    "sourceVault"
    {
         Try{
            Refresh-Token -PlatformURLs $platformURLs -creds $Credentials -ForceAuthType $ForceAuthType
            #Get Users from Vault
            $VaultUsersTypesTOCheck = @("EPVUser", "EPVUserLite", "BasicUser", "ExtUser", "BizUser")
            $VaultUsersAll = @()
            Write-LogMessage -type Info -MSG "Start retrieving users from Vault" -subHeader
            foreach ($userTYpe in $VaultUsersTypesTOCheck)
            {
                Write-LogMessage -type Info -MSG "Retrieving Users under UserTYpe: $userTYpe" -Early
        	    Try{
                    $respUsers = @()
                    $respUsers = Invoke-RestMethod -Uri ("$($PVWA_GetallUsers)?UserType=$($userTYpe)") -Method Get -Headers $logonheader -ErrorVariable pvwaERR
                    Write-LogMessage -type Info -MSG "$userTYpe $($respUsers.total)" -Early
                    # Save each user type as output
                    $respUsers.Users.username | out-file "$ExportDir\VaultUsers_$($userTYpe).txt" -force
                    if($respUsers.total -gt 0){
                        $VaultUsersAll += $respUsers.Users.username
                    }
                   }
                        Catch
        	       {
                        Write-LogMessage -type Info -MSG "Couldn't find type $($userType) likely no license for it, skipping..." -Early
        	       }
            }
            Write-LogMessage -type Info -MSG "Done retrieving users from Vault" -subHeader

            # Get all Identity Users
            $allIdentityUsers = @()
            $pageNumber = 1
            $resultsPerPage = 500
            $hasMoreResults = $true
                      
            Write-LogMessage -type Info -MSG "Start retrieving users from Identity" -subHeader
            while($hasMoreResults){  
                Refresh-Token -PlatformURLs $platformURLs -creds $Credentials -ForceAuthType $ForceAuthType
                $body = @{
                    Script = "@@All Users"
                    Args = @{
                        Ascending = $true
                        PageNumber = $pageNumber
                        PageSize = $resultsPerPage
                        Limit = 100000
                        SortBy = "Username"
                        Caching = -1
                        Direction = "ASC"
                    }
                }
                $body = $body | ConvertTo-Json -Depth 3
                $resp = Invoke-RestMethod -Method Post -Uri "$IdentityAPIURL/Redrock/Query" -ContentType "application/json" -Headers $logonheader -Body $body -ErrorVariable identityErr
                # if count bigger than 0 we move to next page
                if ($resp.Result.Results.row.Count -gt 0) {
                    Write-LogMessage -type Info -MSG "Total Users: $($resp.Result.Results.row.Count)" -early
                    $allIdentityUsers += $resp.Result.Results.row
                    # Move to the next page
                    $pageNumber++
                    Write-LogMessage -type Info -MSG "Checking next Index...$($pageNumber)" -Early
                } else {
                    # No more results, exit the loop
                    Write-LogMessage -type Info -MSG "No more pages, proceeding to next step." -Early
                    $hasMoreResults = $false
                }
                Start-Sleep -Seconds 1
            }
            
            Write-LogMessage -type Info -MSG "Done retrieving users from Identity" -subHeader
            Write-LogMessage -type Info -MSG "Comparing between the list of users..."
            # Users that are both in vault and Identity
            $matchingUsers = $allIdentityUsers | Where-Object { $VaultUsersAll -contains $_.Username }
            # Users that are in vault but not in Identity
            $unmatchedUsers = $VaultUsersAll | Where-Object { $allIdentityUsers.Username -notcontains $_ }

            if($skipReloadRights.IsPresent){
                Write-LogMessage -type Info -MSG "User selected running without Reload rights for each User" -early
            }Else{
                Write-LogMessage -type warning -MSG "Script will now reload rights for all matched users before checking if they are part of any Priv Cloud role."
                Write-LogMessage -type warning -MSG "You can skip this process if changes to users were made 24h+ ago by running script with -skipReloadRights"
                Write-LogMessage -type warning -MSG "We typically recommend reloading rights to reflect true status of the user in real time, but it also prolongs the run."
                Start-Sleep 5
                Write-LogMessage -type Info -MSG "Start reloading rights for each user before checking roles..." -early
                foreach($identityUser in $matchingUsers){

                    $ProvBody = @{
                        UserData = @{
                            Username = "$($identityUser.username)"
                        }
                    } | ConvertTo-Json -Depth 10 -Compress

                    Refresh-Token -PlatformURLs $platformURLs -creds $Credentials -ForceAuthType $ForceAuthType
                    Try{
                        Write-LogMessage -type Info -MSG "Reloading Identity rights for User: $($identityUser.username)" -early
                        Refresh-Token -PlatformURLs $platformURLs -creds $Credentials -ForceAuthType $ForceAuthType
                        $respreloaduser = Invoke-RestMethod -Method Post -Uri "$IdentityAPIURL/CDirectoryService/RefreshToken?id=$($identityUser.ID)" -ContentType "application/json" -Headers $logonheader -Body $body -ErrorVariable identityErr
                        Write-LogMessage -type Info -MSG "Reloading license userType for User: $($identityUser.username)" -early
                        $respprovisionUser = Invoke-RestMethod -Method Post -Uri "$pvwaAPI/Provision/User"  -ContentType "application/json" -Headers $logonheader -Body $ProvBody -ErrorVariable identityErr
                    }Catch{
                        Write-LogMessage -Type Error -Msg "Error on user $($identityUser.username): $(Collect-ExceptionMessage $identityErr.message + $_.exception.status + $_.exception.Response.ResponseUri.AbsoluteUri $identityErr)"
                    }
                }
                Write-LogMessage -type Info -MSG "Done reloading rights for each user" -early
            }

            Write-LogMessage -type Info -MSG "Retrieving Priv Cloud roles..." -early
            $PrivCloudRoles = $(Get-PrivCloudRoles).Row.ID
            Write-LogMessage -type Info -MSG "Start checking if users part of any Privilege Cloud* role in Identity" -subHeader
            $matchedUsersRoles = @()
            $usersNoPcloudRoles = @()
            foreach ($matchedUser in $matchingUsers) {    
                Try {
                    Refresh-Token -PlatformURLs $platformURLs -creds $Credentials -ForceAuthType $ForceAuthType
                    Write-LogMessage -type Info -MSG "Checking User: $($matchedUser.username)" -early
                    $respreloaduser = Invoke-RestMethod -Method Post -Uri "$IdentityAPIURL/UserMgmt/GetUsersRolesAndAdministrativeRights?id=$($matchedUser.ID)" -ContentType "application/json" -Headers $logonheader -Body $body -ErrorVariable identityErr
            
                    # Grab roles for user
                    $userRoles = $respreloaduser.Result.Results.entities.key
            
                    # Find matching roles between user roles and PrivCloudRoles
                    $matchingRoles = $userRoles | Where-Object { $PrivCloudRoles -contains $_ }
            
                    if ($matchingRoles) {
                        Write-LogMessage -type Info -MSG "User $($matchedUser.username) has the following Privilege Cloud roles:" -early
                        Write-Host ($matchingRoles -join "`n") -ForegroundColor DarkGray
                        $matchedUsersRoles += [pscustomobject]@{
                            Username = $matchedUser.username
                            Roles   = ($matchingRoles -join ", ") # Join matching roles with commas
                        }

                    } else {
                        Write-LogMessage -type Warning -MSG "User $($matchedUser.username) does not have any matching Privilege Cloud roles."
                        $usersNoPcloudRoles += $($matchedUser.username)
                    }
                } Catch {
                    Write-LogMessage -Type Error -Msg "Error: $(Collect-ExceptionMessage $identityErr.message + $_.exception.status + $_.exception.Response.ResponseUri.AbsoluteUri $identityErr)"
                }
            }

            $matchedUsersRoles | Export-Csv -Path "$ExportDir\IdentityUsersWithPcloudRoles.csv" -NoTypeInformation -Encoding UTF8

            # announce Results and save to Excel.
            if (!($usersNoPcloudRoles.Count -gt 0) -and !($unmatchedUsers.Count -gt 0)){
                Write-LogMessage -type Success -MSG "No discrepancies found between Identity and Privilege Cloud Vault!"
            }
            Else
            {
                if($usersNoPcloudRoles){
                    $totalCount = $usersNoPcloudRoles.Count
                    $displayCount = [Math]::Min($totalCount, 50)

                    Write-LogMessage -type Warning -MSG "Following Users should be removed from the Vault (Reason: do not belong to any Priv Cloud role in Identity):"
                    Write-Host ""
                    Write-LogMessage -type info -MSG "Showing $displayCount of $totalCount users:"
                    $usersNoPcloudRoles | Select-Object -First $displayCount
                    Write-Host ""
                    $usersNoPcloudRoles | out-file "$ExportDir\vaultUsersToDelete_Reason_Not_In_PrivCloud_Role.txt" -force
                    write-host "Results exported to $ExportDir\vaultUsersToDelete_Reason_Not_In_PrivCloud_Role.txt" -ForegroundColor Cyan
                }
                if($unmatchedUsers){
                    $totalCount = $unmatchedUsers.Count
                    $displayCount = [Math]::Min($totalCount, 50)

                    Write-LogMessage -type Warning -MSG "Following Users should be removed from the Vault (Reason: do not exist in Identity):"
                    Write-Host ""
                    Write-LogMessage -type info -MSG "Showing $displayCount of $totalCount users:"
                    $unmatchedUsers | Select-Object -First $displayCount
                    Write-Host ""
                    $unmatchedUsers | out-file "$ExportDir\vaultUsersToDelete_Reason_Not_In_Identity.txt" -force
                    write-host "Results exported to $ExportDir\vaultUsersToDelete_Reason_Not_In_Identity.txt" -ForegroundColor Cyan
                }
            }
        }Catch{
            Write-LogMessage -Type Error -Msg "Error: $(Collect-ExceptionMessage $_.exception.message $($_.ErrorDetails.Message) $($_.exception.status) $($_.exception.Response.ResponseUri.AbsoluteUri) $pvwaERR)"
        }   
    }
}
# SIG # Begin signature block
# MIIzKQYJKoZIhvcNAQcCoIIzGjCCMxYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAK8Uy9oPJH/98t
# jKx405vnSQgzAB3Mlxfs27Xap7YhKqCCGJkwggROMIIDNqADAgECAg0B7l8Wnf+X
# NStkZdZqMA0GCSqGSIb3DQEBCwUAMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBH
# bG9iYWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9i
# YWxTaWduIFJvb3QgQ0EwHhcNMTgwOTE5MDAwMDAwWhcNMjgwMTI4MTIwMDAwWjBM
# MSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xv
# YmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8RgJDx7KKnQRf
# JMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsTgHeMCOFJ0mpi
# Lx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmmKPZpO/bLyCiR
# 5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zdQQ4gOsC0p6Hp
# sk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZXriX7613t2Sa
# er9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaOCASIwggEeMA4GA1Ud
# DwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSP8Et/qC5FJK5N
# UPpjmove4t0bvDAfBgNVHSMEGDAWgBRge2YaRQ2XyolQL30EzTSo//z9SzA9Bggr
# BgEFBQcBAQQxMC8wLQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24u
# Y29tL3Jvb3RyMTAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3JsLmdsb2JhbHNp
# Z24uY29tL3Jvb3QuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIB
# FiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG
# 9w0BAQsFAAOCAQEAI3Dpz+K+9VmulEJvxEMzqs0/OrlkF/JiBktI8UCIBheh/qvR
# XzzGM/Lzjt0fHT7MGmCZggusx/x+mocqpX0PplfurDtqhdbevUBj+K2myIiwEvz2
# Qd8PCZceOOpTn74F9D7q059QEna+CYvCC0h9Hi5R9o1T06sfQBuKju19+095VnBf
# DNOOG7OncA03K5eVq9rgEmscQM7Fx37twmJY7HftcyLCivWGQ4it6hNu/dj+Qi+5
# fV6tGO+UkMo9J6smlJl1x8vTe/fKTNOvUSGSW4R9K58VP3TLUeiegw4WbxvnRs4j
# vfnkoovSOWuqeRyRLOJhJC2OKkhwkMQexejgcDCCBaIwggSKoAMCAQICEHgDGEJF
# cIpBz28BuO60qVQwDQYJKoZIhvcNAQEMBQAwTDEgMB4GA1UECxMXR2xvYmFsU2ln
# biBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkds
# b2JhbFNpZ24wHhcNMjAwNzI4MDAwMDAwWhcNMjkwMzE4MDAwMDAwWjBTMQswCQYD
# VQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEpMCcGA1UEAxMgR2xv
# YmFsU2lnbiBDb2RlIFNpZ25pbmcgUm9vdCBSNDUwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQC2LcUw3Xroq5A9A3KwOkuZFmGy5f+lZx03HOV+7JODqoT1
# o0ObmEWKuGNXXZsAiAQl6fhokkuC2EvJSgPzqH9qj4phJ72hRND99T8iwqNPkY2z
# BbIogpFd+1mIBQuXBsKY+CynMyTuUDpBzPCgsHsdTdKoWDiW6d/5G5G7ixAs0sdD
# HaIJdKGAr3vmMwoMWWuOvPSrWpd7f65V+4TwgP6ETNfiur3EdaFvvWEQdESymAfi
# dKv/aNxsJj7pH+XgBIetMNMMjQN8VbgWcFwkeCAl62dniKu6TjSYa3AR3jjK1L6h
# wJzh3x4CAdg74WdDhLbP/HS3L4Sjv7oJNz1nbLFFXBlhq0GD9awd63cNRkdzzr+9
# lZXtnSuIEP76WOinV+Gzz6ha6QclmxLEnoByPZPcjJTfO0TmJoD80sMD8IwM0kXW
# LuePmJ7mBO5Cbmd+QhZxYucE+WDGZKG2nIEhTivGbWiUhsaZdHNnMXqR8tSMeW58
# prt+Rm9NxYUSK8+aIkQIqIU3zgdhVwYXEiTAxDFzoZg1V0d+EDpF2S2kUZCYqaAH
# N8RlGqocaxZ396eX7D8ZMJlvMfvqQLLn0sT6ydDwUHZ0WfqNbRcyvvjpfgP054d1
# mtRKkSyFAxMCK0KA8olqNs/ITKDOnvjLja0Wp9Pe1ZsYp8aSOvGCY/EuDiRk3wID
# AQABo4IBdzCCAXMwDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMD
# MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFB8Av0aACvx4ObeltEPZVlC7zpY7
# MB8GA1UdIwQYMBaAFI/wS3+oLkUkrk1Q+mOai97i3Ru8MHoGCCsGAQUFBwEBBG4w
# bDAtBggrBgEFBQcwAYYhaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vcm9vdHIz
# MDsGCCsGAQUFBzAChi9odHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2Vy
# dC9yb290LXIzLmNydDA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2Jh
# bHNpZ24uY29tL3Jvb3QtcjMuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsG
# AQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAN
# BgkqhkiG9w0BAQwFAAOCAQEArPfMFYsweagdCyiIGQnXHH/+hr17WjNuDWcOe2LZ
# 4RhcsL0TXR0jrjlQdjeqRP1fASNZhlZMzK28ZBMUMKQgqOA/6Jxy3H7z2Awjuqgt
# qjz27J+HMQdl9TmnUYJ14fIvl/bR4WWWg2T+oR1R+7Ukm/XSd2m8hSxc+lh30a6n
# sQvi1ne7qbQ0SqlvPfTzDZVd5vl6RbAlFzEu2/cPaOaDH6n35dSdmIzTYUsvwyh+
# et6TDrR9oAptksS0Zj99p1jurPfswwgBqzj8ChypxZeyiMgJAhn2XJoa8U1sMNSz
# BqsAYEgNeKvPF62Sk2Igd3VsvcgytNxN69nfwZCWKb3BfzCCBugwggTQoAMCAQIC
# EHe9DgW3WQu2HUdhUx4/de0wDQYJKoZIhvcNAQELBQAwUzELMAkGA1UEBhMCQkUx
# GTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2JhbFNpZ24g
# Q29kZSBTaWduaW5nIFJvb3QgUjQ1MB4XDTIwMDcyODAwMDAwMFoXDTMwMDcyODAw
# MDAwMFowXDELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MjAwBgNVBAMTKUdsb2JhbFNpZ24gR0NDIFI0NSBFViBDb2RlU2lnbmluZyBDQSAy
# MDIwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyyDvlx65ATJDoFup
# iiP9IF6uOBKLyizU/0HYGlXUGVO3/aMX53o5XMD3zhGj+aXtAfq1upPvr5Pc+OKz
# GUyDsEpEUAR4hBBqpNaWkI6B+HyrL7WjVzPSWHuUDm0PpZEmKrODT3KxintkktDw
# tFVflgsR5Zq1LLIRzyUbfVErmB9Jo1/4E541uAMC2qQTL4VK78QvcA7B1MwzEuy9
# QJXTEcrmzbMFnMhT61LXeExRAZKC3hPzB450uoSAn9KkFQ7or+v3ifbfcfDRvqey
# QTMgdcyx1e0dBxnE6yZ38qttF5NJqbfmw5CcxrjszMl7ml7FxSSTY29+EIthz5hV
# oySiiDby+Z++ky6yBp8mwAwBVhLhsoqfDh7cmIsuz9riiTSmHyagqK54beyhiBU8
# wurut9itYaWvcDaieY7cDXPA8eQsq5TsWAY5NkjWO1roIs50Dq8s8RXa0bSV6KzV
# SW3lr92ba2MgXY5+O7JD2GI6lOXNtJizNxkkEnJzqwSwCdyF5tQiBO9AKh0ubcdp
# 0263AWwN4JenFuYmi4j3A0SGX2JnTLWnN6hV3AM2jG7PbTYm8Q6PsD1xwOEyp4Lk
# tjICMjB8tZPIIf08iOZpY/judcmLwqvvujr96V6/thHxvvA9yjI+bn3eD36blcQS
# h+cauE7uLMHfoWXoJIPJKsL9uVMCAwEAAaOCAa0wggGpMA4GA1UdDwEB/wQEAwIB
# hjATBgNVHSUEDDAKBggrBgEFBQcDAzASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1Ud
# DgQWBBQlndD8WQmGY8Xs87ETO1ccA5I2ETAfBgNVHSMEGDAWgBQfAL9GgAr8eDm3
# pbRD2VZQu86WOzCBkwYIKwYBBQUHAQEEgYYwgYMwOQYIKwYBBQUHMAGGLWh0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2NvZGVzaWduaW5ncm9vdHI0NTBGBggrBgEF
# BQcwAoY6aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvY29kZXNp
# Z25pbmdyb290cjQ1LmNydDBBBgNVHR8EOjA4MDagNKAyhjBodHRwOi8vY3JsLmds
# b2JhbHNpZ24uY29tL2NvZGVzaWduaW5ncm9vdHI0NS5jcmwwVQYDVR0gBE4wTDBB
# BgkrBgEEAaAyAQIwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2ln
# bi5jb20vcmVwb3NpdG9yeS8wBwYFZ4EMAQMwDQYJKoZIhvcNAQELBQADggIBACV1
# oAnJObq3oTmJLxifq9brHUvolHwNB2ibHJ3vcbYXamsCT7M/hkWHzGWbTONYBgIi
# ZtVhAsVjj9Si8bZeJQt3lunNcUAziCns7vOibbxNtT4GS8lzM8oIFC09TOiwunWm
# dC2kWDpsE0n4pRUKFJaFsWpoNCVCr5ZW9BD6JH3xK3LBFuFr6+apmMc+WvTQGJ39
# dJeGd0YqPSN9KHOKru8rG5q/bFOnFJ48h3HAXo7I+9MqkjPqV01eB17KwRisgS0a
# Ifpuz5dhe99xejrKY/fVMEQ3Mv67Q4XcuvymyjMZK3dt28sF8H5fdS6itr81qjZj
# yc5k2b38vCzzSVYAyBIrxie7N69X78TPHinE9OItziphz1ft9QpA4vUY1h7pkC/K
# 04dfk4pIGhEd5TeFny5mYppegU6VrFVXQ9xTiyV+PGEPigu69T+m1473BFZeIbuf
# 12pxgL+W3nID2NgiK/MnFk846FFADK6S7749ffeAxkw2V4SVp4QVSDAOUicIjY6i
# vSLHGcmmyg6oejbbarphXxEklaTijmjuGalJmV7QtDS91vlAxxCXMVI5NSkRhyTT
# xPupY8t3SNX6Yvwk4AR6TtDkbt7OnjhQJvQhcWXXCSXUyQcAerjH83foxdTiVdDT
# HvZ/UuJJjbkRcgyIRCYzZgFE3+QzDiHeYolIB9r1MIIHsTCCBZmgAwIBAgIMBmw4
# iuAOfBdrKw0JMA0GCSqGSIb3DQEBCwUAMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUg
# RVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDAeFw0yNTAxMjgxMDI4MzNaFw0yODAxMjkx
# MDI4MzNaMIH3MR0wGwYDVQQPDBRQcml2YXRlIE9yZ2FuaXphdGlvbjESMBAGA1UE
# BRMJNTEyMjkxNjQyMRMwEQYLKwYBBAGCNzwCAQMTAklMMQswCQYDVQQGEwJJTDEQ
# MA4GA1UECBMHQ2VudHJhbDEUMBIGA1UEBxMLUGV0YWggVGlrdmExEzARBgNVBAkT
# CjkgSGFwc2Fnb3QxHzAdBgNVBAoTFkN5YmVyQXJrIFNvZnR3YXJlIEx0ZC4xHzAd
# BgNVBAMTFkN5YmVyQXJrIFNvZnR3YXJlIEx0ZC4xITAfBgkqhkiG9w0BCQEWEmFk
# bWluQGN5YmVyYXJrLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# ANZQPlxrcfMjyi+hhEn41HogbUr17cJB+2rbTOBphAPzZEySpd+GObt2pAyYbXTb
# 1XGHRomYxq/fTVcDWn6ESHKqIpTUnTsai2FakMr4OINfey2c0Lw81SCwedG6ind+
# QxszJ3c1iAoyuO8fbNAJJQHKTNAdTCADAHrfHvv8fuF8iw8vZCP5E6JFdcvaNUL9
# 9lecTTlIuXMyfLoO/9Q6geZ30UeSibynHoZbGzzK20pxL9VM5LA9YiGtA+bfdRGe
# hlqhPD4KgBRkc9bogTxA78QaiBUEnYM1vMmKc86MjXSS6R+z5mFAdhcs5C6cqWdO
# wo5jVFXpwxQh0jNTalt/kkwTjlIeO3+fdDDYLmbmH3nIsMutaHyXPogVp7upktz9
# WeS9r0ZpqKw7viVe/CWS9Df8/ceZD9zBkIbTrYGFU02hDaWaN1pFs6V21iaiTaZX
# pnnpEbtgoy8rptlFFIf0GQBDD0mTBDm7lZ8rDfN7IECcahCN4dMfnFO/QFpxAILa
# ekomXUmtkH3WBaQl4hraHja+fCi4ZtKhYYTZWdakH6bvdkENywuze/liwv2OVdZ4
# qddJpbvblqa9jqnV8RhugofYVEBq6yyd6OgJosdFPIZN7upzrCmHJTiTDtBNQJ2z
# m7LXrryUF9yTyjeUjLbUfTKbpj4UzM3jcKu1J5jDL5zFAgMBAAGjggHVMIIB0TAO
# BgNVHQ8BAf8EBAMCB4AwgZ8GCCsGAQUFBwEBBIGSMIGPMEwGCCsGAQUFBzAChkBo
# dHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9nc2djY3I0NWV2Y29k
# ZXNpZ25jYTIwMjAuY3J0MD8GCCsGAQUFBzABhjNodHRwOi8vb2NzcC5nbG9iYWxz
# aWduLmNvbS9nc2djY3I0NWV2Y29kZXNpZ25jYTIwMjAwVQYDVR0gBE4wTDBBBgkr
# BgEEAaAyAQIwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5j
# b20vcmVwb3NpdG9yeS8wBwYFZ4EMAQMwCQYDVR0TBAIwADBHBgNVHR8EQDA+MDyg
# OqA4hjZodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2ln
# bmNhMjAyMC5jcmwwHQYDVR0RBBYwFIESYWRtaW5AY3liZXJhcmsuY29tMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd0PxZCYZjxezzsRM7VxwDkjYR
# MB0GA1UdDgQWBBQewhxJyrlxdN3533DHK3x6hrz7uzANBgkqhkiG9w0BAQsFAAOC
# AgEAWgNDad105JaVijYhNrwnSPmm1mIhDpSvPDvIR4pENU9IdPcI8rxXRmJ083JM
# vIx5p7LvuBOTkyaNgZOjmkypMNM4NtMtHHdXAiWb6T+Udv4w0lcgUBWapeRxO7X5
# ok+E9lrVeSiiSrM/6TDF3xkAwcR5CzYjEYsgYa0H+hBXl9+oXe2QYFuArlQ0OfTv
# nXr2iFlvl0AKR7fRY0qBBGoKUATjGiYUFcigc9PyW2vml1BMxXx65jkKdoPIMZSJ
# Ka7xkExONB+t3uJc8yI+n2x24k1bjl8mJdnEkryUATe58vLxfYa93mLFC7VLCTND
# cJjFBvdL86F1HyveXhHX5XMlS/HPcnRk6VV8+zkr72fGP18cxl1nOAftgjOxh0mD
# Y6l9UMkOle1gSlf/S15z6VlRx+TkE/ZeL2n/tw4zHqWaNatHy+Zs2BIzaMdzP/u4
# tYTOuhQfXYnP5zrGw5ldYkIAQawVZwcODVO+FBb8/F3uTBbiMqCaOxy8RGLTqJlI
# bk+fBnkgtYyiIglUE10Y/FwI4qMgG2iZh97WsISLblu4Lfz9t7/bo54Y4bGqOdnW
# rz6e4hDhlkozop7MHG35nqHRN5Qx4iUDxvyDJLpZXG0kes+Cx+zkqhGvz9ST0bB6
# WH5RcnIk2Rog6Rr/bs0O1ZMS5DZy6vm1RB5fAZfAZ451uRwxghnmMIIZ4gIBATBs
# MFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYD
# VQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMAIM
# Bmw4iuAOfBdrKw0JMA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYBBAGCNwIBDDECMAAw
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBQmms98Hof10t+2tV9oqBptmJpr/sgV
# F2PRlWw7fZqjMA0GCSqGSIb3DQEBAQUABIICAF4tE5BfALbvmmeGlc8/EzNp0Xt3
# FAgHV4NT/xuYd2QTY6F7MSViBeBg19VguQIXeQCejCvuoVuqEvZucIfBea2H56e1
# vqgi+Cv5du3vbGGFPGL8N+ruqipfnLW/4HjNYrjX00YqMcFSKwOoeWiblG2j9iFg
# PzUQqFjSPvIbnyWNTp5dDuej9qgvEoU5RcgbnEiUsx3EhgtaybPQeSoT6dMDuigs
# i9adW/vZneg/VYkeGJPOqjbG65Nl4NcTOFEM+Bb2Pj0jYJB2uh2GTboPZjPBjV+7
# a8sYLr3AQLIP340B24Kdbedqhe2AkqVTFFPlI0w0YMAEiFlWVhHDi+VnDGK1Ey12
# tOLSfr763UtXaj8Jpsrl5heNoz6GOkULlmPPHMMM8Mq+et/twYlB7/E0zfdEXESa
# IhwnSnOfRzp9EL724qIZ1enR54GRF64/7ETK9Ebl5xoQLCJXudbb6+1WZ1AVA1hD
# d9Fxn4FiqtrkcGBlXw1m/HMIXQB7/XemyPOvw0RjIG92c/22tF4gyiLQkq6yYtk5
# 6ZRYkQ1MesQH8c6P7Lp8KV8dwVwUZoC0B3RSkD3IR0rJFPVGmDD/gf9cLaUWJoJ8
# XdlcRngoRNNQcWDtyIe+XneSiR+rBi1vqfbyyVROtavWlBYZBwTfRHPQhPgmljbq
# oIdJpVNdylfHevLmoYIWzTCCFskGCisGAQQBgjcDAwExgha5MIIWtQYJKoZIhvcN
# AQcCoIIWpjCCFqICAQMxDTALBglghkgBZQMEAgEwgegGCyqGSIb3DQEJEAEEoIHY
# BIHVMIHSAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQCAQUABCBt+UdXPBSH
# QvJM7JWaOiTOVVzqqbWRUp/0qXSVjEmcCQIUUo/aup8idK17EDP7IVJWTSS8BU0Y
# DzIwMjUwMjE2MTU1ODU2WjADAgEBoGGkXzBdMQswCQYDVQQGEwJCRTEZMBcGA1UE
# CgwQR2xvYmFsU2lnbiBudi1zYTEzMDEGA1UEAwwqR2xvYmFsc2lnbiBUU0EgZm9y
# IENvZGVTaWduMSAtIFI2IC0gMjAyMzExoIISVDCCBmwwggRUoAMCAQICEAGb6t7I
# TWuP92w6ny4BJBYwDQYJKoZIhvcNAQELBQAwWzELMAkGA1UEBhMCQkUxGTAXBgNV
# BAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0
# YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjMxMTA3MTcxMzQwWhcNMzQxMjA5
# MTcxMzQwWjBdMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1z
# YTEzMDEGA1UEAwwqR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2IC0g
# MjAyMzExMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA6oQ3UGg8lYW1
# SFRxl/OEcsmdgNMI3Fm7v8tNkGlHieUs2PGoan5gN0lzm7iYsxTg74yTcCC19SvX
# ZgV1P3qEUKlSD+DW52/UHDUu4C8pJKOOdyUn4LjzfWR1DJpC5cad4tiHc4vvoI2X
# fhagxLJGz2DGzw+BUIDdT+nkRqI0pz4Yx2u0tvu+2qlWfn+cXTY9YzQhS8jSoxMa
# Pi9RaHX5f/xwhBFlMxKzRmUohKAzwJKd7bgfiWPQHnssW7AE9L1yY86wMSEBAmpy
# siIs7+sqOxDV8Zr0JqIs/FMBBHkjaVHTXb5zhMubg4htINIgzoGraiJLeZBC5oJC
# rwPr1NDag3rDLUjxzUWRtxFB3RfvQPwSorLAWapUl05tw3rdhobUOzdHOOgDPDG/
# TDN7Q+zw0P9lpp+YPdLGulkibBBYEcUEzOiimLAdM9DzlR347XG0C0HVZHmivGAu
# w3rJ3nA3EhY+Ao9dOBGwBIlni6UtINu41vWc9Q+8iL8nLMP5IKLBAgMBAAGjggGo
# MIIBpDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYD
# VR0OBBYEFPlOq764+Fv/wscD9EHunPjWdH0/MFYGA1UdIARPME0wCAYGZ4EMAQQC
# MEEGCSsGAQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxz
# aWduLmNvbS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSB
# gzCBgDA5BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2Ev
# Z3N0c2FjYXNoYTM4NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2Jh
# bHNpZ24uY29tL2NhY2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaA
# FOoWxmnn48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9j
# cmwuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG
# 9w0BAQsFAAOCAgEAlfRnz5OaQ5KDF3bWIFW8if/kX7LlFRq3lxFALgBBvsU/JKAb
# RwczBEy0tGL/xu7TDMI0oJRcN5jrRPhf+CcKAr4e0SQdI8svHKsnerOpxS8M5OWQ
# 8BUkHqMVGfjvg+hPu2ieI299PQ1xcGEyfEZu8o/RnOhDTfqD4f/E4D7+3lffBmvz
# agaBaKsMfCr3j0L/wHNp2xynFk8mGVhz7ZRe5BqiEIIHMjvKnr/dOXXUvItUP35Q
# lTSfkjkkUxiDUNRbL2a0e/5bKesexQX9oz37obDzK3kPsUusw6PZo9wsnCsjlvZ6
# KrutxVe2hLZjs2CYEezG1mZvIoMcilgD9I/snE7Q3+7OYSHTtZVUSTshUT2hI4WS
# wlvyepSEmAqPJFYiigT6tJqJSDX4b+uBhhFTwJN7OrTUNMxi1jVhjqZQ+4h0Htcx
# NSEeEb+ro2RTjlTic2ak+2Zj4TfJxGv7KzOLEcN0kIGDyE+Gyt1Kl9t+kFAloWHs
# hps2UgfLPmJV7DOm5bga+t0kLgz5MokxajWV/vbR/xeKriMJKyGuYu737jfnsMmz
# Fe12mrf95/7haN5EwQp04ZXIV/sU6x5a35Z1xWUZ9/TVjSGvY7br9OIXRp+31wdu
# ap0r/unScU7Svk9i00nWYF9A43aZIETYSlyzXRrZ4qq/TVkAF55gZzpHEqAwggZZ
# MIIEQaADAgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNV
# BAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWdu
# MRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAw
# MDAwMFowWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOv
# dYNfqUdSx2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt
# 0ShKwSy7uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHP
# vIo7bmrEiPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFU
# UweLmW64VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16
# ZevRVqkuvftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS
# 2SU07Zbv+GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm1
# 9m1W/oodCT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIG
# bxsY1TbqZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMD
# Ad6ZJflxbumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/Miy
# Tdtk8EWfusE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9
# GbCX6oxQkW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGG
# MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDD
# vWWWMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEB
# BDIwMDAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jv
# b3RyNjA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29t
# L3Jvb3QtcjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZo
# dHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0B
# AQwFAAOCAgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYW
# axlASSUIHuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCy
# z+zCVmUdvX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQ
# cXZw0g+W8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0
# Wn1yhjWzAlcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59e
# odaZzul9S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8
# oMWsr1EG8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1
# If5iEO0dMPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbcl
# IA4bUaDUY6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2M
# tnHtUiH+PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB
# +SXiLBB+gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIID
# a6ADAgECAg5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQL
# ExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjET
# MBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAw
# MDBaMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQK
# EwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4
# QZIzFKRvf+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTe
# c5RO86eJf094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWy
# ZtWQmrcxBsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7tt
# U+JIfIwQBzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrK
# otudCd5dRC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKF
# t3OiuDWqRfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTfl
# puwhCHX85mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2Fm
# CWqxBjplllnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5
# paHYgw/R/98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4O
# hxlcVLFltr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwo
# TK8CAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYD
# VR0OBBYEFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki
# 5+LXHNbH8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnm
# XNCE3tytok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJE
# lrSVXsB7jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMp
# mY4w06wh4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6
# JV2NoTFR3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG
# 7cKTBYn6fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/
# gsge/lgbKCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324G
# abbeCglIWYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5
# MCMHTI8Qv4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO7
# 7oHl2l98i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4st
# Q1LrRgyU4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjx
# guhFPmzWAtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAGb6t7ITWuP92w6ny4BJBYwCwYJ
# YIZIAWUDBAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZI
# hvcNAQk0MR4wHDALBglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcN
# AQkEMSIEILMWZq4x9mGCm64/eKNADcUvi+OI3IW44wop98miUjU5MIGwBgsqhkiG
# 9w0BCRACLzGBoDCBnTCBmjCBlwQgOoh6lRteuSpe4U9su3aCN6VF0BBb8EURveJf
# gqkW0egwczBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24g
# bnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hB
# Mzg0IC0gRzQCEAGb6t7ITWuP92w6ny4BJBYwDQYJKoZIhvcNAQELBQAEggGAxKg9
# fPRR7QrWpkC7hj2u4EgC5u2MUkbCecOWv0EUIuuC1KVFbIsewaDDU45opCvwOiIf
# ReTdTdE0J7lBPzdMMpQ9pny1iyPrOmC8Modeg6SQqZhd6g5M7VhkBRiJV1HHjJrA
# 3yYhA5surEeWvNg/l5zcKN3CwhDui/yhVMEsoqhl7ojcHNJDSSIzwx8BZHqdJq7y
# 6C9aVCI7DPB8NYVrsfKll/524P3qr830aisUdmoqo/hw0Lg36jZ5Us5xU5YcseVF
# SyAVupISijgpvttDYsI9ofVcEwc8Bn5FrdGRO4ztQHqutow4qTcnvyFzC8dTmMbn
# 4F+gOdFD8mETTvtf4QGJQcF2DkROgT05KrIJ9AETsiFBih1g9QUMBwdSyfr3Tldy
# RnuzK+kWON5vcZ/K8hB6y0gX9Ek1TexEeAHsW2nR/MdbHWNhO/NScdA9iwpqQG15
# WcHS7z0Lw9rb49imUrhmD6qjKu3aC/w/FX1qxLQ8BJXB/net7dHJ/qmMuavC
# SIG # End signature block
