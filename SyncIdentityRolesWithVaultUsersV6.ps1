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
[int]$scriptVersion = 6

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

$global:nextRefreshTime = $null
function Refresh-Token {
    # Check if the token refresh is needed based on the next scheduled refresh time
    if ([DateTime]::Now -ge $global:nextRefreshTime -or -not $global:logonheader) {
        
        # Perform login to get a new token
        if ($ForceAuthType) {
            $global:logonheader = Authenticate-Platform -platformURLs $platformURLs -creds $Credentials -ForceAuthType $ForceAuthType
        } else {
            $global:logonheader = Authenticate-Platform -platformURLs $platformURLs -creds $Credentials
        }

        if (-not($logonheader.Authorization)) {
            Write-Host "Failed to get Token, exiting..."
            Exit
        }

        # Set the next refresh time
        $global:nextRefreshTime = [DateTime]::Now.AddMinutes(10)
        Start-Sleep 1  

        Write-LogMessage -type Info -MSG "Token refreshed at $([DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss')). Next refresh scheduled for $($nextRefreshTime.ToString('yyyy-MM-dd HH:mm:ss'))."
    }
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
Refresh-Token

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
                    Refresh-Token
        
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
            Refresh-Token
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
            Refresh-Token
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
                Refresh-Token
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
                    Refresh-Token
                    Write-LogMessage -type Info -MSG "Reloading rights for User: $($identityUser.username)" -early
                    Try{
                        Refresh-Token
                        $respreloaduser = Invoke-RestMethod -Method Post -Uri "$IdentityAPIURL/CDirectoryService/RefreshToken?id=$($identityUser.ID)" -ContentType "application/json" -Headers $logonheader -Body $body -ErrorVariable identityErr
                    }Catch{
                        Write-LogMessage -Type Error -Msg "Error: $(Collect-ExceptionMessage $identityErr.message + $_.exception.status + $_.exception.Response.ResponseUri.AbsoluteUri $identityErr)"
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
                    Refresh-Token
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
                            Groups   = ($matchingRoles -join ", ") # Join matching roles with commas
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