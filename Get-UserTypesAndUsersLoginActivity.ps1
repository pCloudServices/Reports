<#
.SYNOPSIS
    Privilege Cloud License Capacity User Report
.DESCRIPTION
    This PowerShell script generates a comprehensive report of users consuming resources in the Privilege Cloud for a given tenant URL. The report includes information about users of different types and their last login dates. Additionally, it identifies users who have been inactive for more than a specified number of days.
.PARAMETER PortalURL
    Specifies the URL of the Privilege Cloud tenant.
    Example: https://<subdomain>.cyberark.cloud
.PARAMETER InactiveDays
    Specifies the number of days to consider users as inactive.
    Default value: 60
.PARAMETER ExportToCSV
    Specifies whether to export the results to a CSV file or print them in PowerShell.
    If this switch is specified, the results will be exported to a CSV file.
.PARAMETER GetSpecificUserTypes
    Specifies the user types you want to get a report on.
    Default values: EPVUser, EPVUserLite, BasicUser, ExtUser, CPM, PSM, AppProvider
.PARAMETER ReportType
    Specifies the type of report to generate.
    Valid values are 'CapacityReport' and 'DetailedReport'.
    Default value: CapacityReport
.EXAMPLE
    .\PrivilegeCloudConsumedUserReport.ps1 -PortalURL "https://<subdomain>.cyberark.cloud" -AuthType "cyberark" -InactiveDays 90 -ExportToCSV -GetSpecificUserTypes EPVUser, BasicUser -ReportType DetailedReport
    Generates a detailed report for EPVUser and BasicUser types in the Privilege Cloud, considering users inactive if their last login date is older than 90 days. The results will be exported to a CSV file.
#>
param(
    [Parameter(Mandatory = $true, HelpMessage = "Specify the URL of the Privilege Cloud tenant (e.g., https://<subdomain>.cyberark.cloud)")]
    [string]$PortalURL,
    [Parameter(Mandatory = $false, HelpMessage = "Specify the number of days to consider users as inactive.")]
    [int]$InactiveDays = 60,
    [switch]$ExportToCSV,
    [Parameter(Mandatory=$false, HelpMessage="Specify the UserTypes you want to get a report on.")]
    [ValidateSet("EPVUser", "EPVUserLite", "BasicUser", "ExtUser", "BizUser", "AIMAccount", "AppProvider", "CCP", "CCPEndpoints", "CPM", "PSM")]
    [string[]]$GetSpecificuserTypes = @("EPVUser", "EPVUserLite", "BasicUser", "ExtUser", "BizUser", "AIMAccount", "AppProvider", "CCP", "CCPEndpoints", "CPM", "PSM"),
    [Parameter(Mandatory = $false, HelpMessage = "Specify the type of report to generate. Valid values are 'CapacityReport' and 'DetailedReport'.")]
    [ValidateSet("DetailedReport", "CapacityReport")]
    [string]$ReportType,
    [Parameter(Mandatory = $true, HelpMessage = "Specify a User with the relevant permissions. See readme if you need help.")]
    [PSCredential]$Credentials,
    [ValidateSet("cyberark","identity")]
    [string]$ForceAuthType
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
$global:LOG_FILE_PATH = "$ScriptLocation\_Get-UserTypesAndUsersLoginActivity.log"

[int]$scriptVersion = 10

# PS Window title
$Host.UI.RawUI.WindowTitle = "Privilege Cloud License Capacity User Report"

## Force Output to be UTF8 (for OS with different languages)
$OutputEncoding = [Console]::InputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding

if ($ExportToCSV.IsPresent) {
    $global:ExportDir = "$ScriptLocation\$(Get-Date -Format 'yyyyMMdd_HH-mm')"
    if (!(Test-Path -Path $global:ExportDir)) {
        New-Item -ItemType Directory -Path $global:ExportDir | Out-Null
    }
}



Function CalcLicenseInfo() {
    param(
        [string]$licenseInfo
    )
    
$formats = @(
    "M/d/yyyy h:mm:ss tt",    # NA
    "MM/dd/yyyy hh:mm:ss tt", # NA with leading zeros
    "d/M/yyyy HH:mm:ss",      # EU STD without leading zeros
    "dd/M/yyyy HH:mm:ss",     # EU STD with/without leading zeros
    "dd/MM/yyyy HH:mm:ss",    # EU STD with leading zeros
    "dd-MM-yyyy HH:mm:ss",    # India
    "yyyy/MM/dd HH:mm:ss",    # East Asia (Japan, China, Korea)
    "yyyy-MM-dd HH:mm:ss",    # ISO 8601
    "dd.MM.yyyy HH:mm:ss",    # Central Europe (Germany, Austria, Switzerland, Russia)
    "d.M.yyyy H:mm:ss",       # Short format without leading zeros (Some parts of Europe)
    "dd/MM/yyyy h:mm:ss tt",  # UK, Ireland, Australia
    "MM-dd-yyyy HH:mm:ss",    # Philippines
    "yyyyMMdd HH:mm:ss",      # Compact form
    "d/M/yyyy h:mm:ss tt",    # Short format without leading zeros
    "M-d-yyyy hh:mm:ss tt",   # Variations with dash separator
    "d-M-yyyy HH:mm:ss",      # Variations with/without leading zeros and 24-hour format
    "d/MM/yyyy h:mm tt",      # Without seconds
    "M/dd/yyyy HH:mm:ss",     # Variations with/without leading zeros and 24-hour format
    "MM/dd/yyyy H:mm:ss",     # Variations with leading zeros and 24-hour format
    "d-M-yyyy hh:mm:ss tt",   # 12-hour format variations with/without leading zeros
    "MM-d-yyyy hh:mm:ss tt",  # 12-hour format variations with leading zeros
    "M.d.yyyy hh:mm:ss tt",   # Dot separator variations
    "dd.MM.yyyy h:mm:ss tt",  # Dot separator variations with leading zeros
    "MM.dd.yyyy HH:mm:ss",    # Dot separator variations with 24-hour format
    "d.M.yyyy HH:mm:ss",      # 24-hour format variations with/without leading zeros
    "yyyy.MM.dd HH:mm:ss",    # ISO variations with dot separator
    "yyyy-MM.dd HH:mm:ss tt", # ISO variations with mixed separators
    "yyyy/MM.dd hh:mm:ss tt" # ISO variations with mixed separators and 12-hour format

)


    # Get the current culture of the system
	$currentCulture = [System.Globalization.CultureInfo]::CurrentCulture

	# Check if the current culture is any variation of English
	if ($currentCulture.TwoLetterISOLanguageName -like "en*") {
		# If it's any variation of English, use the InvariantCulture
		$provider = [System.Globalization.CultureInfo]::InvariantCulture
	} else {
		# If it's not any variation of English, use the current culture
		$provider = $currentCulture
	}

    $parsedSuccessfully = $false
    foreach ($format in $formats) {
        try {
            $licenseExpirationDate = [DateTime]::ParseExact($licenseInfo, $format, $provider)
            $parsedSuccessfully = $true
            break
        } catch {
            # Do nothing; just try the next format
        }
    }

    if (-not $parsedSuccessfully) {
        Write-Error "Failed to parse date: $licenseInfo"
        return
    }

    # Convert to local time
    $global:licenseExpirationDateLocal = $licenseExpirationDate.ToLocalTime()

    # Calculate the difference in days between the current date and the license expiration date
    $currentDate = Get-Date
    $daysToExpiration = ($licenseExpirationDateLocal - $currentDate).Days
    
    # Set the color based on the number of days to expiration
    $global:lessThanXDays = ""
    $global:Alertcolor = "Green"
    if ($daysToExpiration -le 30) {
        $global:Alertcolor = "Yellow"
        $global:lessThanXDays = "Less than $daysToExpiration days remaining!"
    }
    if ($daysToExpiration -le 15) {
        $global:Alertcolor = "Red"
        $global:lessThanXDays = "Less than $daysToExpiration days remaining!"
    }   
}




Function Get-LicenseCapacityReport(){
param(
 [string]$vaultIp,
 [string[]]$GetSpecificuserTypes
)
$VaultOperationFolderInside = "$PSScriptRoot\VaultOperationsTester"
$VaultOperationFolderOneUp = "$(Split-Path $PSScriptRoot)\VaultOperationsTester"
$VaultOperationFolderTwoUp = "$(Split-Path (Split-Path $PSScriptRoot))\VaultOperationsTester"


if (Test-Path -Path "$VaultOperationFolderInside\VaultOperationsTester.exe") {
    $VaultOperationFolder = $VaultOperationFolderInside
} elseif (Test-Path -Path "$VaultOperationFolderOneUp\VaultOperationsTester.exe") {
    $VaultOperationFolder = $VaultOperationFolderOneUp
} elseif (Test-Path -Path "$VaultOperationFolderTwoUp\VaultOperationsTester.exe") {
    $VaultOperationFolder = $VaultOperationFolderTwoUp
} else {
    Write-Host "Required file 'VaultOperationsTester.exe' doesn't exist in expected folders: `n- `"$VaultOperationFolderInside`" `n- `"$VaultOperationFolderOneUp`" `n- `"$VaultOperationFolderTwoUp`". Make sure you get the latest version and extract it correctly from zip." -ForegroundColor Red
    Pause
    Return
}

$stdoutFile = "$VaultOperationFolder\Log\stdout.log"
$LOG_FILE_PATH_CasosArchive = "$VaultOperationFolder\Log\old"

$specificUserTypesString = $GetSpecificuserTypes -join ','

        $redistributables = @(
            #@{ Name = "Microsoft Visual C++ 2013 x86*"; Path = "$VaultOperationFolder\vcredist_x86.exe" }, #2013 obsolete
            @{ Name = "Microsoft Visual C++ 2022 X86*"; Path = "$VaultOperationFolder\vc_redist.x86.exe" }, #2015-2022 86bit
            @{ Name = "Microsoft Visual C++ 2022 X64*"; Path = "$VaultOperationFolder\vc_redist.x64.exe" } #2015-2022 64bit
        )
        
        # Loop through each redistributable and check if it's installed
        foreach ($redis in $redistributables) {
            if ((Get-CimInstance -Class win32_product | where {$_.Name -like $redis.Name}) -eq $null) {
                Write-LogMessage -type Info -MSG "Installing Redis++ from $($redis.Path)..." -Early
                Start-Process -FilePath $redis.Path -ArgumentList "/install /passive /norestart" -Wait
            }
        }              
        #Cleanup log file if it gets too big
        if (Test-Path $LOG_FILE_PATH_CasosArchive)
        {
            if (Get-ChildItem $LOG_FILE_PATH_CasosArchive | measure -Property length -Sum | where { $_.sum -gt 5MB })
            {
                Write-Host "Archive log folder is getting too big, deleting it." -ForegroundColor Gray
                write-host "Deleting $LOG_FILE_PATH_CasosArchive"  -ForegroundColor Gray
                Remove-Item $LOG_FILE_PATH_CasosArchive -Recurse -Force
            }
        }
        
        #create log file
        New-Item -Path $stdoutFile -Force | Out-Null


        $process = Start-Process -FilePath "$VaultOperationFolder\VaultOperationsTester.exe" -ArgumentList "$($Credentials.UserName) $($Credentials.GetNetworkCredential().Password) $VaultIP GetLicense $specificUserTypesString" -WorkingDirectory "$VaultOperationFolder" -NoNewWindow -PassThru -Wait -RedirectStandardOutput $stdoutFile
        #$Credentials = $null
        $stdout = (gc $stdoutFile)
            if($process.ExitCode -ne 0){
                Write-Host "-----------------------------------------"
                $stdout | Select-String -Pattern 'Extra details' -NotMatch | Write-Host -ForegroundColor red
                Write-Host "$($stdout | Select-String -Pattern 'Extra details')" -ForegroundColor Red
                Write-Host "Failed" -ForegroundColor Red
                Write-Host "-----------------------------------------"
                Write-Host "More detailed log can be found here: $VaultOperationFolder\Log\Casos.Error.log"
            }
            Else{
                $usersInfo = @()
                $currentUserInfo = $null
                
                # extract information for each user
                foreach ($line in $stdout) {
                    $trimmedLine = $line.Trim()
                    
                    if ($trimmedLine -eq "Connecting to the vault...") {
                        # Reset the user information when we find the start marker
                        $currentUserInfo = @{
                            "Name" = $null
                            "UserType Description" = $null
                            "Licensed Users" = $null
                            "Existing Users" = $null
                            "Currently Logged On Users" = $null
                        }
                    }
                    elseif ($trimmedLine.StartsWith("Name: ")) {
                        $currentUserInfo["Name"] = $trimmedLine -replace "Name: "
                    }
                    elseif ($trimmedLine.StartsWith("UserType Description: ")) {
                        $currentUserInfo["UserType Description"] = $trimmedLine -replace "UserType Description: "
                    }
                    elseif ($trimmedLine.StartsWith("Licensed Users: ")) {
                        $currentUserInfo["Licensed Users"] = $trimmedLine -replace "Licensed Users: "
                    }
                    elseif ($trimmedLine.StartsWith("Existing Users: ")) {
                        $currentUserInfo["Existing Users"] = $trimmedLine -replace "Existing Users: "
                    }
                    elseif ($trimmedLine.StartsWith("Currently Logged On Users: ")) {
                        $currentUserInfo["Currently Logged On Users"] = $trimmedLine -replace "Currently Logged On Users: "
                        # Once we have all the required information, add the user object to the array
                        $usersInfo += New-Object PSObject -Property $currentUserInfo
                    }
                    elseif ($trimmedLine.StartsWith("License Expiration Date: ")) {
                        $licenseInfo = $trimmedLine -replace "License Expiration Date: "
                    }
                }
                
                # Output
                CalcLicenseInfo -licenseInfo $licenseInfo
                Write-Host "License Expiration Date: $licenseExpirationDateLocal $lessThanXDays" -ForegroundColor $Alertcolor
                $usersInfo | Select-Object Name, "UserType Description", "Licensed Users", "Existing Users", "Currently Logged On Users" | Format-Table -AutoSize | Out-Host
                Write-Host "-------------------------------------------------------------"
                # Export the results to a CSV file
                # If ExportToCSV flag not present, offer it via popup as reminder
                if (-Not $ExportToCSV.IsPresent) {
                    $ExportCSVChoice = Get-Choice -Title "Export Results to CSV" -Options "Yes","No" -DefaultChoice 2

                    if ($ExportCSVChoice -eq "Yes") {
                        $csvFilePath = "$ExportDir\LicenseCapacityReport.csv"
                        $usersInfo | Select-Object Name, "UserType Description", "Licensed Users", "Existing Users", "Currently Logged On Users" | Export-Csv -Path $csvFilePath -NoTypeInformation -Force
                        Write-Host "Results exported to $csvFilePath" -ForegroundColor Cyan
                        # Write license info to a text file
                        $licenseFilePath = "$ExportDir\LicenseExpirationDate.txt"
                        "License Expiration Date: $licenseExpirationDateLocal" | Out-File $licenseFilePath -Force
                        Write-Host "License exported to $licenseFilePath" -ForegroundColor Cyan
                    }
                }
                # otherwise flag present, we export to csv.
                else {
                    $csvFilePath = "$ExportDir\LicenseCapacityReport.csv"
                    $usersInfo | Select-Object Name, "UserType Description", "Licensed Users", "Existing Users", "Currently Logged On Users" | Export-Csv -Path $csvFilePath -NoTypeInformation -Force
                    Write-Host "Results exported to $csvFilePath" -ForegroundColor Cyan
                    # Write license info to a text file
                    $licenseFilePath = "$ExportDir\LicenseExpirationDate.txt"
                    "License Expiration Date: $licenseExpirationDateLocal" | Out-File $licenseFilePath -Force
                    Write-Host "License exported to $licenseFilePath" -ForegroundColor Cyan
                }

                Write-Host "To get more detailed report rerun the script with '-ReportType DetailedReport' flag." -ForegroundColor Magenta
            }
}



function Get-UserType {
    param (
        [string[]]$UserType,
        [string]$URLAPI
    )

    $uri = "$URLAPI/Users?UserType=$UserType"
    $retryCount = 0
    $success = $false

    while (-not $success -and $retryCount -lt 3) {
        try {
            Refresh-Token -PlatformURLs $platformURLs -creds $Credentials -ForceAuthType $ForceAuthType

            # Initial API call to get user type information
            $response = Invoke-RestMethod -Uri $uri -Headers $logonheader -Method GET -UseBasicParsing
            $success = $true  # Exit retry loop if initial call is successful

            Write-Host ""
            Write-Host "$UserType = $($response.Total)" -ForegroundColor Green

            if ($response.Total -ge 1) {
                Write-Host "----------Start $UserType-----------------"

                $userInformation = @()  # Array to store user information

                # Loop through each user, with token refresh and retry logic inside
                foreach ($user in $response.Users.id) {
                    $userSuccess = $false
                    $userRetryCount = 0

                    while (-not $userSuccess -and $userRetryCount -lt 3) {
                        try {
                            # Refresh the token if needed before each user-specific call
                            Refresh-Token -PlatformURLs $platformURLs -creds $Credentials -ForceAuthType $ForceAuthType
                            Start-Sleep -Milliseconds 70

                            # API call to retrieve individual user details
                            $UserResponse = Invoke-RestMethod -Uri "$URLAPI/Users/$user" -Headers $logonheader
                            $lastLoginDate = [DateTimeOffset]::FromUnixTimeSeconds($UserResponse.lastSuccessfulLoginDate).ToLocalTime()

                            # Calculate inactivity period
                            $daysSinceLastLogin = (Get-Date) - $lastLoginDate.DateTime
                            $inactive = $daysSinceLastLogin.TotalDays -gt $InactiveDays

                            $userObject = [PSCustomObject]@{
                                UserName       = $UserResponse.Username
                                LastLoginDate  = $lastLoginDate.ToString()
                                "Inactive for $($InactiveDays) Days" = $inactive
                            }

                            # Save user information for CSV export if needed
                            $userInformation += $userObject

                            # Print user info based on inactivity status
                            if ($inactive) {
                                Write-Host "UserName: $($UserResponse.Username) LastLoginDate: $($lastLoginDate.ToString())" -ForegroundColor Yellow
                            } else {
                                Write-Host "UserName: $($UserResponse.Username) LastLoginDate: $($lastLoginDate.ToString())" -ForegroundColor Gray
                            }

                            # If successful, set flag to exit inner retry loop
                            $userSuccess = $true

                        } catch {
                            # Handle 401 Unauthorized error for individual user call
                            if ($_.Exception.Response.StatusCode -eq 401) {
                                Write-Host "401 Unauthorized error encountered for userID $($user). Refreshing token and retrying..." -ForegroundColor Yellow
                                Refresh-Token -PlatformURLs $platformURLs -creds $Credentials -ForceAuthType $ForceAuthType
                                $userRetryCount++
                            } else {
                                # if error "(400) Bad Request" means the userType didn't exist, that's ok, many licences are different, we can ignore this.
                                Write-Host "Error fetching details for userID $($user) $($_.Exception.Message) $($_.ErrorDetails.Message) $($_.Exception.Status)" -ForegroundColor Red
                                $userSuccess = $true  # Exit loop to avoid endless retry on non-401 errors
                            }
                        }
                    }

                    # If max retries reached for user, log and continue to next user
                    if (-not $userSuccess) {
                        Write-Host "Max retries reached for user $user. Moving to the next user..." -ForegroundColor Red
                    }
                }

                Write-Host "----------End $UserType-----------------"
                # Export results to CSV
                if ($ExportToCSV.IsPresent) {
                    $csvFilePath = "$ExportDir\$UserType-UsersReport.csv"
                    $userInformation | Export-Csv -Path $csvFilePath -NoTypeInformation -Force
                    Write-Host "Results exported to $csvFilePath" -ForegroundColor Cyan  
                }
            }

        } catch {
            # if error "(400) Bad Request" means the userType didn't exist, that's ok, many licences are different, we can ignore this.
            if ($_.Exception.Message -like "*(400) Bad Request*") {
                $response = [PSCustomObject]@{ Total = 0 }
                $success = $true  # Exit outer retry loop
            }
            # Handle 401 Unauthorized error for initial user type call
            elseif ($_.Exception.Response.StatusCode -eq 401) {
                Write-Host "401 Unauthorized error encountered. Refreshing token and retrying..." -ForegroundColor Yellow
                Refresh-Token -PlatformURLs $platformURLs -creds $Credentials -ForceAuthType $ForceAuthType
                $retryCount++
            } else {
                # Log and ignore other errors, proceed with the next type if needed
                Write-Host "Error fetching user type details: $($_.Exception.Message) $($_.ErrorDetails.Message) $($_.Exception.Status)" -ForegroundColor Red
                $success = $true  # Exit loop to avoid endless retry on non-401 errors
            }
        }
    }

    # If max retries reached for user type, log an error
    if (-not $success) {
        Write-Host "Max retries reached for $UserType. Moving to the next user type..." -ForegroundColor Red
    }
}


# Main
try {
	write-Host "Script Version: $scriptVersion" -ForegroundColor Gray


    # Build PVWA Urls
    $platformURLs = DetermineTenantTypeURLs -PortalURL $PortalURL
    $IdentityAPIURL = $platformURLs.IdentityURL
    $pvwaAPI = $platformURLs.PVWA_API_URLs.PVWAAPI
    $VaultURL = $platformURLs.vaultURL    
    $global:AlreadyAnswered = $false

    # if reportType flag was not called
    if([string]::IsNullOrEmpty($ReportType)){
        $SelectOption = Get-Choice -Title "Choose Report Type" -Options "License Capacity Report","Detailed User Report" -DefaultChoice 1
        if($SelectOption -like "*Detailed*"){
            $script:ReportType = "DetailedReport"
        }Else{
            $script:ReportType = "CapacityReport"
        }
    }


    If($ReportType -eq "DetailedReport"){
        # Login
        Refresh-Token -PlatformURLs $platformURLs -creds $Credentials -ForceAuthType $ForceAuthType
       
        Write-Host ""
        Write-Host "Privilege Cloud consumed users report for tenant $PortalURL"
        Write-Host "-----------------------------------------------------------------------"

        Write-Host "Yellow Users = Inactive for more than $($InactiveDays) days" -ForegroundColor Black -BackgroundColor Yellow
        foreach ($userType in $GetSpecificuserTypes) {
            Get-UserType -UserType $userType -URLAPI $pvwaAPI
        }
    }
    Else
    {
        # Login
        $ForceAuthType = "cyberark"
        Refresh-Token -PlatformURLs $platformURLs -creds $Credentials -ForceAuthType $ForceAuthType

        
        Write-Host "Privilege Cloud Capacity report for tenant $PortalURL"
        Write-Host "-----------------------------------------------------------------------"
        
        Get-LicenseCapacityReport -vaultIp $VaultURL -GetSpecificuserTypes $GetSpecificuserTypes
    }

} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Error Details: $($_.ErrorDetails.Message)" -ForegroundColor Red
    Write-Host "Exiting..."
}
Finally{
        # logoff
        $Credentials = $null
        Try{Invoke-RestMethod -Uri $($platformURLs.PVWA_API_URLs.Logoff) -Method Post -Headers $logonHeader | Out-Null}Catch{}
}
#### Script End ####
# SIG # Begin signature block
# MIIpEwYJKoZIhvcNAQcCoIIpBDCCKQACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAVFUvkb3qS7GSK
# bWcxAsSLUtlBCwmhgYg6oVPuCwl3gaCCDpUwggboMIIE0KADAgECAhB3vQ4Ft1kL
# th1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAwMDBaMFwx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQD
# EylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj/SBerjgS
# i8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlMg7BKRFAE
# eIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRVX5YLEeWa
# tSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV0xHK5s2z
# BZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEzIHXMsdXt
# HQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMkoog28vmf
# vpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq7rfYrWGl
# r3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult5a/dm2tj
# IF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNutwFsDeCX
# pxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYyAjIwfLWT
# yCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofnGrhO7izB
# 36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUJZ3Q
# /FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0Q9lWULvO
# ljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5n
# bG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUHMAKGOmh0
# dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWduaW5ncm9v
# dHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxzaWdu
# LmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJKwYBBAGg
# MgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3Jl
# cG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJyTm6t6E5
# iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbVYQLFY4/U
# ovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQtpFg6bBNJ
# +KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSXhndGKj0j
# fShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6bs+XYXvf
# cXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nOZNm9/Lws
# 80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOHX5OKSBoR
# HeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dqcYC/lt5y
# A9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0ixxnJpsoO
# qHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7qWPLd0jV
# +mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72f1LiSY25
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB6UwggWNoAMCAQICDAJZP4AHVQPEmDE5
# fjANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjQwMzA0MTM1NzE4WhcNMjYwMzA1MTM1NzE4WjCB
# 6zEdMBsGA1UEDwwUUHJpdmF0ZSBPcmdhbml6YXRpb24xEjAQBgNVBAUTCTUxMjI5
# MTY0MjETMBEGCysGAQQBgjc8AgEDEwJJTDELMAkGA1UEBhMCSUwxGTAXBgNVBAgT
# EENlbnRyYWwgRGlzdHJpY3QxFDASBgNVBAcTC1BldGFoIFRpa3ZhMR8wHQYDVQQK
# ExZDeWJlckFyayBTb2Z0d2FyZSBMdGQuMR8wHQYDVQQDExZDeWJlckFyayBTb2Z0
# d2FyZSBMdGQuMSEwHwYJKoZIhvcNAQkBFhJhZG1pbkBjeWJlcmFyay5jb20wggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCW/EphpbQKOtU69jouawb8wLcd
# 1OFl4mjU/IwWs/F50xD/XtpkocmEjb5eQmzWDLjFjyaQc4+9lKZVmh5BJiH5O/4K
# Zh07tYcD/zWw1+ASFu9M/46znESl0Wu9T743zWm/8MNI21Z7GiXocpk3ca81IOsp
# PNVU/qyMMgU67gK2l48ywRVLposh2oQcU2oGofzk3GvfQ1Ej4/HfUaT0U45V+uMj
# +XyNo6QZcfCYQiv9TLqwhVzD/PDvo2IMDk153Vt7y4/PKi4eimip0a/sWoNQV8aD
# +iOF6qgBKdQ34l7nPWeAic1EnkOiBMPlukrmBxOo6qX3OOpoxByG8iQKCt2ZsJE1
# Jfg6r/p+idbbFnRMd4jGxG4byA3cVxBWupE+qcZabqtcWcIjmWIFksvRqFCHZFZj
# 9KLy46c1I5jG6G99jr8jOJYxupmLBvWo4VwAxAm10rAn2473+axyExaKtqR5DP1H
# 8kjmUoEtto2v/l2XK0SpxIfNYEYvbp0uRw5d6SmWEyp4q5kvFxRsL7R3rJcgxtll
# lHiFBfo9M5s/aNqwbKyvf5c3QjLI9xADuDdaYIYc5HDolgnDdyjzpefSDEljmAmB
# BqRYwDe5/dhCDgn8yoZ0gOWbAxyGHj+BA35G6dge2sHsD3WHV4xNXtF4A2v6n8Y6
# dD0qufDn1Q8C/zZzuQIDAQABo4IB1TCCAdEwDgYDVR0PAQH/BAQDAgeAMIGfBggr
# BgEFBQcBAQSBkjCBjzBMBggrBgEFBQcwAoZAaHR0cDovL3NlY3VyZS5nbG9iYWxz
# aWduLmNvbS9jYWNlcnQvZ3NnY2NyNDVldmNvZGVzaWduY2EyMDIwLmNydDA/Bggr
# BgEFBQcwAYYzaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVldmNv
# ZGVzaWduY2EyMDIwMFUGA1UdIAROMEwwQQYJKwYBBAGgMgECMDQwMgYIKwYBBQUH
# AgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAcGBWeB
# DAEDMAkGA1UdEwQCMAAwRwYDVR0fBEAwPjA8oDqgOIY2aHR0cDovL2NybC5nbG9i
# YWxzaWduLmNvbS9nc2djY3I0NWV2Y29kZXNpZ25jYTIwMjAuY3JsMB0GA1UdEQQW
# MBSBEmFkbWluQGN5YmVyYXJrLmNvbTATBgNVHSUEDDAKBggrBgEFBQcDAzAfBgNV
# HSMEGDAWgBQlndD8WQmGY8Xs87ETO1ccA5I2ETAdBgNVHQ4EFgQUvfk3K3nY9zOK
# r24uYKcj/KTt+p8wDQYJKoZIhvcNAQELBQADggIBAB7REam0h5j/shCjeh87xdmt
# AvLf+bBp2STB6GVNs6nZixmLw4qjCWkFdeEBM5SG9HEpKQxCrmVAk9waH14pb7O7
# xrNeBcdsNMDZ3b3sjae63LodNC4kS+qPWGlIBG9giV3dbZjnTCW0zVI0WXWX6o5s
# vOs35FeLIAak8t8NsA3fJK0ngsBjOfO+2aJikZU4BaDy8Oj04TTAvLeLe2wtuzt/
# W+dddwIVNys7VFs4dppNCtrzPK0pYYWIq17KHPtQ0yPp5EtxWQqBgEnDjdu1mDss
# 0I93shcUYmst3AqGVliQRJZHnE6Hk665IiN7S6QJ+UVoyxprVGC6+k21pCPiMTTr
# BtwvfEP00JB/CGG3/Q+yIoetCMv1jkg6Cso7KOAGQkfeVAucRgq61AfDjp7f8LwO
# dqLJhQvL6pJ0fLiGSlh6y9Rr0kG0DRHKmsLUYofs67oRLUT9T/RqFwYSTzU4eKxU
# TJurkigpkCbn55bYw+C5T0+gX1QI16K97E51wEnJ9jp6u+YenUy/OgGDGnUWLiMn
# 4M6L60ZOgUx8Bndk5UxPPgdYwn6R6iPaJhYe0TAB2mTD9qPPD4+NBzBMDHC25tvP
# +Si4LmDAxO1H35ifRREyPZ1OD08iWQDsjcHqtS4vntaRa9SNtwNE/4KJtBE1C+vC
# c3epnQA75eTfm9t3CdYEMYIZ1DCCGdACAQEwbDBcMQswCQYDVQQGEwJCRTEZMBcG
# A1UEChMQR2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0Mg
# UjQ1IEVWIENvZGVTaWduaW5nIENBIDIwMjACDAJZP4AHVQPEmDE5fjANBglghkgB
# ZQMEAgEFAKB8MBAGCisGAQQBgjcCAQwxAjAAMBkGCSqGSIb3DQEJAzEMBgorBgEE
# AYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJ
# BDEiBCDbkYGXHA3NIQVnAwyNkzELHDZCBmdPtXkASPYFo3loHjANBgkqhkiG9w0B
# AQEFAASCAgADanGgiBlG4Sh8rIUZhddb+s69S2eKeS2GQ0sk82J74MHcXrJET0BD
# g6f16HtXuFxBvB1Fdc6q1XaRQEYN0lipFBqyv0IL8NXNncm9sWcTMB0Pr905JbtW
# SrCr9c0w7sSud4vkCv5VljFxl2ItM9v/6hKOsjcn+agQvzLWExu7ifVQIAUe6a84
# WZj2IvmU/C7s6T5dOWOh3bQqW6SK8h+9Zu9mAipNhrRH635zq9WNrqlyjx+gX8Vp
# aPM2Q4W8rPa7/EQAPAGZJdMY64FbMaREgcxp83cbBJgvrcqT2413335ZNvPWBNaB
# RueHklS8gUrqiH0VnBNFJZW0HVnesvZkxianwGSpEwqPvZX2SIOI9ZfPyRGo83XX
# zHmO8EPqeqqVt/sCqWiAmzgAQmbqjfWg7TiZ2IFYGJZR8KfRZtRsdqLrrthAI4Wn
# t6/ENdz14vOJE7RnyN023USwhgRY6iQbZOFU3HodRBpGnO99RzZoXttHNvvd/O0k
# OC3OgUGzCZt2oadfCzYISqnDx5PHfPP/lHADPVbhRJQpIDXeJyN09pdR+65FGZLE
# K8yuK7wVB/UKZRzVTQMeoOL8VPAaClwPYeax19Sqc9T853q5BnCeOqDNNUgmiNPW
# ptjSk6Vmut9wYrbAdukmGqLfbYtW7NNYXCXUqYxYOvDtvXw7MWXL36GCFrswgha3
# BgorBgEEAYI3AwMBMYIWpzCCFqMGCSqGSIb3DQEHAqCCFpQwghaQAgEDMQ0wCwYJ
# YIZIAWUDBAIBMIHfBgsqhkiG9w0BCRABBKCBzwSBzDCByQIBAQYLKwYBBAGgMgID
# AQIwMTANBglghkgBZQMEAgEFAAQgXUIZgf4p0va3keFdUDwrQpYKhYjugX0OhPCJ
# UXTGohcCFHFHXxpqnAZitoez5mvjpq/NlKQBGA8yMDI1MDUxOTEzMzc1MlowAwIB
# AaBYpFYwVDELMAkGA1UEBhMCQkUxGTAXBgNVBAoMEEdsb2JhbFNpZ24gbnYtc2Ex
# KjAoBgNVBAMMIUdsb2JhbHNpZ24gVFNBIGZvciBDb2RlU2lnbjEgLSBSNqCCEksw
# ggZjMIIES6ADAgECAhABAAsgBbOUB2LbPjZ5lJupMA0GCSqGSIb3DQEBDAUAMFsx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTEwLwYDVQQD
# EyhHbG9iYWxTaWduIFRpbWVzdGFtcGluZyBDQSAtIFNIQTM4NCAtIEc0MB4XDTI1
# MDQxMTE0NDczOVoXDTM0MTIxMDAwMDAwMFowVDELMAkGA1UEBhMCQkUxGTAXBgNV
# BAoMEEdsb2JhbFNpZ24gbnYtc2ExKjAoBgNVBAMMIUdsb2JhbHNpZ24gVFNBIGZv
# ciBDb2RlU2lnbjEgLSBSNjCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGB
# AKJbxKpNSeUjeD7ghevmqgo+1fKsqKdEYfeKy5mN+wp/Hq/NEpHys3SRyZN06mvU
# GOFMFeoXnV30m+YJNF8nctzDRI9ahPmaJjxHIwu7kbRnXwfz7Z4nlic47T1VJZhD
# 61DLKBVO8KCUnEVdVuv+nn4tgckh17IWd9FdRA2dpSkNAyt6t2yOLCRP+Z/3UMvI
# i+IY02kvb9GEMuUSWPqNTVocT/x7Dbpuuzq+KxQ7BiBPOYYOa+INwlxboqlr5TZj
# 2wgVoHcafzwqmNC4ntOA7imw8EXep65uQB+aCESchVIy7xuBztC9VF2DLieidScz
# uN/EQNJiUb1NmcGyOsohR2ktMd0oBWpL4RCy5+LZsJ4GD4/hQ19y2lh554vzBiV0
# cZzdKUHWCahGISlJazB/ftipZ3XM//cl2BhMsE7fPHd8vk1Bb2ZQANATDmDDK2BU
# BKbZUYNg2K8ebFrV9arws5OrBAS0VTxGxNIvidNSC5Qc0aXCbrGVEMhitkVUjhX1
# zwIDAQABo4IBqDCCAaQwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsG
# AQUFBwMIMB0GA1UdDgQWBBSAQ0z8um0dE9J1EogJd2/bxk+VVDBWBgNVHSAETzBN
# MAgGBmeBDAEEAjBBBgkrBgEEAaAyAR4wNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93
# d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDAYDVR0TAQH/BAIwADCBkAYI
# KwYBBQUHAQEEgYMwgYAwOQYIKwYBBQUHMAGGLWh0dHA6Ly9vY3NwLmdsb2JhbHNp
# Z24uY29tL2NhL2dzdHNhY2FzaGEzODRnNDBDBggrBgEFBQcwAoY3aHR0cDovL3Nl
# Y3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3N0c2FjYXNoYTM4NGc0LmNydDAf
# BgNVHSMEGDAWgBTqFsZp5+PLV0U5M6TwQL7Qw71lljBBBgNVHR8EOjA4MDagNKAy
# hjBodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL2NhL2dzdHNhY2FzaGEzODRnNC5j
# cmwwDQYJKoZIhvcNAQEMBQADggIBALemx0qZdnT9IGInvYl8Nwc+V88LL5omIrBI
# 26MkWYp/o6h9uiBau30DCKzeVXV/ChpeaRHttW/LJD31HLYq6KOkEuaFhEpeJM2a
# MNoif6iZ++k5Ly/r9n+Jh6JRiwcMg5u+H16+vFut8bomEqZ23+zWD8gWhyO8yfxK
# 0k+GwNNEwvn7T7bUvhvzITVGioN+MmifGegBDZz3QgfFSK7f7KnekdZPPTo8dYy9
# +kARD1K9nbSCJUtyou+AlNeWE7xvl8bfXMBPtBsf6kUL/GGxflHLHYGFOIzUWQdJ
# E1dwbHd5ciFprfA0+EUI/S0NSCzqahvws8HfavRiS+o0iXkqtQAuGaHFTLqnGHfw
# /SaSDC/QUP8JOZYCZIFxHNYEYD7A7FPc89+icpjdfmIb8dFa+u469EH6pN1dM+v8
# VZhACSmn03iHw/YUHIY4hpMsNxCjYsh8jN+63SvwbE0sdKwdzB3ahPf3R0F+TVDk
# AllL4ZFstdLu9csxilp2wFkOjTbqvX7XMGBU5nMqOWGxcM35MkvmO/PjvbraoIul
# aBNjc1SW7nKhi2bSRScxiQ+8Xv66lC8GB3kNxz0pzQmoG+o6gXhUp108dBm7mLpN
# 4wOdXUDbbKIFQBlwqh7IetkFQJf4GnU33EWjKSFgHNwj7qd8dfXQwKbKZkcjlc1w
# VLbIglrCMIIGWTCCBEGgAwIBAgINAewckkDe/S5AXXxHdDANBgkqhkiG9w0BAQwF
# ADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMK
# R2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xODA2MjAwMDAwMDBa
# Fw0zNDEyMTAwMDAwMDBaMFsxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxT
# aWduIG52LXNhMTEwLwYDVQQDEyhHbG9iYWxTaWduIFRpbWVzdGFtcGluZyBDQSAt
# IFNIQTM4NCAtIEc0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA8ALi
# MCP64BvhmnSzr3WDX6lHUsdhOmN8OSN5bXT8MeR0EhmW+s4nYluuB4on7lejxDXt
# szTHrMMM64BmbdEoSsEsu7lw8nKujPeZWl12rr9EqHxBJI6PusVP/zZBq6ct/XhO
# Q4j+kxkX2e4xz7yKO25qxIjw7pf23PMYoEuZHA6HpybhiMmg5ZninvScTD9dW+y2
# 79Jlz0ULVD2xVFMHi5luuFSZiqgxkjvyen38DljfgWrhsGweZYIq1CHHlP5Cljvx
# C7F/f0aYDoc9emXr0VapLr37WD21hfpTmU1bdO1yS6INgjcZDNCr6lrB7w/Vmbk/
# 9E818ZwP0zcTUtklNO2W7/hn6gi+j0l6/5Cx1PcpFdf5DV3Wh0MedMRwKLSAe70q
# m7uE4Q6sbw25tfZtVv6KHQk+JA5nJsf8sg2glLCylMx75mf+pliy1NhBEsFV/W6R
# xbuxTAhLntRCBm8bGNU26mSuzv31BebiZtAOBSGssREGIxnk+wU0ROoIrp1JZxGL
# guWtWoanZv0zAwHemSX5cW7pnF0CTGA8zwKPAf1y7pLxpxLeQhJN7Kkm5XcCrA5X
# DAnRYZ4miPzIsk3bZPBFn7rBP1Sj2HYClWxqjcoiXPYMBOMp+kuwHNM3dITZHWar
# NHOPHn18XpbWPRmwl+qMUJFtr1eGfhA3HWsaFN8CAwEAAaOCASkwggElMA4GA1Ud
# DwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTqFsZp5+PL
# V0U5M6TwQL7Qw71lljAfBgNVHSMEGDAWgBSubAWjkxPioufi1xzWx/B/yGdToDA+
# BggrBgEFBQcBAQQyMDAwLgYIKwYBBQUHMAGGImh0dHA6Ly9vY3NwMi5nbG9iYWxz
# aWduLmNvbS9yb290cjYwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9i
# YWxzaWduLmNvbS9yb290LXI2LmNybDBHBgNVHSAEQDA+MDwGBFUdIAAwNDAyBggr
# BgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8w
# DQYJKoZIhvcNAQEMBQADggIBAH/iiNlXZytCX4GnCQu6xLsoGFbWTL/bGwdwxvsL
# Ca0AOmAzHznGFmsZQEklCB7km/fWpA2PHpbyhqIX3kG/T+G8q83uwCOMxoX+SxUk
# +RhE7B/CpKzQss/swlZlHb1/9t6CyLefYdO1RkiYlwJnehaVSttixtCzAsw0SEVV
# 3ezpSp9eFO1yEHF2cNIPlvPqN1eUkRiv3I2ZOBlYwqmhfqJuFSbqtPl/KufnSGRp
# L9KaoXL29yRLdFp9coY1swJXH4uc/LusTN763lNMg/0SsbZJVU91naxvSsguarnK
# iMMSME6yCHOfXqHWmc7pfUuWLMwWaxjN5Fk3hgks4kXWss1ugnWl2o0et1sviC49
# ffHykTAFnM57fKDFrK9RBvARxx0wxVFWYOh8lT0i49UKJFMnl4D6SIknLHniPOWb
# HuOqhIKJPsBK9SH+YhDtHTD89szqSCd8i3VCf2vL86VrlR8EWDQKie2CUOTRe6jJ
# 5r5IqitV2Y23JSAOG1Gg1GOqg+pscmFKyfpDxMZXxZ22PLCLsLkcMe+97xTYFEBs
# IB3CLegLxo1tjLZx7VIh/j72n585Gq6s0i96ILH0rKod4i0UnfqWah3GPMrz2Ry/
# U02kR1l8lcRDQfkl4iwQfoH5DZSnffK1CfXYYHJAUJUg1ENEvvqglecgWbZ4xqRq
# qiKbMIIFgzCCA2ugAwIBAgIORea7A4Mzw4VlSOb/RVEwDQYJKoZIhvcNAQEMBQAw
# TDEgMB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjYxEzARBgNVBAoTCkds
# b2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMTQxMjEwMDAwMDAwWhcN
# MzQxMjEwMDAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBS
# NjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJUH6HPKZvnsFMp7PPcNCPG0RQss
# grRIxutbPK6DuEGSMxSkb3/pKszGsIhrxbaJ0cay/xTOURQh7ErdG1rG1ofuTToV
# Bu1kZguSgMpE3nOUTvOniX9PeGMIyBJQbUJmL025eShNUhqKGoC3GYEOfsSKvGRM
# IRxDaNc9PIrFsmbVkJq3MQbFvuJtMgamHvm566qjuL++gmNQ0PAYid/kD3n16qIf
# KtJwLnvnvJO7bVPiSHyMEAc4/2ayd2F+4OqMPKq0pPbzlUoSB239jLKJz9CgYXfI
# WHSw1CM69106yqLbnQneXUQtkPGBzVeS+n68UARjNN9rkxi+azayOeSsJDa38O+2
# HBNXk7besvjihbdzorg1qkXy4J02oW9UivFyVm4uiMVRQkQVlO6jxTiWm05OWgtH
# 8wY2SXcwvHE35absIQh1/OZhFj931dmRl4QKbNQCTXTAFO39OfuD8l4UoQSwC+n+
# 7o/hbguyCLNhZglqsQY6ZZZZwPA1/cnaKI0aEYdwgQqomnUdnjqGBQCe24DWJfnc
# BZ4nWUx2OVvq+aWh2IMP0f/fMBH5hc8zSPXKbWQULHpYT9NLCEnFlWQaYw55PfWz
# jMpYrZxCRXluDocZXFSxZba/jJvcE+kNb7gu3GduyYsRtYQUigAZcIN5kZeR1Bon
# vzceMgfYFGM8KEyvAgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E
# BTADAQH/MB0GA1UdDgQWBBSubAWjkxPioufi1xzWx/B/yGdToDAfBgNVHSMEGDAW
# gBSubAWjkxPioufi1xzWx/B/yGdToDANBgkqhkiG9w0BAQwFAAOCAgEAgyXt6NH9
# lVLNnsAEoJFp5lzQhN7craJP6Ed41mWYqVuoPId8AorRbrcWc+ZfwFSY1XS+wc3i
# EZGtIxg93eFyRJa0lV7Ae46ZeBZDE1ZXs6KzO7V33EByrKPrmzU+sQghoefEQzd5
# Mr6155wsTLxDKZmOMNOsIeDjHfrYBzN2VAAiKrlNIC5waNrlU/yDXNOd8v9EDERm
# 8tLjvUYAGm0CuiVdjaExUd1URhxN25mW7xocBFymFe944Hn+Xds+qkxV/ZoVqW/h
# pvvfcDDpw+5CRu3CkwWJ+n1jez/QcYF8AOiYrg54NMMl+68KnyBr3TsTjxKM4kEa
# SHpzoHdpx7Zcf4LIHv5YGygrqGytXm3ABdJ7t+uA/iU3/gKbaKxCXcPu9czc8FB1
# 0jZpnOZ7BN9uBmm23goJSFmH63sUYHpkqmlD75HHTOwY3WzvUy2MmeFe8nI+z1TI
# vWfspA9MRf/TuTAjB0yPEL+GltmZWrSZVxykzLsViVO6LAUP5MSeGbEYNNVMnbrt
# 9x+vJJUEeKgDu+6B5dpffItKoZB0JaezPkvILFa9x8jvOOJckvB595yEunQtYQEg
# fn7R8k8HWV+LLUNS60YMlOH1Zkd5d9VUWx+tJDfLRVpOoERIyNiwmcUVhAn21klJ
# wGW45hpxbqCo8YLoRT5s1gLXCmeDBVrJpBAxggNJMIIDRQIBATBvMFsxCzAJBgNV
# BAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTEwLwYDVQQDEyhHbG9i
# YWxTaWduIFRpbWVzdGFtcGluZyBDQSAtIFNIQTM4NCAtIEc0AhABAAsgBbOUB2Lb
# PjZ5lJupMAsGCWCGSAFlAwQCAaCCAS0wGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJ
# EAEEMCsGCSqGSIb3DQEJNDEeMBwwCwYJYIZIAWUDBAIBoQ0GCSqGSIb3DQEBCwUA
# MC8GCSqGSIb3DQEJBDEiBCCST0nIBXK4y1zHrUbZMW93+V6IBe1ZHKYSqy4F/xTw
# NjCBsAYLKoZIhvcNAQkQAi8xgaAwgZ0wgZowgZcEIHJe8n9I4W5puWPYQmiMW8oH
# qIxpFwZCyP9aK3evYFz9MHMwX6RdMFsxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBH
# bG9iYWxTaWduIG52LXNhMTEwLwYDVQQDEyhHbG9iYWxTaWduIFRpbWVzdGFtcGlu
# ZyBDQSAtIFNIQTM4NCAtIEc0AhABAAsgBbOUB2LbPjZ5lJupMA0GCSqGSIb3DQEB
# CwUABIIBgGWrOzXhNp6tbOIsZnpeGh12uXK+bJ62hQu64XKcZEBPiAybGAVfNvCU
# 18ccaR9JdYYvuupwGkGCiJePS0kJ129gLjsL4cwGkPZ/DzcVbeY5vR8HCiB5RTP0
# mDSMT2OYUE7cCYqGkZlelMUpf2gORIwbDEd1WdVld86pNFWvknHp31VF66QvsR3+
# YWk0tJIuVfCuoYBFbWFALeokZ7+6pbwLjpMhHG6nO9Fvw5iDzanM3wagGLDDFu8N
# BdHtIpX7NmgVjB2rmQ+pVUZnY052HZy1V8xykyxkPu+gdw381UsMJ2KdPrko/+KL
# K9X0W3bLIO2S47cWBSdFsb/yi2/hdtki7y/9sQ9aZz69z9NgdS8HSylqotmHDJyh
# n5hBGbcflExJUuH8yguU6UYduGaqiBdtAKlf5S/b9rLrvRjoCW+9lrDpYgcBkXzB
# THIGxjJFNfMgvxL5I09vd6j5Wsiz95bCwjk4Spql6JNunAbtFxwjM+6axKsOBU2v
# Gt4a83QMmg==
# SIG # End signature block
