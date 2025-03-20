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
    [string[]]$GetSpecificuserTypes,
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