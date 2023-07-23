<#
.SYNOPSIS
    Privilege Cloud Consumed User Report
.DESCRIPTION
    This PowerShell script generates a comprehensive report of users consuming resources in the Privilege Cloud for a given tenant URL. The report includes information about users of different types and their last login dates. Additionally, it identifies users who have been inactive for more than a specified number of days.
.PARAMETER PortalURL
    Specifies the URL of the Privilege Cloud tenant.
    Example: https://<subdomain>.cyberark.cloud
.PARAMETER AuthType
    Specifies the authentication type for accessing Privilege Cloud.
    Valid values are 'cyberark' and 'identity'.
    Default value: identity
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
    [Parameter(Mandatory = $false, HelpMessage = "Specify the authentication type for accessing Privilege Cloud. Valid values are 'cyberark' and 'identity'.")]
    [ValidateSet("cyberark", "identity")]
    [string]$AuthType = "cyberark",
    [Parameter(Mandatory = $false, HelpMessage = "Specify the number of days to consider users as inactive.")]
    [int]$InactiveDays = 60,
    [switch]$ExportToCSV,
    [Parameter(Mandatory=$false, HelpMessage="Specify the UserTypes you want to get a report on (default values are: EPVUser, EPVUserLite, BasicUser, ExtUser, AppProvider, CPM, PSM)")]
    [string[]]$GetSpecificuserTypes = @("EPVUser", "EPVUserLite", "BasicUser", "ExtUser", "AppProvider","CPM", "PSM"),
    [Parameter(Mandatory = $false, HelpMessage = "Specify the type of report to generate. Valid values are 'CapacityReport' and 'DetailedReport'.")]
    [ValidateSet("DetailedReport", "CapacityReport")]
    [string]$ReportType = "CapacityReport"
)

# Version
[int]$Version = 2


function Authenticate-CyberArk {
    param(
        [string]$rebuildPortalURL,
        [string]$body,
        [pscredential]$creds
    )

    $body = @{
    username = $creds.UserName.Replace('\', '')
    password = $creds.GetNetworkCredential().Password
    } | ConvertTo-Json

    try {
        $PVWAresponse = Invoke-WebRequest -Uri "$rebuildPortalURL/PasswordVault/API/auth/Cyberark/Logon/" -Method Post -Body $body -ContentType "application/json"
        $sessionToken = $PVWAresponse.Content.Trim('"')
        $headers = @{
            Authorization = $sessionToken
        }
        return $headers
    } catch {
        Write-Host "Error: $($_.Exception.Message) $($_.ErrorDetails.Message) $($_.Exception.Status) $($_.Exception.Response.ResponseUri.AbsoluteUri)" -ForegroundColor Red
        throw $_.Exception.Message
    }
}


function Authenticate-Identity {
    param(
        [string]$PortalURL,
        [pscredential]$creds
    )

Try{
    #Platform Identity API
    $IdentityBaseURL = Invoke-WebRequest $PortalURL -MaximumRedirection 0 -ErrorAction SilentlyContinue -Verbose
    $IdentityHeaderURL = ([System.Uri]$IdentityBaseURL.headers.Location).Host

    $IdentityTenantId = $IdentityHeaderURL.Split(".")[0]
    $IdaptiveBasePlatformURL = "https://$IdentityHeaderURL"
    $IdaptiveBasePlatformSecURL = "$IdaptiveBasePlatformURL/Security"
    $startPlatformAPIAuth = "$IdaptiveBasePlatformSecURL/StartAuthentication"
    $startPlatformAPIAdvancedAuth = "$IdaptiveBasePlatformSecURL/AdvanceAuthentication"
    $script:LogoffPlatform = "$IdaptiveBasePlatformSecURL/logout"


    	#Begin Start Authentication Process
		Write-Host "Begin Start Authentication Process: $startPlatformAPIAuth"
        $IdentityTenantId = $IdentityHeaderURL.Split(".")[0]
		$startPlatformAPIBody = @{TenantId = $IdentityTenantId; User = $creds.UserName ; Version = "1.0"} | ConvertTo-Json -Compress

		$IdaptiveResponse = Invoke-RestMethod -Uri $startPlatformAPIAuth -Method Post -ContentType "application/json" -Body $startPlatformAPIBody -TimeoutSec 10 -Verbose
		write-host $($IdaptiveResponse.Result.Challenges.mechanisms | Out-String)



		
        if(-not($IdaptiveResponse.Result.Challenges.mechanisms -eq $null))
        {
		    #Begin Advanced Authentication Process
		    Write-Host "Begin Advanced Authentication Process: $startPlatformAPIAdvancedAuth"
            $startPlatformAPIAdvancedAuthBody = @{SessionId = $($IdaptiveResponse.Result.SessionId); MechanismId = $($IdaptiveResponse.Result.Challenges.mechanisms|where {$_.AnswerType -eq "Text" -and $_.Name -eq "UP"}).MechanismId; Action = "Answer"; Answer = $creds.GetNetworkCredential().Password } | ConvertTo-Json -Compress
		    $AnswerToResponse = Invoke-RestMethod -Uri $startPlatformAPIAdvancedAuth -Method Post -ContentType "application/json" -Body $startPlatformAPIAdvancedAuthBody -TimeoutSec 30
		    write-host $AnswerToResponse.Result.Summary
            write-host $AnswerToResponse.Message
        }
        Else
        {
            Write-Host "Did not receive challenge response, check response recieved below:" -ForegroundColor Red
            write-host $($IdaptiveResponse | Out-String)
            # Tenant has Custom URL enabled, we don't support it yet.
            if($IdaptiveResponse.Result.PodFqdn){
                Write-Host "Hint: It looks like you have configured customized URL in Identity Administration, this isn't supported in ISPSS please disable it and try again (wait at least 10 min for changes to take affect)." -ForegroundColor Yellow
                write-host "Hint: Navigate to Identity Administration -> Settings -> Customization -> Tenant URLs -> Delete the Custom URL and make sure default is '$($IdentityHeaderURL)'" -ForegroundColor Yellow
                Pause
                Exit
            }
            Pause
            Exit
        }
	
		if($AnswerToResponse.Result.Summary -eq "LoginSuccess"){
            $Headers = @{Authorization  = "Bearer $($AnswerToResponse.Result.Token)"}
            $Headers.Add("X-IDAP-NATIVE-CLIENT","true")
            return $Headers
		}Else{
				if($IdaptiveResponse.Result.Challenges.mechanisms.AnswerType.Count -gt 1){
                    #Begin Start Authentication Process
                    $startPlatformAPIBody = @{TenantId = $IdentityTenantId; User = $creds.UserName ; Version = "1.0"} | ConvertTo-Json -Compress
                    $IdaptiveResponse = Invoke-RestMethod -Uri $startPlatformAPIAuth -Method Post -ContentType "application/json" -Body $startPlatformAPIBody -TimeoutSec 30
                    write-host $($IdaptiveResponse.Result.Challenges.mechanisms | Out-String)


                    #Beging Advanced Authentication Process
                    # *********Local Password (1st MFA) *********
                    $startPlatformAPIAdvancedAuthBody = @{SessionId = $($IdaptiveResponse.Result.SessionId); MechanismId = $($IdaptiveResponse.Result.Challenges.mechanisms|where {$_.AnswerType -eq "Text" -and $_.Name -eq "UP"}).MechanismId; Action = "Answer"; Answer = $creds.GetNetworkCredential().Password } | ConvertTo-Json -Compress
                    $AnswerToResponse = Invoke-RestMethod -Uri $startPlatformAPIAdvancedAuth -Method Post -ContentType "application/json" -Body $startPlatformAPIAdvancedAuthBody -TimeoutSec 30 -Verbose
                    write-host $($AnswerToResponse.Result | Out-String)
                    
                    # ********* Start MFA *********
                    $startPlatformAPIAdvancedAuthBody = @{SessionId = $($IdaptiveResponse.Result.SessionId); MechanismId = $($IdaptiveResponse.Result.Challenges.mechanisms|where {$_.AnswerType -eq "StartTextOob" -and $_.name -eq "EMAIL"}).MechanismId; Action = "StartOOB"; } | ConvertTo-Json -Compress
                    $AnswerToResponse = Invoke-RestMethod -Uri $startPlatformAPIAdvancedAuth -Method Post -ContentType "application/json" -Body $startPlatformAPIAdvancedAuthBody -TimeoutSec 30 -Verbose
                    #Check status is PendingOOB, you should receive an email now, click on t he auth link there.
                    write-host $($AnswerToResponse.Result | Out-String)

                    Write-Host "Challenge sent to your other device (email/phone), go there and accept it, then click ENTER here to proceed." -ForegroundColor Yellow
                    Pause
                    # *************WAIT BEFORE YOU PROCEED, MAKE SURE YOU CLICKED THE AUTH LINK IN EMAIL FIRST. *********************

                    $startPlatformAPIAdvancedAuthBody = @{SessionId = $($IdaptiveResponse.Result.SessionId); MechanismId = $($IdaptiveResponse.Result.Challenges.mechanisms|where {$_.AnswerType -eq "StartTextOob" -and $_.name -eq "EMAIL"}).MechanismId; Action = "Poll" } | ConvertTo-Json -Compress
                    $AnswerToResponse = Invoke-RestMethod -Uri $startPlatformAPIAdvancedAuth -Method Post -ContentType "application/json" -Body $startPlatformAPIAdvancedAuthBody -TimeoutSec 30 -Verbose

                    $Headers = @{Authorization  = "Bearer $($AnswerToResponse.Result.Token)"}
                    $Headers.Add("X-IDAP-NATIVE-CLIENT","true")
                    return $Headers
				}
			}
}
Catch{
    write-host "Error: $($_.exception.message) $($_.ErrorDetails.Message) $($_.exception.status) $($_.exception.Response.ResppnseUri.AbsoluteUri)"
    }
}


Function Get-LicenseCapacityReport(){
param(
 [string]$vaultIp,
 [string[]]$GetSpecificuserTypes
)
#Static
$VaultOperationFolder = "$PSScriptRoot\VaultOperationsTester"
$stdoutFile = "$VaultOperationFolder\Log\stdout.log"
$LOG_FILE_PATH_CasosArchive = "$VaultOperationFolder\Log\old"

$specificUserTypesString = $GetSpecificuserTypes -join ','

 #Prereqs   
 if(!(Test-Path -Path "$VaultOperationFolder\VaultOperationsTester.exe")){
     Write-LogMessage -Type Error -Msg "Required folder doesn't exist: `"$VaultOperationFolder`". Make sure you get the latest version and extract it correctly from zip."
     Pause
     Return
 }
 if((Get-CimInstance -Class win32_product | where {$_.Name -like "Microsoft Visual C++ 2013 x86*"}) -eq $null){
    $CpmRedis = "$VaultOperationFolder\vcredist_x86.exe"
    Write-LogMessage -type Info -MSG "Installing Redis++ x86 from $CpmRedis..." -Early
    Start-Process -FilePath $CpmRedis -ArgumentList "/install /passive /norestart" -Wait
 }               
        #Cleanup log file if it gets too big
        if (Test-Path $LOG_FILE_PATH_CasosArchive)
        {
            if (Get-ChildItem $LOG_FILE_PATH_CasosArchive | measure -Property length -Sum | where { $_.sum -gt 5MB })
            {
                Write-LogMessage -type Info -MSG "Archive log folder is getting too big, deleting it." -Early
                Write-LogMessage -type Info -MSG "Deleting $LOG_FILE_PATH_CasosArchive" -Early
                Remove-Item $LOG_FILE_PATH_CasosArchive -Recurse -Force
            }
        }
        
        #create log file
        New-Item -Path $stdoutFile -Force | Out-Null
      

        $process = Start-Process -FilePath "$VaultOperationFolder\VaultOperationsTester.exe" -ArgumentList "$($creds.UserName) $($creds.GetNetworkCredential().Password) $VaultIP GetLicense $specificUserTypesString" -WorkingDirectory "$VaultOperationFolder" -NoNewWindow -PassThru -Wait -RedirectStandardOutput $stdoutFile
        $creds = $null
        $stdout = (gc $stdoutFile)
            if($process.ExitCode -ne 0){
                Write-Host "-----------------------------------------"
                $stdout | Select-String -Pattern 'Extra details' -NotMatch | Write-Host -ForegroundColor DarkGray
                Write-LogMessage -type Error -MSG "$($stdout | Select-String -Pattern 'Extra details')"
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
                }
                
                # Output the custom objects with "Name" as the leftmost property
                $usersInfo | Select-Object Name, "UserType Description", "Licensed Users", "Existing Users", "Currently Logged On Users" | Format-Table -AutoSize | Out-Host
                Write-Host "-------------------------------------------------------------"
                # Export the results to a CSV file
                if($ExportToCSV){
                    $csvFilePath = ".\LicenseCapacityReport.csv"
                    $usersInfo | Select-Object Name, "UserType Description", "Licensed Users", "Existing Users", "Currently Logged On Users" | Export-Csv -Path $csvFilePath -NoTypeInformation -Force
                    Write-Host "Results exported to $csvFilePath" -ForegroundColor Cyan
                    }
                Write-Host "To get more detailed report rerun the script with '-ReportType DetailedReport' flag." -ForegroundColor Magenta
                 

            }
}

function Logoff{
    param (
        [string]$LogoffUrl,
        [hashtable]$headers,
        [string]$auth,
        [string]$reportType
    )
    Write-Host "Logging off..."
    # only need to logoff from PVWA (so when using DetailedReport), casos has it's own logoff.
    if ($auth -eq "cyberark" -and $reportType -eq "DetailedReport") {
        $uri = "$LogoffUrl/PasswordVault/API/Auth/Logoff/"
        Invoke-WebRequest -Uri $uri -Method Post -Headers $headers -ContentType "application/json" | Out-Null
    }
    elseif($auth -eq "identity")
    {
        Invoke-RestMethod -Uri $LogoffUrl -Method Post -Headers $headers | Out-Null
    }
}

function Get-UserType {
    param (
        [string[]]$UserType
    )

    $uri = "$rebuildPortalURL/PasswordVault/api/Users?UserType=$UserType"
    $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method GET

    Write-Host "$UserType = $($response.Total)" -ForegroundColor Green

    if ($response.Total -ge 1) {
        Write-Host "----------Start $UserType-----------------"

        $userInformation = @()  # Array to store user information

        foreach ($user in $response.Users.id) {
            $UserResponse = Invoke-RestMethod -Uri "$rebuildPortalURL/PasswordVault/Api/Users/$user" -Headers $headers
            $lastLoginDate = [DateTimeOffset]::FromUnixTimeSeconds($UserResponse.lastSuccessfulLoginDate).ToLocalTime()

            $daysSinceLastLogin = (Get-Date) - $lastLoginDate.DateTime
            $inactive = $daysSinceLastLogin.TotalDays -gt $InactiveDays

            $userObject = [PSCustomObject]@{
                UserName       = $UserResponse.Username
                LastLoginDate  = $lastLoginDate.ToString()
                Inactive       = $inactive
            }

            # Save into param if we want to export to csv
            $userInformation += $userObject

            # Print user info
            if ($inactive) {
                Write-Host "UserName: $($UserResponse.Username) LastLoginDate: $($lastLoginDate.ToString())" -ForegroundColor Yellow
            } else {
                Write-Host "UserName: $($UserResponse.Username) LastLoginDate: $($lastLoginDate.ToString())" -ForegroundColor Gray
            }
        }

        Write-Host "----------End $UserType-----------------"

        if ($ExportToCSV) {
            $csvPath = "$UserType-UsersReport.csv"
            $userInformation | Export-Csv -Path $csvPath -NoTypeInformation -Force
            Write-Host "User information exported to $csvPath" -ForegroundColor Cyan
        }
    }
}


# Main
try {
    $creds = Get-Credential

    # Extract subdomain from PortalURL and rebuild it with "privilegecloud" in between
    $uri = New-Object System.Uri($PortalURL)
    $subdomain = $uri.Host.Split('.')[0]
    $rebuildPortalURL = $PortalURL -replace "$subdomain\.", "${subdomain}.privilegecloud."
    $VaultURL = $PortalURL -replace "https://$subdomain\.", "vault-${subdomain}.privilegecloud."


    If($ReportType -eq "DetailedReport"){
        
        # Get Auth
        if($AuthType -eq "identity"){
            $headers = Authenticate-Identity -PortalURL $PortalURL -creds $creds
        }Else{
            $headers = Authenticate-CyberArk -rebuildPortalURL $rebuildPortalURL -body $body -creds $creds
        }

        Write-Host ""
        Write-Host "Privilege Cloud consumed users report for tenant $PortalURL"
        Write-Host "-----------------------------------------------------------------------"


        Write-Host "Yellow Users = Inactive for more than $($InactiveDays) days" -ForegroundColor Black -BackgroundColor Yellow
        foreach ($userType in $GetSpecificuserTypes) {
            Get-UserType -UserType $userType
        }

        # logoff
        Logoff -LogoffUrl $LogoffPlatform -headers $headers -auth $AuthType
    }
    Else
    {
        if($AuthType -eq "cyberark" -and $ReportType -eq "CapacityReport"){
            # Get Auth
            $headers = Authenticate-CyberArk -rebuildPortalURL $rebuildPortalURL -creds $creds

            Write-Host "Privilege Cloud Capacity report for tenant $PortalURL"
            Write-Host "-----------------------------------------------------------------------"
            
            Get-LicenseCapacityReport -vaultIp $VaultURL -GetSpecificuserTypes $GetSpecificuserTypes
        }Else{
            # If Identity auth, not supported with casos.
            Write-Host "You can't use $AuthType for Get-LicenseCapacityReport, use AuthType Cyberark instead, or rerun different report type with '-ReportType DetailedReport' flag." -ForegroundColor Yellow
            Pause
            Exit
        }
        # logoff
        Logoff -LogoffUrl $rebuildPortalURL -headers $headers -auth $AuthType -reportType $ReportType
    }

$creds = $null

} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Error Details: $($_.ErrorDetails.Message)" -ForegroundColor Red
    Write-Host "Exiting..."
}
