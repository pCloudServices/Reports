<#
.SYNOPSIS
    Privilege Cloud Consumed User Report
.DESCRIPTION
    This script generates a Privilege Cloud consumed users report for a given tenant URL.
.PARAMETER PortalURL
    Specifies the URL of the Privilege Cloud tenant.
    Example: https://<subdomain>.cyberark.cloud
.PARAMETER AuthType
    Specifies the authentication type for accessing Privilege Cloud.
    Valid values are 'cyberark' and 'identity'.
    Default value: identity
.PARAMETER ExportToCSV
    Specifies whether to export the results to a CSV file or print them in PowerShell.
    If this switch is specified, the results will be exported to a CSV file.
#>
param(
    [Parameter(Mandatory = $true, HelpMessage = "Specify the URL of the Privilege Cloud tenant (e.g., https://<subdomain>.cyberark.cloud)")]
    [string]$PortalURL,
    [Parameter(Mandatory = $true, HelpMessage = "Specify the authentication type for accessing Privilege Cloud. Valid values are 'cyberark' and 'identity'.")]
    [ValidateSet("cyberark", "identity")]
    [string]$AuthType = "identity",
    [Parameter(Mandatory = $false, HelpMessage = "Specify the URL of the Privilege Cloud tenant (e.g., https://<subdomain>.cyberark.cloud)")]
    [int]$InactiveDays = 60,
    [switch]$ExportToCSV
)

# Version
[int]$Version = 1


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
    write-host "Error: $($_.exception.message) $($_.ErrorDetails.Message) $($_.exception.status) $($_.exception.Response.ResppnseUri.AbsoluteUri))"
    }
}

function Get-UserType {
    param (
        [string]$UserType
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

    $headers = if ($AuthType -eq "cyberark") {
        Authenticate-CyberArk -rebuildPortalURL $rebuildPortalURL -body $body -creds $creds
    } else {
        Authenticate-Identity -PortalURL $PortalURL -creds $creds
    }

    $userTypeFilters = [ordered] @{
        "EPVUser" = $null
        "EPVUserLite" = $null
        "BasicUser" = $null
        "ExtUser" = $null
        "CPM" = $null
        "PSM" = $null
    }

    Write-Host ""
    Write-Host "Privilege Cloud consumed users report for tenant $PortalURL"
    Write-Host "-----------------------------------------------------------------------"
    Write-Host "Yellow Users = Inactive for more than $($InactiveDays) days" -ForegroundColor Black -BackgroundColor Yellow

    foreach ($filterKey in $userTypeFilters.Keys) {
        Get-UserType -UserType $filterKey
    }

    # Logoff
    Write-Host "Logging off..."
    if ($AuthType -eq "cyberark") {
        $uri = "$rebuildPortalURL/PasswordVault/API/Auth/Logoff/"
        Invoke-WebRequest -Uri $uri -Method Post -Headers $headers -ContentType "application/json" | Out-Null
    } else {
        Invoke-RestMethod -Uri $LogoffPlatform -Method Post -Headers $headers | Out-Null
    }

} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Error Details: $($_.ErrorDetails.Message)" -ForegroundColor Red
    Write-Host "Exiting..."
}
