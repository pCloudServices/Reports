<#
.SYNOPSIS
    Privilege Cloud License Capacity User Report
.DESCRIPTION
    This PowerShell script generates a comprehensive report of users consuming resources in the Privilege Cloud for a given tenant URL. The report includes information about users of different types and their last login dates. Additionally, it identifies users who have been inactive for more than a specified number of days.
.PARAMETER PortalURL
    Specifies the URL of the Privilege Cloud tenant.
    Example: https://<subdomain>.cyberark.cloud
.PARAMETER AuthType
    Specifies the authentication type for accessing Privilege Cloud.
    Valid values are 'cyberark'.
    Default value: cyberark
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
    [Parameter(Mandatory = $false, HelpMessage = "Currently only supporting CyberArk Auth Type.")]
    [ValidateSet("cyberark")]
    [string]$AuthType = "cyberark",
    [Parameter(Mandatory = $false, HelpMessage = "Specify the number of days to consider users as inactive.")]
    [int]$InactiveDays = 60,
    [switch]$ExportToCSV,
    [Parameter(Mandatory=$false, HelpMessage="Specify the UserTypes you want to get a report on (default values are: EPVUser, EPVUserLite, BasicUser, ExtUser, AppProvider, CPM, PSM)")]
    [string[]]$GetSpecificuserTypes = @("EPVUser", "EPVUserLite", "BasicUser", "ExtUser", "BizUser", "AIMAccount", "AppProvider", "CCP", "CCPEndpoints", "CPM", "PSM"),
    [Parameter(Mandatory = $false, HelpMessage = "Specify the type of report to generate. Valid values are 'CapacityReport' and 'DetailedReport'.")]
    [ValidateSet("DetailedReport", "CapacityReport")]
    [string]$ReportType
)

# Version
[int]$Version = 3


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


function Logoff{
    param (
        [string]$LogoffUrl,
        [hashtable]$headers
    )
    Write-Host "Logging off..."
    # only need to logoff from PVWA (so when using DetailedReport), casos has it's own logoff.
        $uri = "$LogoffUrl/PasswordVault/API/Auth/Logoff/"
        Invoke-WebRequest -Uri $uri -Method Post -Headers $headers -ContentType "application/json" | Out-Null
}

Function Get-Choice{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        $Title,

        [Parameter(Mandatory = $true, Position = 1)]
        [String[]]
        $Options,

        [Parameter(Position = 2)]
        $DefaultChoice = -1
    )
    if ($DefaultChoice -ne -1 -and ($DefaultChoice -gt $Options.Count -or $DefaultChoice -lt 1))
    {
        Write-Warning "DefaultChoice needs to be a value between 1 and $($Options.Count) or -1 (for none)"
        exit
    }
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()
    $script:result = ""
    $form = New-Object System.Windows.Forms.Form
    $form.FormBorderStyle = [Windows.Forms.FormBorderStyle]::FixedDialog
    $form.BackColor = [Drawing.Color]::White
    $form.TopMost = $True
    $form.Text = $Title
    $form.ControlBox = $False
    $form.StartPosition = [Windows.Forms.FormStartPosition]::CenterScreen
    #calculate width required based on longest option text and form title
    $minFormWidth = 300
    $formHeight = 44
    $minButtonWidth = 150
    $buttonHeight = 23
    $buttonY = 12
    $spacing = 10
    $buttonWidth = [Windows.Forms.TextRenderer]::MeasureText((($Options | Sort-Object Length)[-1]), $form.Font).Width + 1
    $buttonWidth = [Math]::Max($minButtonWidth, $buttonWidth)
    $formWidth = [Windows.Forms.TextRenderer]::MeasureText($Title, $form.Font).Width
    $spaceWidth = ($options.Count + 1) * $spacing
    $formWidth = ($formWidth, $minFormWidth, ($buttonWidth * $Options.Count + $spaceWidth) | Measure-Object -Maximum).Maximum
    $form.ClientSize = New-Object System.Drawing.Size($formWidth, $formHeight)
    $index = 0
    #create the buttons dynamically based on the options
    foreach ($option in $Options)
    {
        Set-Variable "button$index" -Value (New-Object System.Windows.Forms.Button)
        $temp = Get-Variable "button$index" -ValueOnly
        $temp.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
        $temp.UseVisualStyleBackColor = $True
        $temp.Text = $option
        $buttonX = ($index + 1) * $spacing + $index * $buttonWidth
        $temp.Add_Click({ 
                $script:result = $this.Text; 
                $form.Close() 
            })
        $temp.Location = New-Object System.Drawing.Point($buttonX, $buttonY)
        $form.Controls.Add($temp)
        $index++
    }
    $shownString = '$this.Activate();'
    if ($DefaultChoice -ne -1)
    {
        $shownString += '(Get-Variable "button$($DefaultChoice-1)" -ValueOnly).Focus()'
    }
    $shownSB = [ScriptBlock]::Create($shownString)
    $form.Add_Shown($shownSB)
    [void]$form.ShowDialog()
    return $result
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
     Write-Host "Required folder doesn't exist: `"$VaultOperationFolder`". Make sure you get the latest version and extract it correctly from zip." -ForegroundColor Red
     Pause
     Return
 }
 if((Get-CimInstance -Class win32_product | where {$_.Name -like "Microsoft Visual C++ 2013 x86*"}) -eq $null){
    $CpmRedis = "$VaultOperationFolder\vcredist_x86.exe"
    Write-Host "Installing Redis++ x86 from $CpmRedis..." -ForegroundColor Gray
    Start-Process -FilePath $CpmRedis -ArgumentList "/install /passive /norestart" -Wait
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


        $process = Start-Process -FilePath "$VaultOperationFolder\VaultOperationsTester.exe" -ArgumentList "$($creds.UserName) $($creds.GetNetworkCredential().Password) $VaultIP GetLicense $specificUserTypesString" -WorkingDirectory "$VaultOperationFolder" -NoNewWindow -PassThru -Wait -RedirectStandardOutput $stdoutFile
        $creds = $null
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
                }
                
                # Output the custom objects with "Name" as the leftmost property
                $usersInfo | Select-Object Name, "UserType Description", "Licensed Users", "Existing Users", "Currently Logged On Users" | Format-Table -AutoSize | Out-Host
                Write-Host "-------------------------------------------------------------"
                # Export the results to a CSV file
                # If ExportToCSV flag not present, offer it via popup as reminder
                if (-Not $ExportToCSV.IsPresent) {
                    $ExportCSVChoice = Get-Choice -Title "Export Results to CSV" -Options "Yes","No" -DefaultChoice 2

                    if ($ExportCSVChoice -eq "Yes") {
                        $csvFilePath = ".\LicenseCapacityReport.csv"
                        $usersInfo | Select-Object Name, "UserType Description", "Licensed Users", "Existing Users", "Currently Logged On Users" | Export-Csv -Path $csvFilePath -NoTypeInformation -Force
                        Write-Host "Results exported to $csvFilePath" -ForegroundColor Cyan
                    }
                }
                # otherwise flag present, we export to csv.
                else {
                    $csvFilePath = ".\LicenseCapacityReport.csv"
                    $usersInfo | Select-Object Name, "UserType Description", "Licensed Users", "Existing Users", "Currently Logged On Users" | Export-Csv -Path $csvFilePath -NoTypeInformation -Force
                    Write-Host "Results exported to $csvFilePath" -ForegroundColor Cyan  
                }

                Write-Host "To get more detailed report rerun the script with '-ReportType DetailedReport' flag." -ForegroundColor Magenta
                 

            }
}



function Get-UserType {
    param (
        [string[]]$UserType
    )

    $uri = "$rebuildPortalURL/PasswordVault/api/Users?UserType=$UserType"
    try {
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method GET
    }
    catch {
        # if error "(400) Bad Request" means the userType didn't exist, that's ok, many licences are different, we can ignore this.
        if ($_.Exception.Message -like "*(400) Bad Request*") {
            $response = [PSCustomObject]@{
                Total = 0
            }
        }
        else {
            "Error: $($_.Exception.Message) $($_.ErrorDetails.Message) $($_.Exception.Status)"
        }
    }
    Write-Host ""
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
                "Inactive for $($InactiveDays) Days"      = $inactive
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

            # Export the results to a CSV file
            if (-Not $ExportToCSV.IsPresent) {
                
                if(-not($AlreadyAnswered)){
                    $global:ExportCSVChoice = Get-Choice -Title "Export Results to CSV" -Options "Yes","No" -DefaultChoice 2
                    $global:AlreadyAnswered = $true
                }
            
                if ($ExportCSVChoice -eq "Yes") {
                    $csvFilePath = "$UserType-UsersReport.csv"
                    $userInformation | Export-Csv -Path $csvFilePath -NoTypeInformation -Force
                    Write-Host "Results exported to $csvFilePath" -ForegroundColor Cyan
                }
            }
            # Flag was present, run csv
            else {
                $csvFilePath = "$UserType-UsersReport.csv"
                $userInformation | Export-Csv -Path $csvFilePath -NoTypeInformation -Force
                Write-Host "Results exported to $csvFilePath" -ForegroundColor Cyan  
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
    $AlreadyAnswered = $null

    # if reportType flag was not called
    if([string]::IsNullOrEmpty($ReportType)){

        $SelectOption = Get-Choice -Title "Choose Report Type" -Options "License Capacity Report","Detailed User Report" -DefaultChoice 1
        if($SelectOption -like "*Detailed*"){
            $script:ReportType = "DetailedReport"
        }Else{
            $script:ReportType = "CapacityReport"
        }
    }

        # Get Auth
        $headers = Authenticate-CyberArk -rebuildPortalURL $rebuildPortalURL -creds $creds


    If($ReportType -eq "DetailedReport"){
       
        Write-Host ""
        Write-Host "Privilege Cloud consumed users report for tenant $PortalURL"
        Write-Host "-----------------------------------------------------------------------"

        Write-Host "Yellow Users = Inactive for more than $($InactiveDays) days" -ForegroundColor Black -BackgroundColor Yellow
        foreach ($userType in $GetSpecificuserTypes) {
            Get-UserType -UserType $userType
        }

        # logoff
        Logoff -LogoffUrl $rebuildPortalURL -headers $headers
    }
    Else
    {
        
        Write-Host "Privilege Cloud Capacity report for tenant $PortalURL"
        Write-Host "-----------------------------------------------------------------------"
        
        Get-LicenseCapacityReport -vaultIp $VaultURL -GetSpecificuserTypes $GetSpecificuserTypes

        # logoff is handed by casos
    }

$creds = $null

} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Error Details: $($_.ErrorDetails.Message)" -ForegroundColor Red
    Write-Host "Exiting..."
}
# SIG # Begin signature block
# MIIqRQYJKoZIhvcNAQcCoIIqNjCCKjICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAIT8o8GMLnutjs
# ottJGgy+tUomqGDH5Rvq1I6/NtmT+aCCGFcwggROMIIDNqADAgECAg0B7l8Wnf+X
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
# HvZ/UuJJjbkRcgyIRCYzZgFE3+QzDiHeYolIB9r1MIIHbzCCBVegAwIBAgIMcE3E
# /BY6leBdVXwMMA0GCSqGSIb3DQEBCwUAMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUg
# RVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDAeFw0yMjAyMTUxMzM4MzVaFw0yNTAyMTUx
# MzM4MzVaMIHUMR0wGwYDVQQPDBRQcml2YXRlIE9yZ2FuaXphdGlvbjESMBAGA1UE
# BRMJNTEyMjkxNjQyMRMwEQYLKwYBBAGCNzwCAQMTAklMMQswCQYDVQQGEwJJTDEQ
# MA4GA1UECBMHQ2VudHJhbDEUMBIGA1UEBxMLUGV0YWggVGlrdmExEzARBgNVBAkT
# CjkgSGFwc2Fnb3QxHzAdBgNVBAoTFkN5YmVyQXJrIFNvZnR3YXJlIEx0ZC4xHzAd
# BgNVBAMTFkN5YmVyQXJrIFNvZnR3YXJlIEx0ZC4wggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQDys9frIBUzrj7+oxAS21ansV0C+r1R+DEGtb5HQ225eEqe
# NXTnOYgvrOIBLROU2tCq7nKma5qA5bNgoO0hxYQOboC5Ir5B5mmtbr1zRdhF0h/x
# f/E1RrBcsZ7ksbqeCza4ca1yH2W3YYsxFYgucq+JLqXoXToc4CjD5ogNw0Y66R13
# Km94WuowRs/tgox6SQHpzb/CF0fMNCJbpXQrzZen1dR7Gtt2cWkpZct9DCTONwbX
# GZKIdBSmRIfjDYDMHNyz42J2iifkUQgVcZLZvUJwIDz4+jkODv/++fa2GKte06po
# L5+M/WlQbua+tlAyDeVMdAD8tMvvxHdTPM1vgj11zzK5qVxgrXnmFFTe9knf9S2S
# 0C8M8L97Cha2F5sbvs24pTxgjqXaUyDuMwVnX/9usgIPREaqGY8wr0ysHd6VK4wt
# o7nroiF2uWnOaPgFEMJ8+4fRB/CSt6OyKQYQyjSUSt8dKMvc1qITQ8+gLg1budzp
# aHhVrh7dUUVn3N2ehOwIomqTizXczEFuN0siQJx+ScxLECWg4X2HoiHNY7KVJE4D
# L9Nl8YvmTNCrHNwiF1ctYcdZ1vPgMPerFhzqDUbdnCAU9Z/tVspBTcWwDGCIm+Yo
# 9V458g3iJhNXi2iKVFHwpf8hoDU0ys30SID/9mE3cc41L+zoDGOMclNHb0Y5CQID
# AQABo4IBtjCCAbIwDgYDVR0PAQH/BAQDAgeAMIGfBggrBgEFBQcBAQSBkjCBjzBM
# BggrBgEFBQcwAoZAaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# Z3NnY2NyNDVldmNvZGVzaWduY2EyMDIwLmNydDA/BggrBgEFBQcwAYYzaHR0cDov
# L29jc3AuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVldmNvZGVzaWduY2EyMDIwMFUG
# A1UdIAROMEwwQQYJKwYBBAGgMgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3
# Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAcGBWeBDAEDMAkGA1UdEwQCMAAw
# RwYDVR0fBEAwPjA8oDqgOIY2aHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9nc2dj
# Y3I0NWV2Y29kZXNpZ25jYTIwMjAuY3JsMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8G
# A1UdIwQYMBaAFCWd0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBTRWDsgBgAr
# Xx8j10jVgqJYDQPVsTANBgkqhkiG9w0BAQsFAAOCAgEAU50DXmYXBEgzng8gv8EN
# mr1FT0g75g6UCgBhMkduJNj1mq8DWKxLoS11gomB0/8zJmhbtFmZxjkgNe9cWPvR
# NZa992pb9Bwwwe1KqGJFvgv3Yu1HiVL6FYzZ+m0QKmX0EofbwsFl6Z0pLSOvIESr
# ICa4SgUk0OTDHNBUo+Sy9qm+ZJjA+IEK3M/IdNGjkecsFekr8tQEm7x6kCArPoug
# mOetMgXhTxGjCu1QLQjp/i6P6wpgTSJXf9PPCxMmynsxBKGggs+vX/vl9CNT/s+X
# Z9sz764AUEKwdAdi9qv0ouyUU9fiD5wN204fPm8h3xBhmeEJ25WDNQa8QuZddHUV
# hXugk2eHd5hdzmCbu9I0qVkHyXsuzqHyJwFXbNBuiMOIfQk4P/+mHraq+cynx6/2
# a+G8tdEIjFxpTsJgjSA1W+D0s+LmPX+2zCoFz1cB8dQb1lhXFgKC/KcSacnlO4SH
# oZ6wZE9s0guXjXwwWfgQ9BSrEHnVIyKEhzKq7r7eo6VyjwOzLXLSALQdzH66cNk+
# w3yT6uG543Ydes+QAnZuwQl3tp0/LjbcUpsDttEI5zp1Y4UfU4YA18QbRGPD1F9y
# wjzg6QqlDtFeV2kohxa5pgyV9jOyX4/x0mu74qADxWHsZNVvlRLMUZ4zI4y3KvX8
# vZsjJFVKIsvyCgyXgNMM5Z4xghFEMIIRQAIBATBsMFwxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdD
# QyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMAIMcE3E/BY6leBdVXwMMA0GCWCG
# SAFlAwQCAQUAoHwwEAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisG
# AQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcN
# AQkEMSIEIDLVfOB1yeAUCEOAPEiAnkrl88JH2WUjo7ri7bpLdBUmMA0GCSqGSIb3
# DQEBAQUABIICABxTLiSBdu2/54USKuLAL6t6g8FMsNKwED2xlQ3Cgp3NmTX1KJxy
# 2miqSEmJIXBNVGcklXsjqADG5kahxNMiWZpf0+79dMEtNxgA9p6HNQn+HfwknLVg
# 8ZK3bWqDdWP4Yym0lnnbrZLxFSJDdKXESVTfIm4Zk5lucsnmvmeAf9dtMQt0FauZ
# 4WjaGnBeMV+Pq+M4hnec6SPTbZUqHxo/5ioiq7YJ1UByISjRyXh8ZJAM8SQBLFxF
# CljZ1b0hQHmHt9hcufzGwz9kkUQ46Sx9inZbI8dnfI5Te9dOG5YcHNurGiN9JmFt
# jlhD+zphO5PTc3RepYzIb0ekOJdMERDNipKGlgfifpBy+BDSto97PvJkQyt9iPf+
# bp3hcAUBaZVlqfHw3BXzRWUKuiQg6j38WQv37/BjHn/9C/OC2pjsT6yjGiz9sF0N
# lnHn8w8UR05sB+ZqavFNpoG6WCJb9J9ViWpoYUqRV+NQnOK5MB7x+8Zc66clWSJ3
# ePrhBb6025zc7uKpYxyF9A36fKTwKS1dabQNKuJRibkX5wgaXh5vt5UC9xVytZwm
# KRzmrGLAatll/G4HtTyyf+s/huJ7f8zlJPHGe149A3UrGYiQqRpXjvHbEiAZJXxU
# goR/Gej42kiwb7maGey0y6maGsU2BXKlgBZs2TJrHsul/ezbOKuV5QzqoYIOKzCC
# DicGCisGAQQBgjcDAwExgg4XMIIOEwYJKoZIhvcNAQcCoIIOBDCCDgACAQMxDTAL
# BglghkgBZQMEAgEwgf4GCyqGSIb3DQEJEAEEoIHuBIHrMIHoAgEBBgtghkgBhvhF
# AQcXAzAhMAkGBSsOAwIaBQAEFGXVjdoJ21qSM9aiKKyDghBALfK5AhRDXczcUiKW
# rPo2IvLeBHQoUDxkTxgPMjAyMzA3MjQyMjM5NDFaMAMCAR6ggYakgYMwgYAxCzAJ
# BgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEfMB0GA1UE
# CxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazExMC8GA1UEAxMoU3ltYW50ZWMgU0hB
# MjU2IFRpbWVTdGFtcGluZyBTaWduZXIgLSBHM6CCCoswggU4MIIEIKADAgECAhB7
# BbHUSWhRRPfJidKcGZ0SMA0GCSqGSIb3DQEBCwUAMIG9MQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlTaWduIFRydXN0
# IE5ldHdvcmsxOjA4BgNVBAsTMShjKSAyMDA4IFZlcmlTaWduLCBJbmMuIC0gRm9y
# IGF1dGhvcml6ZWQgdXNlIG9ubHkxODA2BgNVBAMTL1ZlcmlTaWduIFVuaXZlcnNh
# bCBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTE2MDExMjAwMDAwMFoX
# DTMxMDExMTIzNTk1OVowdzELMAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5bWFudGVj
# IENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3b3JrMSgw
# JgYDVQQDEx9TeW1hbnRlYyBTSEEyNTYgVGltZVN0YW1waW5nIENBMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1mdWVVPnYxyXRqBoutV87ABrTxxrDKP
# BWuGmicAMpdqTclkFEspu8LZKbku7GOz4c8/C1aQ+GIbfuumB+Lef15tQDjUkQbn
# QXx5HMvLrRu/2JWR8/DubPitljkuf8EnuHg5xYSl7e2vh47Ojcdt6tKYtTofHjmd
# w/SaqPSE4cTRfHHGBim0P+SDDSbDewg+TfkKtzNJ/8o71PWym0vhiJka9cDpMxTW
# 38eA25Hu/rySV3J39M2ozP4J9ZM3vpWIasXc9LFL1M7oCZFftYR5NYp4rBkyjyPB
# MkEbWQ6pPrHM+dYr77fY5NUdbRE6kvaTyZzjSO67Uw7UNpeGeMWhNwIDAQABo4IB
# dzCCAXMwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwZgYDVR0g
# BF8wXTBbBgtghkgBhvhFAQcXAzBMMCMGCCsGAQUFBwIBFhdodHRwczovL2Quc3lt
# Y2IuY29tL2NwczAlBggrBgEFBQcCAjAZGhdodHRwczovL2Quc3ltY2IuY29tL3Jw
# YTAuBggrBgEFBQcBAQQiMCAwHgYIKwYBBQUHMAGGEmh0dHA6Ly9zLnN5bWNkLmNv
# bTA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vcy5zeW1jYi5jb20vdW5pdmVyc2Fs
# LXJvb3QuY3JsMBMGA1UdJQQMMAoGCCsGAQUFBwMIMCgGA1UdEQQhMB+kHTAbMRkw
# FwYDVQQDExBUaW1lU3RhbXAtMjA0OC0zMB0GA1UdDgQWBBSvY9bKo06FcuCnvEHz
# KaI4f4B1YjAfBgNVHSMEGDAWgBS2d/ppSEefUxLVwuoHMnYH0ZcHGTANBgkqhkiG
# 9w0BAQsFAAOCAQEAdeqwLdU0GVwyRf4O4dRPpnjBb9fq3dxP86HIgYj3p48V5kAp
# reZd9KLZVmSEcTAq3R5hF2YgVgaYGY1dcfL4l7wJ/RyRR8ni6I0D+8yQL9YKbE4z
# 7Na0k8hMkGNIOUAhxN3WbomYPLWYl+ipBrcJyY9TV0GQL+EeTU7cyhB4bEJu8LbF
# +GFcUvVO9muN90p6vvPN/QPX2fYDqA/jU/cKdezGdS6qZoUEmbf4Blfhxg726K/a
# 7JsYH6q54zoAv86KlMsB257HOLsPUqvR45QDYApNoP4nbRQy/D+XQOG/mYnb5DkU
# vdrk08PqK1qzlVhVBH3HmuwjA42FKtL/rqlhgTCCBUswggQzoAMCAQICEHvU5a+6
# zAc/oQEjBCJBTRIwDQYJKoZIhvcNAQELBQAwdzELMAkGA1UEBhMCVVMxHTAbBgNV
# BAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBUcnVz
# dCBOZXR3b3JrMSgwJgYDVQQDEx9TeW1hbnRlYyBTSEEyNTYgVGltZVN0YW1waW5n
# IENBMB4XDTE3MTIyMzAwMDAwMFoXDTI5MDMyMjIzNTk1OVowgYAxCzAJBgNVBAYT
# AlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEfMB0GA1UECxMWU3lt
# YW50ZWMgVHJ1c3QgTmV0d29yazExMC8GA1UEAxMoU3ltYW50ZWMgU0hBMjU2IFRp
# bWVTdGFtcGluZyBTaWduZXIgLSBHMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
# AQoCggEBAK8Oiqr43L9pe1QXcUcJvY08gfh0FXdnkJz93k4Cnkt29uU2PmXVJCBt
# MPndHYPpPydKM05tForkjUCNIqq+pwsb0ge2PLUaJCj4G3JRPcgJiCYIOvn6QyN1
# R3AMs19bjwgdckhXZU2vAjxA9/TdMjiTP+UspvNZI8uA3hNN+RDJqgoYbFVhV9Hx
# AizEtavybCPSnw0PGWythWJp/U6FwYpSMatb2Ml0UuNXbCK/VX9vygarP0q3InZl
# 7Ow28paVgSYs/buYqgE4068lQJsJU/ApV4VYXuqFSEEhh+XetNMmsntAU1h5jlIx
# Bk2UA0XEzjwD7LcA8joixbRv5e+wipsCAwEAAaOCAccwggHDMAwGA1UdEwEB/wQC
# MAAwZgYDVR0gBF8wXTBbBgtghkgBhvhFAQcXAzBMMCMGCCsGAQUFBwIBFhdodHRw
# czovL2Quc3ltY2IuY29tL2NwczAlBggrBgEFBQcCAjAZGhdodHRwczovL2Quc3lt
# Y2IuY29tL3JwYTBABgNVHR8EOTA3MDWgM6Axhi9odHRwOi8vdHMtY3JsLndzLnN5
# bWFudGVjLmNvbS9zaGEyNTYtdHNzLWNhLmNybDAWBgNVHSUBAf8EDDAKBggrBgEF
# BQcDCDAOBgNVHQ8BAf8EBAMCB4AwdwYIKwYBBQUHAQEEazBpMCoGCCsGAQUFBzAB
# hh5odHRwOi8vdHMtb2NzcC53cy5zeW1hbnRlYy5jb20wOwYIKwYBBQUHMAKGL2h0
# dHA6Ly90cy1haWEud3Muc3ltYW50ZWMuY29tL3NoYTI1Ni10c3MtY2EuY2VyMCgG
# A1UdEQQhMB+kHTAbMRkwFwYDVQQDExBUaW1lU3RhbXAtMjA0OC02MB0GA1UdDgQW
# BBSlEwGpn4XMG24WHl87Map5NgB7HTAfBgNVHSMEGDAWgBSvY9bKo06FcuCnvEHz
# KaI4f4B1YjANBgkqhkiG9w0BAQsFAAOCAQEARp6v8LiiX6KZSM+oJ0shzbK5pnJw
# Yy/jVSl7OUZO535lBliLvFeKkg0I2BC6NiT6Cnv7O9Niv0qUFeaC24pUbf8o/mfP
# cT/mMwnZolkQ9B5K/mXM3tRr41IpdQBKK6XMy5voqU33tBdZkkHDtz+G5vbAf0Q8
# RlwXWuOkO9VpJtUhfeGAZ35irLdOLhWa5Zwjr1sR6nGpQfkNeTipoQ3PtLHaPpp6
# xyLFdM3fRwmGxPyRJbIblumFCOjd6nRgbmClVnoNyERY3Ob5SBSe5b/eAL13sZgU
# chQk38cRLB8AP8NLFMZnHMweBqOQX1xUiz7jM1uCD8W3hgJOcZ/pZkU/djGCAlow
# ggJWAgEBMIGLMHcxCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jw
# b3JhdGlvbjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazEoMCYGA1UE
# AxMfU3ltYW50ZWMgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQe9Tlr7rMBz+hASME
# IkFNEjALBglghkgBZQMEAgGggaQwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MBwGCSqGSIb3DQEJBTEPFw0yMzA3MjQyMjM5NDFaMC8GCSqGSIb3DQEJBDEiBCCG
# 2z31XlkS+AanPu4ab6eCmLljA6YNo9fq+DEVZJawyTA3BgsqhkiG9w0BCRACLzEo
# MCYwJDAiBCDEdM52AH0COU4NpeTefBTGgPniggE8/vZT7123H99h+DALBgkqhkiG
# 9w0BAQEEggEAlk9jGYg0qxMV8HQicotQEeJ5auSqbOVNiQict0vo3U8MUdX3t14G
# /0sP5jKDIuXopDAVsQXoMZ1BagEv4JZNZgYhFAQBwlkp205WZZizzrQxbp8tf4e+
# CFQhJ1FwSExvpSNAjaytoFcq+ck1HRH1Oy8UmF5Qehda19tc2aYhlM18tp4usPXa
# ZnmFfxeqnsCY/CPYpxmmCJreyHXy1loWVUCAQao6pXDj/h0ggT48O37+L+rDpzzC
# dW5gzXAgRIzVhFPBmrjfEOi6glRGy0oEBGgFUisOs/X2YPNRo71G9YSmfHnakDbG
# ya6EF0ESlehJRk3UZUI662VG7hZJr7HLuQ==
# SIG # End signature block
