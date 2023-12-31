param(
    [Parameter(Mandatory = $true, HelpMessage = "Specify the URL of the Privilege Cloud tenant (e.g., https://<subdomain>.cyberark.cloud)")]
    [string]$PortalURL,
    [Parameter(Mandatory = $false, HelpMessage = "Specify the User that has permissions on both Identity User Management and Vault Audit User. (e.g. mike@cyberark.cloud.1022")]
    [PSCredential]$Credentials
)


# Modules
$modulePaths = @(
"..\\PS-Modules\\IdentityAuth.psm1",
"..\\..\\PS-Modules\\IdentityAuth.psm1",
".\\PS-Modules\\IdentityAuth.psm1", 
".\\IdentityAuth.psm1"
"..\\IdentityAuth.psm1"
".\\..\\IdentityAuth.psm1"
"..\\..\\IdentityAuth.psm1"
)

foreach ($modulePath in $modulePaths) {
    if (Test-Path $modulePath) {
        try {
            Import-Module $modulePath -ErrorAction Stop
            Write-Host "Module imported from $modulePath"
            break
        } catch {
            Write-Host "Failed to import module from $modulePath. Error: $_"
        }
     }
}

if (-not (Get-Module -Name IdentityAuth -ErrorAction SilentlyContinue)) {
    Write-Host "Can't find Module to import"
}

$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
$global:LOG_FILE_PATH = "$ScriptLocation\_SyncIdentityRolesWithVaultUsers.log"

[int]$scriptVersion = 1


Function Get-PrivCloudURL(){
    # grab the subdomain, depending how the user entered the url (hostname only or URL).
    if($PortalURL -match "https://"){
        $portalURL = ([System.Uri]$script:PortalURL).host
        $script:portalSubDomainURL = $PortalURL.Split(".")[0]
    }
    Else{
        $script:portalSubDomainURL = $PortalURL.Split(".")[0]
    }
    
    # Check if standard or shared services implementation.
    if($PortalURL -like "*.cyberark.com*"){
        # Standard
        $pvwaURL = "https://$portalSubDomainURL.privilegecloud.cyberark.com"
    }
    Else
    {
        # ispss
        $pvwaURL = "https://$portalSubDomainURL.privilegecloud.cyberark.cloud"
        $portalURL = "https://$portalSubDomainURL.cyberark.cloud"
    }
    return [PSCustomObject]@{pvwaURL = $pvwaURL; portalURL = $portalURL}
}

Function Get-IdentityURL($PortalURL){
    Add-Type -AssemblyName System.Net.Http
    
    # Define the base URL
    $BasePlatformURL = $PortalURL
    
    # Create an HttpClientHandler to modify HttpClient behavior
    $handler = New-Object System.Net.Http.HttpClientHandler
    # Set to not follow redirections automatically
    $handler.AllowAutoRedirect = $false
    
    # Create an HttpClient with the handler
    $client = New-Object System.Net.Http.HttpClient($handler)


    try {
        # Send a GET request to the URL
        $response = $client.GetAsync($BasePlatformURL).Result
    
        # Check if the response status code indicates a redirection
        if ($response.StatusCode -ge 300 -and $response.StatusCode -lt 400) {
            # Get the location header (redirection URL)
            $redirectionUrl = $response.Headers.Location
    
            # Extract the host from the redirection URL
            $IdentityHeaderURL = $redirectionUrl.Host
    
            # Output the result
            return $IdentityHeaderURL
        }
        else {
            Write-LogMessage -Type Error -Msg "Error: $(Collect-ExceptionMessage $_.exception.message $($_.ErrorDetails.Message) $($_.exception.status) $($_.exception.Response.ResponseUri.AbsoluteUri))"
        }
    }
    catch {
        Write-LogMessage -Type Error -Msg "Error: $(Collect-ExceptionMessage $_.exception.message $($_.ErrorDetails.Message) $($_.exception.status) $($_.exception.Response.ResponseUri.AbsoluteUri))"
    }
    finally {
        # Cleanup
        $response.Dispose()
        $client.Dispose()
    }
}


# Check if running user has sufficient permissions
Function Get-IdentityPermissions($IdentityHeaders){
    Try
    {
        $resp = Invoke-RestMethod -Uri "$IdaptiveBasePlatformURL/UserMgmt/GetUsersRolesAndAdministrativeRights" -Method Post -ContentType "application/json" -Headers $IdentityHeaders -ErrorVariable identityErr
        #$resp.Result.Results.row.AdministrativeRights.Description -eq "User Management"
    }
    Catch
    {
        $identityErr.message + $_.exception.status + $_.exception.Response.ResponseUri.AbsoluteUri
    }
    Return $resp.Result.Results.row.AdministrativeRights.Description
}


Function Get-VaultPermissions($IdentityHeaders, $pvwaUser){
    Try
    {
        $UserDetails = Invoke-RestMethod -Uri ("$PVWA_GetallUsers"+"?filter=UserName&search=$($pvwaUser)") -Method Get -ContentType "application/json" -Headers $IdentityHeaders -ErrorVariable identityErr
    }
    Catch
    {
        $identityErr.message + $_.exception.status + $_.exception.Response.ResponseUri.AbsoluteUri
    }
    Return $UserDetails.Users.vaultAuthorization
}



# Looking for all roles starting with "Privilege Cloud" in identity
Function Get-PrivCloudRoles(){

    Try{
        $body  = @{script = "Select Role.Name, ID from  Role ORDER BY Role COLLATE NOCASE"} | ConvertTo-Json -Compress
        $response = Invoke-RestMethod -Method Post -Uri "$IdaptiveBasePlatformURL/Redrock/Query" -ContentType "application/json" -Headers $IdentityHeaders -Body $body -ErrorVariable identityErr
        $PrivCloudROles = $response.Result.Results| where {$_.Row.Name -like "Privilege Cloud*"}
        }
    Catch{
        $identityErr.message + $_.exception.status + $_.exception.Response.ResponseUri.AbsoluteUri
    }

    If ($response.success -eq $false){
    Write-Host "Couldn't retrieve Roles, see response received:" -ForegroundColor Red
    $response
    Write-Host "Aborting script..."
    Pause
    Exit
    }
    Else
    {
        return $PrivCloudROles
    }
}

Function Write-LogMessage
{
	param(
		[Parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[AllowEmptyString()]
		[String]$MSG,
		[Parameter(Mandatory=$false)]
		[Switch]$Header,
		[Parameter(Mandatory=$false)]
		[Switch]$Early,
		[Parameter(Mandatory=$false)]
		[Switch]$SubHeader,
		[Parameter(Mandatory=$false)]
		[Switch]$Footer,
		[Parameter(Mandatory=$false)]
		[ValidateSet("Info","Warning","Error","Debug","Verbose", "Success", "LogOnly")]
		[String]$type = "Info",
		[Parameter(Mandatory=$false)]
		[String]$LogFile = $LOG_FILE_PATH
	)
	Try{
		If ($Header) {
			"=======================================" | Out-File -Append -FilePath $LogFile 
			Write-Host "=======================================" -ForegroundColor Magenta
		}
		ElseIf($SubHeader) { 
			"------------------------------------" | Out-File -Append -FilePath $LogFile 
			Write-Host "------------------------------------" -ForegroundColor Magenta
		}
		
		$msgToWrite = "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t"
		$writeToFile = $true
		# Replace empty message with 'N/A'
		if([string]::IsNullOrEmpty($Msg)) { $Msg = "N/A" }
		
		# Mask Passwords
		if($Msg -match '((?:password|credentials|secret)\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w`~!@#$%^&*()-_\=\+\\\/|;:\.,\[\]{}]+))')
		{
			$Msg = $Msg.Replace($Matches[2],"****")
		}
		# Check the message type
		switch ($type)
		{
			{($_ -eq "Info") -or ($_ -eq "LogOnly")} 
			{ 
				If($_ -eq "Info")
				{
					Write-Host $MSG.ToString() -ForegroundColor $(If($Header -or $SubHeader) { "magenta" } Elseif($Early){"DarkGray"} Else { "White" })
				}
				$msgToWrite += "[INFO]`t$Msg"
			}
			"Success" { 
				Write-Host $MSG.ToString() -ForegroundColor Green
				$msgToWrite += "[SUCCESS]`t$Msg"
            }
			"Warning" {
				Write-Host $MSG.ToString() -ForegroundColor Yellow
				$msgToWrite += "[WARNING]`t$Msg"
			}
			"Error" {
				Write-Host $MSG.ToString() -ForegroundColor Red
				$msgToWrite += "[ERROR]`t$Msg"
			}
			"Debug" { 
				if($InDebug -or $InVerbose)
				{
					Write-Debug $MSG
					$msgToWrite += "[DEBUG]`t$Msg"
				}
				else { $writeToFile = $False }
			}
			"Verbose" { 
				if($InVerbose)
				{
					Write-Verbose -Msg $MSG
					$msgToWrite += "[VERBOSE]`t$Msg"
				}
				else { $writeToFile = $False }
			}
		}

		If($writeToFile) { $msgToWrite | Out-File -Append -FilePath $LogFile }
		If ($Footer) { 
			"=======================================" | Out-File -Append -FilePath $LogFile 
			Write-Host "=======================================" -ForegroundColor Magenta
		}
	}
	catch{
		Throw $(New-Object System.Exception ("Cannot write message"),$_.Exception)
	}
}

Function Collect-ExceptionMessage
{
	param(
		[Exception]$e
	)

	Begin {
	}
	Process {
		$msg = "Source:{0}; Message: {1}" -f $e.Source, $e.Message
		while ($e.InnerException) {
		  $e = $e.InnerException
		  $msg += "`n`t->Source:{0}; Message: {1}" -f $e.Source, $e.Message
		}
		return $msg
	}
	End {
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: IgnoreCertErrors
# Description....: Sets TLS 1.2 and Ignore Cert errors.
# Parameters.....: None
# Return Values..: 
# =================================================================================================================================
Function IgnoreCertErrors()
{
    #Ignore certificate error
    if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
    {
        $certCallback = @"
			using System;
			using System.Net;
			using System.Net.Security;
			using System.Security.Cryptography.X509Certificates;
			public class ServerCertificateValidationCallback
			{
				public static void Ignore()
				{
					if(ServicePointManager.ServerCertificateValidationCallback ==null)
					{
						ServicePointManager.ServerCertificateValidationCallback += 
							delegate
							(
								Object obj, 
								X509Certificate certificate, 
								X509Chain chain, 
								SslPolicyErrors errors
							)
							{
								return true;
							};
					}
				}
			}
"@
        Add-Type $certCallback
    }
    [ServerCertificateValidationCallback]::Ignore()
    #ERROR: The request was aborted: Could not create SSL/TLS secure channel.
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
}


# Start Script here

#Cleanup log file if it gets too big
if (Test-Path $LOG_FILE_PATH)
{
    if (Get-ChildItem $LOG_FILE_PATH -File | Where-Object { $_.Length -gt 5000KB })
    {
        Write-LogMessage -type Info -MSG "Log file is getting too big, deleting it."
        Remove-Item $LOG_FILE_PATH -Force
    }

}


# PVWA & Platform URL
Write-LogMessage -type Info -MSG  "Retrieving Privilege Cloud URL" -Early
$shellURLs = Get-PrivCloudURL
if ($shellURLs.pvwaURL){
    Write-LogMessage -type Info -MSG  "Privilege Cloud URL is: $($shellURLs.pvwaURL)"
}Else{
    Write-LogMessage -type Warning -MSG  "Unable to determine Privilege Cloud URL, Please enter it manually (eg `"https://mikeb.privilegecloud.cyberark.cloud`")"
    $shellURLs.pvwaURL = Read-Host "Identity URL "
}


# Identity URL
Write-LogMessage -type Info -MSG "Retrieving Identity URL by following redirect of $($PortalURL)..." -Early
$IdentityURL = Get-IdentityURL -PortalURL $shellURLs.portalURL
if ($IdentityURL){
    Write-LogMessage -type Info -MSG  "Identity URL is: $IdentityURL"
}Else{
    Write-LogMessage -type Warning -MSG  "Unable to determine Identity URL, Please enter it manually (eg `"aax4550.id.cyberark.cloud`")"
    $IdentityURL = Read-Host "Identity URL "
}

# Privilege Cloud API
$script:PVWA_API = "$($shellURLs.pvwaURL)/PasswordVault/API"
$script:PVWA_GetallUsers = "$PVWA_API/Users"
$script:PVWA_GetUser = "$PVWA_API/Users/{0}/"

# Identity API
$script:IdaptiveBasePlatformURL = "https://$IdentityURL"

# Creds
If ([string]::IsNullOrEmpty($Credentials)) { 
    $creds = Get-Credential -Message "Enter your Identity User and Password"
} Else {
    $creds = $Credentials
}

# Login
IgnoreCertErrors
Write-LogMessage -type Info -MSG "Authenticating to Identity to retrieve Token" -Early
$IdentityHeaders = Get-IdentityHeader -IdentityTenantURL $IdentityURL -IdentityUserName $creds.UserName
if($IdentityHeaders){
    Write-LogMessage -type Info -MSG "Successful authentication"
    $creds = $null
}Else{
    Write-LogMessage -type Error -MSG "Failed to authenticate to Identity...Exiting"
    $creds = $null
    Pause
    Exit
}

# Identity minimal permissions
Write-Host "Checking if we have sufficient permissions to perform the query in Identity..." -ForegroundColor Gray
$IdentityPermission=$(Get-IdentityPermissions -IdentityHeaders $IdentityHeaders)
if (($IdentityPermission -eq "User Management") -or ($IdentityPermission -eq "All Rights")){
    Write-Host "Passed minimal permissions requirement to perform query in Identity" -ForegroundColor Green
}
Else{
    Write-Host "User doesn't have sufficient permissions in Identity, make sure user is part of any role that has `"User Management`" administrative permission." -ForegroundColor Red
    Write-Host "Displaying Current permissions:" -ForegroundColor Yellow
    $IdentityPermission
    Pause
    Exit
}

Write-Host "Checking if we have sufficient permissions to peform the query in Privilege Cloud..." -ForegroundColor Gray
$PrivilegeCloudPermission=$(Get-VaultPermissions -IdentityHeaders $IdentityHeaders -pvwaUser $creds.UserName)
if ($PrivilegeCloudPermission -match "AuditUsers"){
    write-host "Passed minimal permissions requirement to perform query in Privilege Cloud" -ForegroundColor Green
}
Else{
    Write-Host "User doesn't have sufficient permissions in Privilege Cloud, make sure user has Vault Authorization `"AuditUsers`" permission." -ForegroundColor Red
    Write-Host "Displaying Current permissions:" -ForegroundColor Yellow
    $PrivilegeCloudPermission
    Pause
    Exit
}

Write-LogMessage -type Info -MSG "Start retreieving Users under `"Privilege Cloud*`" Roles in identity"
$allIdentityUsers = @()
foreach ($role in $(Get-PrivCloudRoles).Row.ID){    
$body = @"
{
    "Script": "@/lib/reports/compliance/mfa.js",
    "Args": {
        "PageNumber": 1,
        "PageSize": 100,
        "Limit": 100000,
        "SortBy": "",
        "Caching": -1,
        "Parameters": [
            {
                "Name": "roleId",
                "Value": "$($role)",
                "Type": "Role",
            }
        ]
    }
}
"@
    Try{
        Write-Host "Checking Role: $role" -ForegroundColor Gray
        $resp = Invoke-RestMethod -Method Post -Uri "$IdaptiveBasePlatformURL/Redrock/Query" -ContentType "application/json" -Headers $IdentityHeaders -Body $body -ErrorVariable identityErr
        # 
        #if(($resp.Result.Count -ge 1) -and ($resp.Result.Results.Row | Where {$_.Type -eq "User"}))
        if(($resp.Result.Count -ge 1) -and ($resp.Result.Results.row.UserName -ge 1))
        {
            Write-Host "Found Users under role: $role" -ForegroundColor Green
            Write-Host "=== Start List ===" -ForegroundColor Gray
            #($resp.Result.Results.Row | Where {$_.Type -eq "User"}).Name
            #($resp.Result.Results.Row | Where {$_.Type -eq "Role"}).Name
            $resp.Result.Results.row.UserName
            $allIdentityUsers += $resp.Result.Results.row.UserName
            Write-Host "=== End List ==="-ForegroundColor Gray
            #break
        }
    }
    Catch{
        throw $identityErr.message + $_.exception.status + $_.exception.Response.ResponseUri.AbsoluteUri
    }
}
# Sort list by uniques
$allIdentityUsers = $allIdentityUsers | Where-Object { $_ -notlike "installeruser*" } | Sort-Object -Unique

Try{
    #Get Users from Vault
    $VaultUsersTypesTOCheck = @("EPVUser", "EPVUserLite", "BasicUser", "ExtUser", "BizUser")
    $VaultUsersAll = @()
    foreach ($userTYpe in $VaultUsersTypesTOCheck){
        Write-LogMessage -type Info -MSG "Retrieving Users under UserTYpe: $userTYpe" -Early
        $respUsers = Invoke-RestMethod -Uri ("$($PVWA_GetallUsers)?UserType=$($userTYpe)") -Method Get -Headers $IdentityHeaders -ErrorVariable pvwaERR
        $respUsers.Users.username
        $VaultUsersAll += $respUsers.Users.username
    }
    
    
    Write-LogMessage -type Info -MSG "Start comparing users..." -Early
    $VaultUsersAll
    $allIdentityUsers
    # TODO this fails.
    $diff = Compare-Object -ReferenceObject @($VaultUsersAll | Select-Object) -DifferenceObject @($allIdentityUsers | Select-Object)

    $identityDiff = $diff | Where-Object { $_.SideIndicator -eq '=>' }
    if ($identityDiff){
        Write-Host "Users that exist in Identity but not in vault:" -ForegroundColor Yellow
        $identityDiff.inputObject
        $identityDiff.inputObject | Out-File "IdentityUsersToDelete.txt" -Force
        Write-Host "Exported to IdentityUsersToDelete.csv" -ForegroundColor Green
    }
    
    $vaultDiff = $diff | Where-Object { $_.SideIndicator -eq '<=' }
    if ($vaultDiff){
        Write-Host "Users that exist in vault but not in Identity" -ForegroundColor Yellow
        $vaultDiff.inputObject
        $vaultDiff.inputObject | Out-File "VaultUsersToDelete.txt" -Force
        Write-Host "Exported to VaultUsersToDelete.csv" -ForegroundColor Green
    }
    
    if (($identityDiff -eq $null) -and ($vaultDiff -eq $null)){
        Write-Host "No discrepancies found between Identity and Privilege Cloud Vault!" -ForegroundColor Green
    }
}Catch{
    Write-LogMessage -Type Error -Msg "Error: $(Collect-ExceptionMessage $_.exception.message $($_.ErrorDetails.Message) $($_.exception.status) $($_.exception.Response.ResponseUri.AbsoluteUri) $pvwaERR)"
}