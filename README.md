=============================
Privilege Cloud Consumed User Report
=============================

Description:
-------------
This PowerShell script generates a Privilege Cloud consumed users report for a given Privilege Cloud tenant URL. The report provides information about users of different types and their last login dates. It also identifies users who have been inactive for more than a specified number of days.

Prerequisites:
----------------
1. You need HTTPS access to a Privilege Cloud tenant.
2. Depending on the authentication type chosen, you may need one of the following:
   - For 'cyberark' authentication, you need a valid CyberArk account with appropriate access permissions. (You can use the default users we provide:
 	for standard = <subdomain>_admin
	for ISP      = installeruser@cyberark.cloud.#
   - For 'identity' authentication, you need a valid account in your ISPSS tenant, with a strong privilege cloud admin role.

Usage:
------
1. Run the script with the following command:

PS> .\PrivilegeCloudConsumedUserReport.ps1 -PortalURL "<your_tenant_url>" -AuthType "<authentication_type>" [-InactiveDays <number_of_days>] [-ExportToCSV] [-GetSpecificuserTypes <user_types>]

Parameters:
- `-PortalURL`: (Required) Specifies the URL of your Privilege Cloud tenant, e.g., https://<subdomain>.cyberark.cloud.

- `-AuthType`: (Required) Specifies the authentication type for accessing Privilege Cloud. Valid values are 'cyberark' or 'identity'.

- `-InactiveDays`: (Optional) Specifies the number of days to consider users as inactive. Default is 60 days.

- `-ExportToCSV`: (Optional) If specified, the results will be exported to a CSV file.

- `-GetSpecificuserTypes`: (Optional) Specify the user types you want to get a report on. By default, the script generates a report for the following user types: EPVUser, EPVUserLite, BasicUser, ExtUser, CPM, PSM, AppProvider. You can provide multiple user types separated by commas.

Example:
PS> .\PrivilegeCloudConsumedUserReport.ps1 -PortalURL "https://mikeb.cyberark.cloud" -AuthType "Identity" -ExportToCSV

2. The report will be generated and displayed in the PowerShell console. If the `-ExportToCSV` switch is used, the report will also be saved as individual CSV files for each user type.

3. Once the report is generated, the script will automatically log off from the Privilege Cloud tenant.

Note:
-----
- The script may take some time to execute, depending on the number of users and the response time from the Privilege Cloud API.
