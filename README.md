**Privilege Cloud License Capacity User Report**


Description:
-------------
This Script generates two report types: Capacity Report and Detailed Reportm, each offer different useful things.

Prerequisites:
----------------
1. You need HTTPS + CyberArk Port 1858 access to a Privilege Cloud tenant.
 - Capacity Report = 1858
 - Detailed User Report = HTTPS.
2. Depending on the authentication type chosen, you may need one of the following:
   - For 'cyberark' authentication, you need a valid CyberArk account with appropriate access permissions. You can use the default users we provide:
 	for standard = <subdomain>_admin
	for ISP      = installeruser@cyberark.cloud.#
   - For 'identity' authentication, you need a valid account in your ISPSS tenant, with a strong privilege cloud admin role. Take note, with identity auth you won't be able to pull Capacity Report, only Detailed Report.

Usage:
------
1. Run the script with the following command:

PS> .\PrivilegeCloudConsumedUserReport.ps1 -PortalURL "<your_tenant_url>" -AuthType "<authentication_type>" [-InactiveDays <number_of_days>] [-ExportToCSV] [-GetSpecificuserTypes <user_types>] [-ReportType <Report_Type>]

Parameters:
- `-PortalURL`: (Required) Specifies the URL of your Privilege Cloud tenant, e.g., https://<subdomain>.cyberark.cloud.

- `-AuthType`: (Optional) Specifies the authentication type for accessing Privilege Cloud. Valid values are 'cyberark' or 'identity'. Default cyberark.

- `-InactiveDays`: (Optional) Specifies the number of days to consider users as inactive. Default is 60 days.

- `-ExportToCSV`: (Optional) If specified, the results will be exported to a CSV file.

- `-GetSpecificuserTypes`: (Optional) Specify the user types you want to get a report on. By default, the script generates a report for the following user types: EPVUser, EPVUserLite, BasicUser, ExtUser, CPM, PSM, AppProvider. You can provide multiple user types separated by commas.

- `-ReportType`: (Optional) allows you to choose between 'CapacityReport' and 'DetailedReport'. CapacityReport provides a summary of license capacity, while DetailedReport gives a more comprehensive user-based report. Default CapacityReport

Example:
PS> .\PrivilegeCloudConsumedUserReport.ps1 -PortalURL "https://mikeb.cyberark.cloud" -AuthType "Identity" -ExportToCSV

2. The report will be generated and displayed in the PowerShell console. If the `-ExportToCSV` switch is used, the report will also be saved as individual CSV files for each user type.


Note:
-----
- The script may take some time to execute, depending on the number of users and the response time from the Privilege Cloud API.
