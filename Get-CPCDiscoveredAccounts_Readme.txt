==================================================
Privilege Cloud Export Discovered Accounts
==================================================

Description:
-------------
This Script exports discovered accounts from Privilege Cloud to CSV and JSON files.

Prerequisites:
----------------
1. Must execute from a machine that can reach the tenant via HTTPs
2. User must be an Administrator in Privilege Cloud

Usage:
------
Recommended Usage:
.\Get-CPCDiscoveredAccounts.ps1

Other Example:
.\Get-CPCDiscoveredAccounts.ps1 -ClearDiscoveredAccounts # Remove Discovered accounts after exporting
Flag Options:

-PortalURL (Mandatory):
Specifies the URL of the Privilege Cloud tenant. Example: -PortalURL "https://<subdomain>.cyberark.cloud"

-Credentials (Mandatory):
Either script will prompt you or you can prepop it using $creds = Get-credentials and then pass it using -Credentials $creds (an example)

-Force:
For use with -ClearDiscoveredAccounts. Removed Discovered accounts with prompting for confirmation.
Example: -ClearDiscoveredAccounts -Force

The report will be generated and saved as CSV and JSON files. The JSON file is intended for programmatic use.

Note:
-----
- The script may take some time to execute, deDiscovered on the number of users and the response time from the Privilege Cloud API.